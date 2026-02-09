---
title: "LACTF 2026: ooo"
date: "2026-02-09"
description: 'Writeup for the "ooo" reversing challenge in the LACTF 2026.'
---

# LACTF 2026: ooo

#### February 9, 2026

This was a fun reversing challenge in this year's LACTF. We're given a Python script, which at first looks quite quirky:

```
def о(a, b):
    return a+b
def ο(a, b):
    return a-b
def օ(a, b):
    return a*b
def ỏ(a, b):
    return a//b
def ơ(a, b):
    return a^b
def ó(a, b):
    return a|b
def ὀ(a, b):
    return a&b
def ὸ(a, b):
    return b-a
def ὄ(a, b):
    return a
def ὂ(a, b):
    return b
def ȯ(a, b):
    return a % b
    

ὁ = [205, 196, 215, 218, 225, 226, 1189, 2045, 2372, 9300, 8304, 660, 8243, 16057, 16113, 16057, 16004, 16007, 16006, 8561, 805, 346, 195, 201, 154, 146, 223]

guess = input("What's the flag? ") # remember, flags start with lactf{

if (len(guess) < len(ὁ)):
    print("That's too short :(")
    exit()
    
for ö in range(len(ὁ)-1):
    ό = ord(guess[ö])
    ὃ = ord(guess[ö+1])
    if (о(ὄ(ό,ὃ),ὂ(ό,ὃ)) != ὁ[ơ(ö,ȯ(օ(ό,ὃ),ό))]):
        print("That's not the flag :(")
        exit()
    
print("That's the flag! :)")
```

Now we see why the challenge is called "ooo".

We have a bunch of functions and variables with very similar names. With nothing else to look at, I quickly started renaming the functions and variables, for the script to be much readable:

```
def aPlusB(a, b):
    return a+b
def aMinusB(a, b):
    return a-b
def aTimesB(a, b):
    return a*b
def ỏ(a, b):
    return a//b
def aXORb(a, b):
    return a^b
def ó(a, b):
    return a|b
def ὀ(a, b):
    return a&b
def ὸ(a, b):
    return b-a
def a(a, b):
    return a
def b(a, b):
    return b
def aModB(a, b):
    return a % b
    

num_list = [205, 196, 215, 218, 225, 226, 1189, 2045, 2372, 9300, 8304, 660, 8243, 16057, 16113, 16057, 16004, 16007, 16006, 8561, 805, 346, 195, 201, 154, 146, 223]

guess = input("What's the flag? ") # remember, flags start with lactf{

if (len(guess) < len(num_list)):
    print("That's too short :(")
    exit()
    
for num in range(len(num_list)-1):
    arg1 = ord(guess[num])
    arg2 = ord(guess[num+1])
    if (aPlusB(a(arg1,arg2),b(arg1,arg2)) != num_list[aXORb(num,aModB(aTimesB(arg1,arg2),arg1))]):
        print("That's not the flag :(")
        exit()
    
print("That's the flag! :)")
```

I didn't refactor some of the functions above because they weren't used anywhere in code and thus, were useless. But now the code is more readable.

For this challenge, we can use as input whatever we want, and the Python script will tell us if it's the flag or not. To do so, it uses this loop:

```
for num in range(len(num_list)-1):
    arg1 = ord(guess[num])
    arg2 = ord(guess[num+1])
    if (aPlusB(a(arg1,arg2),b(arg1,arg2)) != num_list[aXORb(num,aModB(aTimesB(arg1,arg2),arg1))]):
	    print("That's not the flag :(")
        exit()
    
print("That's the flag! :)")
```

It seems appropriate to understand the condition that tells us that our input is not the flag:

```
if (aPlusB(a(arg1,arg2),b(arg1,arg2)) != num_list[aXORb(num,aModB(aTimesB(arg1,arg2),arg1))]):
```

To make it more readable, what I did was replacing the function calls with their functionality (what each function returns):

```
if (arg1 + arg2) != num_list[num ^ ((arg1 * arg2) % arg1)]:
```

Suddenly, this looks much more readable!

Let's put our eyes on the operations in num_list[] now:

```
num_list[num ^ ((arg1 * arg2) % arg1)]
```

It turns out that these operations can be simplified quite easily with simple arithmetic! The module operation will always be zero. Multiplying `arg1` times `arg2`, and then dividing the result with `arg1`, will always return a remainder of `0`.

```
num_list[num ^ 0]
```

Now, all we have left is a XOR operation. It turns out that every number you XOR with a zero, will always be that same number, meaning...:

```
num_list[num]
```

Putting it all back together:

```
for num in range(len(num_list)-1):
    arg1 = ord(guess[num])
    arg2 = ord(guess[num+1])
    if arg1 + arg2 != num_list[num]:
	    print("That's not the flag :(")
        exit()
    
print("That's the flag! :)")
```

That's much cleaner now isn't it?

This is the algorithm that hints us what the flag is. Now, for challenges like these, bruteforcing always comes to mind. At the end of the day, flags contain readable characters, so there's only a few hundred characters we need to iterate through to get each flag character. The question is how. 

Well, we need to consider something. In order to get one flag character, the algorithm uses two characters of our input. The sum of their ASCII values must return the value in the list, at index `num`. That's the key to get the characters! Because there's a very important detail: We *do* know how the flag starts. It's in the CTF information, and also commented in the code: `lactf{`. This should be enough, let alone just the letter `l`, which we know is the first. With this character we can get the second one just by subtracting the corresponding value in the list to that character. To understand this properly, I'll give an example for the first iteration:

We start with the first character, `l`. Its ASCII value is `108`. Since we are in the first iteration, we check the value at index `0` in `num_list`. The value is `205`. According to the algorithm, the next character is whatever value we need to get `205` when added to `108`. `108 + x = 205`, which gives us the value `97`, the letter `a`. That checks out, because the we know the flag starts with `lactf{`. Let's write this algorithm into code in a new file:

```
num_array = [205, 196, 215, 218, 225, 226, 1189, 2045, 2372, 9300, 8304, 660, 8243, 16057, 16113, 16057, 16004, 16007, 16006, 8561, 805, 346, 195, 201, 154, 146, 223]

solve = "" # Will contain the flag
known = ord("l") # The known character, starts being "l"
for num in range(len(num_array)):
	# We add the known character to the flag
    solve = solve + chr(known)
    
    # We get the next character
    unknown = num_array[num] - known
    
    # Now the next character is our known character
    known = unknown 

# We print the *almost* finished flag
print(solve)
```

Let's see it in action:

```
$ python3 solve.py
lactf{gоοօỏơóὀόὸὁὃὄὂȯöd_j0b
```

That should do! However, we don't get the last character. That's fine though, we assume the last character is `}`. That's our flag!