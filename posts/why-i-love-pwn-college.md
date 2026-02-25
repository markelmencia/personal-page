---
title: "pwn.college: One of the best Computer Science learning environments"
date: "2026-02-25"
description: "Going over why I believe pwn.college is such a great website, which I've used for many hours."
---

# pwn.college: One of the best Computer Science learning environments

#### February 2, 2026

If there's something us Computer Science enthusiasts should be grateful for is the fact that learning new skills in this field is very accessible. Thanks to the internet, and most importantly to those who voluntarily create the resources we can use to learn, broadening your knowledge about computer matters in general is often times just a few clicks away.

There are countless resources out there, many of which are free of charge. Today, I'd like to talk about one in specific, which I've used for quite some time now, and has helped me immensely in learning new things about Computer Science that I didn't learn elsewhere. This resource is [pwn.college](https://pwn.college/), a page I still use to this day and I intend to use for much longer.

## What's pwn.college?

pwn.college is a free and open learning platform developed by the Arizona State University in the United States. Its main focus is to help its users practice core cybersecurity skills. In order to do so, it provides lectures about a wide range of cybersecurity areas, and hundreds of CTF-style challenges.

pwn.college is divided in dojos. A dojo covers specific topics. For example there's a Linux dojo, to learn about the fundamentals of the operating system. There's another dojo that serves as an introduction to cybersecurity overall. Each dojo contains different modules, with each covering a specific area of that topic. For example, in the "Intro to Cybersecurity" dojo, there's a module about binary exploitation, another one for reverse engineering, intercepting communication...

Each module has a few lectures, which are presentations that go over key concepts in each module and prepare us to take on the challenges of it. Every challenge has the same goal: you log into a remote machine, and attempt to read the flag. If you succeed, you win the challenge. Simple enough, right?

Well, this is pwn.college. It's conceptually a very simple resource, but it's very powerful! The modules are quite dense, sometimes reaching more than 50 challenges and other times having a few lectures that can be up to an hour long. This makes pwn.college a very big platform with a lot of content, that will keep you entertained for hours on end.

## How did I discover it?

Back in my first year in university, I was lucky enough to have teachers that were very committed to our learning. One day, they arranged a talk, given by [bubu](https://albertofdr.github.io/), a cybersecurity researcher I later befriended. This talk was about how to get into the world of cybersecurity. In it, he insisted on how good of a platform pwn.college was. I found it interesting, so I gave it a try. That was my first ever contact with the world of cybersecurity.

In the following weeks, I'd spend hours playing pwn.college challenges. I remember that the first module I tried was [Program Misuse](https://pwn.college/fundamentals/program-misuse/). It was about using programs that had its `suid` bit set. Your goal was to "misuse" those programs to read the flag. To this day, I still struggle to believe I managed to beat every challenge of the module. At that time, I was completely new to Linux, and some of the challenges were very challenging!

After completing the module I thought to myself: "What did I really learn with this?". Each challenge was very specific to a program. I was using commands I didn't even understand at times, and getting some flags sometimes felt like a random occurrence. Only later did I realize that without even knowing, I was learning fundamental Linux concepts, and training my mind to always be on the lookout for vulnerabilities. The point of the module wasn't to learn obscure command options to increase your privileges. It was about training yourself to be patient and having a keen eye for vulnerabilities. Two years later, I can't remember the solution of any of the challenges, and still, I'm convinced that this module was a key part of my learning experience that year in college.

Admittedly, the module did burn me out for a while, but mostly because I was definitely not ready for some of the challenges. At the end of the day, it still was my first year in college, and my previous knowledge about Computer Science was limited. So, I moved on to do other projects.

Only in 2025, after I came back to the world of CTFs did I continue my journey in pwn.college. With more experience in general, and more motivation, I continued playing modules, which is what I have been doing since!

The website has had some great improvements, and to me, it feels like it's the most beginner-friendly it has ever been, which is awesome, because it's easy to burn out in cybersecurity. After all, there's a lot to learn, and CTFs can be quite daunting.

## The reason I think it's so good

pwn.college has a single rule: do not post the challenge solutions. Taking into account the fact that pwn.college is open and free, one could find this rule surprising, especially considering how a sizable part of the CTF world are the writeups that people write about the challenges they beat. However, it turns out that some universities use the resources of pwn.college to grade its students. That being said, it makes sense that this rule is a thing.

I think this rule has one side-effect that makes pwn.college a much better platform. **Every challenge in the platform, *you* will have to beat**. There are literally no shortcuts to get flags. If you want to beat the challenge *you* will have to find the vulnerability to do it. There are no written solutions available nor cheats, and each account has personalized flags, making flag-sharing useless. This obligates you to understand each challenge by yourself, without any direct help from writeups to get the flag.

Granted, this rule doesn't mean you can't get any sort of help. pwn.college has its own Discord server, with a very active community that will always be down to help. Each member in the server is committed to help other members as much as they can without giving away the solution. You could think this would make things go very wrong, but surprisingly, the server is very committed to following this rule, which I think is quite cool. You will only get just enough help for you to do the rest of the work.

I think this is what makes pwn.college so good! if you want to progress, it is your effort only what will make you beat challenges. I'm quite fond of "restrictive" learning environments: learning platforms with a few rules that limit the help you can get, or that make you have to adapt to them. Platforms that encourage getting your hands dirty rather than carefully reading theory, see a list of steps, and replicate them in your machine. If done right, these environments will make you be independent and perform your learning abilities, just by pure exposure. 

## "Restrictive" learning environments

pwn.college was not the first time I was in contact with a "restrictive" learning environment. For a few years, I attended an English academy in which only speaking in English was allowed. The teachers were native and their Spanish knowledge was limited. This forced us to think in English, because it was our only form of communication. I attribute a lot of my English level to that academy, and I'm very thankful for them. They were teachers that were always down to help. They were strict, but also close. They'd never talk you down for making a mistake. Their classes were very dynamic: we spent a lot of our time in class doing speaking activities about current topics at the time, and in no time, you'd get used to speaking in pure English for two hours a day. They weren't worried about spending too much time speaking, because at the end of the day, having ordinary conversations about a wide range of topics in English is one of the best things you can do to be more proficient in the language. To this day, I believe this academy was one of the best education I've ever had.

I think pwn.college, intentionally or not, uses the same system, and it's why it works for me so well. Granted, CTFs are "restrictive" by nature. You're given some small piece of information, and with it, you need to exploit something. Looking for help on the internet about what you're specifically trying to do is futile, and LLMs (at least the most used, general-purpose ones) are not good enough to directly give you the solution. It's only *you* against the challenge. This encourages practice: just trying stuff and seeing what happens. Most of the time, what you try won't work; but when it does, you will have already tried a plethora of ideas that might help you in a different challenge. The more you try things by yourself, the faster you'll know what to look for. And all of this without having a tutor or mentor. Sure, you can ask others about a specific approach, or you can do a challenge with a partner (something I definitely encourage of you're able to!), and watch multiple helpful videos, but ultimately, you become your own teacher.

To anyone willing to learn not just about cybersecurity, but about computers in general, I highly recommend this platform. The only thing you need to progress is will. Some challenges are difficult, and they will require some work to beat, but there's nothing as satisfying as getting a flag you've been working on getting for hours. The resources they provide are great, and as far as I can tell, the difficulty curve is just on point. Good luck!

~ Markel