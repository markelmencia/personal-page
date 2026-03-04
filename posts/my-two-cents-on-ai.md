---
title: 'My two cents on AI: How my learning has changed'
date: "2026-03-01"
description: "About the use of generative AI in learning. Giving my thoughts about what has changed, how I use LLMs and what practices I try to avoid."
img: "/img/posts/my-two-cents-on-ai.png"
img-alt: "A data scientist had found that their work (the algorithm depicted on their laptop screen) has ‘jumped’ out of the screen and threatens to cause problems with a variety of different industries. Here a hospital, bus and siren could represent healthcare, transport and emergency services. The data scientist looks shocked and worried about what trouble the AI may cause there."
---

# My two cents on AI: How my learning has changed

![A data scientist had found that their work (the algorithm depicted on their laptop screen) has ‘jumped’ out of the screen and threatens to cause problems with a variety of different industries. Here a hospital, bus and siren could represent healthcare, transport and emergency services. The data scientist looks shocked and worried about what trouble the AI may cause there.](/img/posts/my-two-cents-on-ai.png)
*Yasmin Dwiputri & Data Hazards Project / https://betterimagesofai.org / https://creativecommons.org/licenses/by/4.0/*

#### March 1st, 2026

AI needs no introduction, it's everywhere. In fact, it has become so ordinary that sometimes it's very easy to forget how mainstream it is. Thus, I'm not going to waste time going over how game-changing (for the better or worse) LLMs are.

The sudden rise to the limelight these technologies have achieved has become seemingly-unending fuel for discussion. I find this very positive, because it's important for us to reflect on emerging topics in society overall, whatever they're about. I believe that the quicker we are in debating about a potential risk to the way our jobs are, the environment, or even our very own well-being, the quicker we might be able to pull out from it, should it be necessary. 

There's definitely a lot to talk about in generative AI: its ethics, the privacy risks it might bring, the potential illicit use it can have on many different scenarios, it's environmental impact... I won't be going over these topics in this article. I want to write about a topic closer to me: learning.

As someone who studies an area so close to these technologies, I've used LLMs just like any other computer science enthusiast, because frankly, you almost have to. Many regular activities in this field involve dealing with "dumb" mistakes, remembering trivial syntax characteristics or going over documentation. One of the first things you learn as a programmer is to deal with these cognitively lax yet often time-consuming issues. It'd make sense to use a tool that can pinpoint these issues very quickly. Additionally, LLMs have become especially good at these tasks. It's not a coincidence that a sizable chunk of the (rather confusing at times) AI benchmarks involve solving issues related to coding.

All in all, I've experienced first-hand (just like lots of us) what LLMs can do. And it's not shocking to point out how the use of LLMs has become a part of my learning ecosystem, whether I like it or not. In this article, I'll talk about how I use LLMs, how I think they should be used, the value they bring to me, and the risks it poses to how we approach learning as a whole.
## How I use it
As a computer science student, I code a fair bit. As a matter of fact, I'm writing this two hours after finishing participating in a hackathon. Over the weekend, I've been coding for hours and hours, almost non-stop. It's safe to say that I'm extremely tired, but that's another story.

The truth is that I don't consider myself a developer. I've coded my way through a bunch of projects, but it's not development what interests me. I spend most of my learning hours in cybersecurity, in which coding is also important. Regardless, my use cases for LLMs in development and cybersecurity don't really differ.

I don't have the data to confirm this, because most of my AI queries are done without an account (considering the way big AI companies have been using worldwide data to train their models, I remain skeptic about giving them ways to get mine), but I'm certain that most of my questions are about implementation. I think giving a list of prompts will picture it better:

- "I'm trying to send a packet to a specific host with X and Y values in the header. How can I do this using Z library?"
- "I'm working on a relational database. I have these two tables and the table 1 should have a one-to-many relationship with the table 2. How do I implement this using the ORM of X programming language?"
- "Why am I getting a type error in this snippet?"
- "What can I use to implement file downloading in a website that uses this framework?"

My questions are usually closed, and don't require much context. I use LLMs when I know I can get a result quicker than with a Google search, or when I can't be asked to look into the documentation of a specific tool I'm using. The tasks I use it for don't really require much thought. These tasks are usually an interlude to the goal I'm trying to get to. It's a bit cliché, but it reminds me to how you could use a calculator to do a quick math operation instead of using your mind. Could you be missing out on getting better at calculating things by yourself by offloading that effort to a calculator? Definitely, but at times you just can't be bothered, and that's okay sometimes.
### A tool
This brings me to the point about how I think it should be used. You've heard this before, I've heard this before, but there's no better way to put it. LLMs should be nothing more than just another set of tools. Sometimes there's things that are better off done quicker than better. Reading the documentation about a certain library could be more enriching than a quick question to your favorite LLM, but sometimes it's better to spend that extra time on something that will make you learn more, or that requires more thought.

For example, if I'm working on a CTF challenge in which I need to create a script to send a payload that gives me arbitrary code execution, I'm not going to care much about how well-done that script is. The script is just the means. As long as it works, it's fine. The objective of a challenge like that is not to learn how a payload like that is done, it's more about understanding it. 

You can know the ins and outs of a programming language or a library that offers resources to craft a payload for the challenge. But that knowledge will be futile if you don't understand the environment, or what you're trying to do. I think that's the essence of learning. Not memorizing functionalities, syntax or other trivial things, but knowing where to look, what you can potentially do, understanding the uses it has and being able to learn new concepts about whatever you're learning about by yourself. So if I'm prompting an LLM to quickly get something done so I can use more of my time understanding what I'm doing, I'm not going to feel like I'm missing out.

But of course, this is much easier said than done, and it's easy to miss the line between what's positive and what isn't.
## What I try to avoid
As I've mentioned, it's easy to get carried away with an LLM. Sometimes, and I know I'm not the only one that this has happened to, you just get lazy and keep prompting the AI. You keep on prompting, correcting the mistakes the answers give, you waste time, and you find out you could've solved whatever issue you're dealing with quicker just by doing it yourself. That's why I try to scope in my questions: asking about something that doesn't need a bigger picture for the LLM to do it. At the end of the day, you wouldn't solely rely on your calculator to solve a math problem. You'd use it as a tool to assist you on the calculations, while you focus on the logic and the approach.

But this is not the only practice I find problematic. Here's a list of other common activities I wouldn't use to learn or study:
### Personal "coaches"
Using an LLM as a coach or a guiding figure to learn something new is something that has become popular in self-learning. While I don't find it inherently harmful (and I believe [it can work](https://cacm.acm.org/blogcacm/ai-tutored-me-and-i-learned-something/)), I believe it can become an issue.

Firstly, when you prompt an AI that you want to learn something, you'll get a sort of roadmap with broad areas for you to explore. It's a good place to start. In fact, I remember that my very first question to an LLM was about how to start learning cybersecurity. I've gone a long way since then!

From that point on, you might keep asking questions to learn more, and eventually make it a regular thing in your learning routine. As I've mentioned, this is done a lot, and in many different ways.

My issue is that AI is way too accessible. You can always ask for directions, virtually anytime. This can be tempting, but doing so can be problematic because you're missing out on a key skill in self-learning. At the end of the day, why spend time finding out what even to investigate if the LLM can do it for you? You'd be spending more time learning and less time investigating what to learn, with which you risk falling into a topic you might not be ready for yet.

I believe there's value in "getting lost", though. When you are self-learning, it's not uncommon to fall into an area that you might just not be ready to digest. That's fine, it happens. You might even try to learn it anyway, and fail. That's natural, and you can always turn back and try it again later on.

Learning is not and should not always be a smooth road. Adversity is just another step in your learning phase, and ultimately, a lesson as important as any other. If anything, making mistakes is crucial to track your progress. How else can we know that we've become better if we don't find ourselves in a situation in which you achieve something you failed to do previously? I believe that somewhere along the way, we've forgotten that making mistakes is natural, especially when learning. We shouldn't be discouraged to delve into a topic we might not be ready to understand.

I think asking an AI to work as a coach will result in an experience that is too linear and sanitized because of how accessible it is. To be clear, however, I suppose this is not an issue if you use the LLM accordingly. The issue is that we might not, especially someone who's starting to get into self-learning, or even people in educational environments, like schools. It's not at all uncommon for a kid to not be motivated to investigate about a topic for a presentation or such. Give them an AI coach, and they'll use it as much as they can just to get the job done and go do something that interests them more. 

As another point, I believe that this might not even be an issue of AI coaches but in the way learning is structured broadly. Food for thought!
### Prompt engineering
I just don't really see the point of it? Being blunt, I've never actually tried to put much attention into crafting my prompts properly. In actuality, my prompts are lazy and full of typos, and yet they work for me with no issues. 

I can't say much about this, but from an outsider's perspective, I just believe that if I'm going to spend that much time fine-tuning a prompt for better results, I might as well spend that time doing whatever you're trying to do by myself. And if I do need the AI to be that specific and concise, I'm probably using it to do something I wouldn't want to do with AI, which brings me to the next point.
### Asking for summaries
As regular as this might sound, I believe that doing this (or worse, making it a habit) can be very harmful.

By default, content in the internet has increasingly become more and more short-form. People read less (I include myself in that group, even though I'm trying my best to read more), and we're becoming more reluctant to content that requires more digestion to consume. That's why when reading longer forms of text, some people resort to generative AI to get them summarized and get the bullet points. This is a regular use case for LLMs and one of the most advertised.

I would never use this in learning setting. The reason is clear: I find making summaries manually extremely useful. To give an example, when studying for exams in university, I spend most of my time summarizing my notes. You're doing a lot: you're reading the text multiple times, you're processing it and making sense of it in your head, and then you're writing it in a structured way, which involves reading it more. All the while, you're exclusively focusing on understanding. This requires time, but it's greatly enriching.

I struggle to keep my attention steady when I solely read. If while I'm reading and making notes, that solves the issue, because I force myself to pay attention. It'd be a shame for me to offload that to an LLM, I'd be missing out on a lot. Making summaries, even if I don't read them later on, benefits me immensely, and using AI for these summaries feels so effective that it's easy to make it a habit. Once it does, you'll lose part of your reading comprehension, mainly because you're cognitively offloading it. Since I'm interested in research, a field which is very intensive in comprehension, I worry about that a lot.

I've talked about using AI as a tool. One could think you're using an LLM for that when you ask it for a summary. In my eyes, a tool shouldn't use reason for you. Our ability to structure information is precisely what makes us as intelligent as we are. Memory, pattern recognition, imagination, creativity... a lot of these skills are used when we try to comprehend. That's why I believe that using AI to summarize is not the same as using it for, say, fixing most small coding mistakes. It's very different, and you'd be missing out on a lot. You're never wasting time in a project, assignment or studying session if what you're doing involves understanding.
## Last thoughts

I might have sounded a bit critical towards AI. The truth is that I am, but this article shouldn't be taken as a hate piece or a harsh critic. It's not my intention to make an article like that. The idea of this is to speak about the practices I find potentially harmful in a learning setting.

Cognitive offloading is one of the biggest double-edged swords in any process that requires thought and reason. As useful as it can be, it's risky to make someone think for you. As I've mentioned previously, AI is very accessible and effective at some tasks, that's why it's easy to overuse it, and ultimately making it an issue. Evidently, there is something very human about learning, and we should cherish that.

I'd also like to say that, obviously, I've done some of the negative things I mention in the article, I'm far from a saint. My points aren't really that deep, and you won't suddenly lose your ability to read if you use AI here and there, not even close. And again, I'm just talking about learning, not the other uses of generative AI in general, my opinions might be different then. That said, it's easy to talk about the things you don't like or practice. As [Tom Scott](https://www.tomscott.com/) has said more than once: "Everyone draws the line of what's acceptable just beneath what they're doing themselves".

~ Markel