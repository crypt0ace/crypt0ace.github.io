---
title: "Gift - HackMyVM Walkthrough"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2021-07-19
description: "Gift - A vulnerable machine from HackMyVM Walkthrough"
tags: [Write-Ups]
---
Gift is a really easy machine from HackMyVM created by [sml](https://twitter.com/x6cx61x63x61x73). Perfect for beginners and the ones just started in the field. Here's my write Up..
\
So we start off with an nmap scan, which i already ran and saved as "Initial":
\
![NmapScan.png](/assets/img/gift-hackmyvm-walkthrough/NmapScan.png)
\
I see port 80 open and a website on it. Let's see whats on it.
\
![website.png](/assets/img/gift-hackmyvm-walkthrough/website.png)
\
Oh okay. That's something. Let's take a look at the source code of the website.
![sourcecode.png](/assets/img/gift-hackmyvm-walkthrough/sourcecode.png)
\
Well I definately don't. This seemed strange to me. I ran a nikto scan as well thinking it might bring up something. But nothing of much use.
\
![nikto.png](/assets/img/gift-hackmyvm-walkthrough/nikto.png)
\
I started a Directory scan with gobuster and this also turned nothing!!
\
![directory.png](/assets/img/gift-hackmyvm-walkthrough/directory.png)
\
So by now I was confused. It wasn't making much sense. But I ran a Hydra ssh Brute Force and we got it.
\
![hydrassh.png](/assets/img/gift-hackmyvm-walkthrough/hydrassh.png)
\
It literally was "Simple" (heh). Let us SSH in the machine.
\
![ssh.png](/assets/img/gift-hackmyvm-walkthrough/ssh.png)
\
Aaaaaand we're in. We're also "Root" user so we can just get the both flags from the "/root" directory.
![root.png](/assets/img/gift-hackmyvm-walkthrough/root.png)

\
And that's it. We pwned the machine. Let me know if you liked the write up or you want to give me any suggestions. You can find me on my socials below in the footer.
> I'm new in writing walkthroughs and writeups. pls go easy one me.. :wink: 