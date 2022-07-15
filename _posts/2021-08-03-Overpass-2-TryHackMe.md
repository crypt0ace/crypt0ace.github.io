---
title: "Overpass 2 - Hacked"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2021-08-03
description: "Overpass has been hacked! Can you analyse the attacker's actions and hack back in?"
tags: [Write-Ups]
---

## Introduction
<hr>
This room is created by [NinjaJc01](https://tryhackme.com/p/NinjaJc01) and focuses on PCAP Analysis and Forensics side. Here's a link to the Room: [Overpass 2 - Hacked](https://tryhackme.com/room/overpass2hacked).

> <b>Overpass has been hacked! The SOC team (Paradox, congratulations on the promotion) noticed suspicious activity on a late night shift while looking at shibes, and managed to capture packets as the attack happened.
Can you work out how the attacker got in, and hack your way back into Overpass' production server?</b>

So this hints what we would have to do. Analyze a PCAP and retrace the steps to get back in the server.

## Analysis
<hr>
We start with a PCAP File. We can analyze this file using Wireshark Tool. Lets fire it up.

<br>

The first question we get is:
> <b>What was the URL of the page they used to upload a reverse shell?</b>

To see the URL to which the shell was uploaded we can see the requests made using this wireshark filter:
![Wireshark Analysis](/assets/img/overpass-2/wireshark-analysis.png)
<br>
With this we can see the requests made to the website and also where the shell was uploaded.
![Requests Analysis](/assets/img/overpass-2/request-analysis.png)
<br>
We will have the answer to our first question right here.

> <b>What payload did the attacker use to gain access?</b>

This can also be found in the same filter. Look for a POST Request. And from there see at the data that was uploaded. You can see the payload that was used for initial access.
![Payload](/assets/img/overpass-2/payload.png)
<br>

> <b> What password did the attacker use to privesc?</b>

To see more information on the pcap, We can look for <b> "tcp.eq.stream == 3" </b>.
![TCP Stream Filter](/assets/img/overpass-2/tcp-stream.png)
<br>
From here just do "Follow TCP Stream" or CTRL+SHIFT+ALT+T to follow the TCP Stream. You can see the password used by the attacker by analysing the TCP Stream.
![Follow TCP Stream](/assets/img/overpass-2/tcp-stream-follow.png)
<br>
> <b>How did the attacker establish persistence?</b>

Using the same TCP Stream, We can find the backdoor that the attacker used and what the code is.
![Backdoor](/assets/img/overpass-2/backdoor.png)
<br>
> <b>Using the fasttrack wordlist, how many of the system passwords were crackable? </b>

Just above this we can see that the attacker dumped the shadow file. We can see the hashes of 5 users. We can use John to crack these hashes from the fasttrack.txt wordlist as asked in the Task.
![Hashes](/assets/img/overpass-2/hash.png)
<br>

## Research
<hr>
In this section we are supposed to research the code that the attacker used to gain persistence on the server. We already have the link so we can just clone the repository on our local machine to research the code.

> <b>What's the default hash for the backdoor?</b>

We can open up sublime or any other text editor you prefer to read the code. GO Language is a programming language but you dont need to have programming knowledge to read the code and answer the questions. When we open it we can see the default hash right away.
![Default Hash](/assets/img/overpass-2/hashes.png)
<br>

> <b>What's the hardcoded salt for the backdoor?</b>

At the very end of this program, we can see the salt used for the backdoor.
![Salt](/assets/img/overpass-2/salt.png)
<br>

> <b>What was the hash that the attacker used? - go back to the PCAP for this!</b>

To get the answer of this we need to go back to the PCAP File. Right where we left. At the part where the attacker set the persistence up. We can see what salt he used.
![Attckers-Salt](/assets/img/overpass-2/attackers-salt.png)
<br>

> <b> Crack the hash using rockyou and a cracking tool of your choice. What's the password?</b>

Okay sow let's get cracking. We can use Hashcat to crack this hash. This is a SHA-512 hash. And we have the salt as well. So we will append the salt next to the hash so it appears liken this <b>"< hash >:< salt >"</b>. Now we can use Hashcat on it. I already ran it so I'm adding the <b>--show</b> tag in it as well. You dont need to use it.
![Hashcat](/assets/img/overpass-2/hashcat.png)
<br>

## Attack
<hr>

Okay so we have enough information now. We can use the information we gathered to get back in the server. Lets get to the tasks of this section.

> <b>The attacker defaced the website. What message did they leave as a heading?</b>

Remember what we did in the Task 2? I did the same again and got a request to <b> "Index.HTML"</b>. In it we can see what the hacker wrote on the website. (Easy solution is to go to the address and see the website in browser ;) )
![Website Name](/assets/img/overpass-2/website.png)
<br>

> <b>Using the information you've found previously, hack your way back in!</b>

We know that the attacker uploaded a backdoor on SSH. We can use the sam eto get back in again. We already cracked the password used to setup the backdoor. Also a thing to note, when we see the hash in Task 1 of Section 2, we can see the port that is being used for the backdoor. Its on Port 2222. Lets get in the server.
![Server](/assets/img/overpass-2/server.png)
<br>

> <b>What's the user flag?</b>

And we're in! Let us get the User Flag.
![User.txt](/assets/img/overpass-2/user.png)
<br>

> <b>What's the root flag?</b>

We can see a file using SUID Permissions in the user's home directory.
![SUID File](/assets/img/overpass-2/suid.png)
<br>
Searching about it on GTFOBins, we can see this paaragraph that gives us a hint on how to exploit it.
![GTFOBins](/assets/img/overpass-2/gtfobins.png)
<br>
So we use this <b>"-p"</b> flag and see if we can get a root shell.
![Root.txt](/assets/img/overpass-2/root.png)
<br>
Aaand we're ROOT! The machine is pwned. Submit the flags and get the points. Let me know if theres something you want to mention about the blog or anything in general. I'll be happy to talk! :smile:
