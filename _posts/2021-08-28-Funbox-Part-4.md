---
title: "Funbox Part 4"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2021-08-28
description: "Funbox Part 4. A beginner level boot2root machine series"
tags: [Write-Ups, Funbox Series]
---
## Introduction
<hr>
This box is the 4th part of boxes in a series named as Funbox. You can find the series [here](https://www.vulnhub.com/series/funbox,341/) and if your'e looking for this paticular box, [here](https://www.vulnhub.com/entry/funbox-next-level,547/). This one is also made by [0815R2d2](https://twitter.com/@0815R2d2).
<br>
This one starts out with a robots.txt file with a hidden directory. Which has upload functionality that takes our shell and gives us access in the machine. The root path is linux kernel exploitation. Let's see it through.
<hr>

## Enumeration
Starting out with the port scan:
<code>rustscan -a 192.168.57.45 -r 1-65530 -- -A -sC -vvv -oN initial</code>
Not putting the whole output because it feels messy but these are the ports that were open:
<blockquote>22		ssh		OpenSSH 7.2p2 Ubuntu 4</blockquote>
<blockquote>80		http	Apache httpd 2.4.18</blockquote>
<blockquote>110		pop3		Dovecot pop3d</blockquote>
<blockquote>143		imap		Dovecot imapd</blockquote>
<br>
Okay so let's see. We have SSH which we noramlly wouldn't look into because it's usually clean and not the initial foothold method. In any other case, you should actually looks into it because this may lead to some information disclosure. Let's start with port 80. It has a default Apache web page. Directory bruteforcing wasn't getting me anywhere either. I tried looking at robots.txt, nothing ther either. I tried robots.txt but in all uppercase as, ROBOTS.TXT, and found the robots file.

![Robots.txt File](/assets/img/funbox-4/robots.png)

But looking into 'upload/' dir didn't gave me anything. So I took another look at the source code of robots file, and saw a hidden directory at the very end.

![Hidden Directory](/assets/img/funbox-4/hidden.png)

going into this directory shows a 403 Forebidden. But we could try a directory scan in here.

![Directory Bruteforcing](/assets/img/funbox-4/directory.png)

And we can see the upload directory which we saw earlier in robots file right here. Along with a couple of upload pages. Let's go to the first one and try to upload a shell.

![Shell](/assets/img/funbox-4/shell.png)

And it looks like our shell was uploaded. So we know we can't view the uploads dir, but we can try to go to the '/upload/shell.php' and see if we get a call back.

![Foothold](/assets/img/funbox-4/foothold.png)

And we get a shel in here! If you're wondering what [Pwncat](https://github.com/calebstewart/pwncat) is, it's an amazing tool for reverse shells. I wrote a bit on it in the previous blogpost [here](https://crypt0ace.github.io/posts/doc-hackmyvm/).
<br>
Back to the box. For some reason, linpeas or linenum wasn't working for me. So I tried to look for kernel versions to see if we can find an exploit for it. And I indeed did find it. Here was the exploit for it, [CVE-2017-16995](https://www.exploit-db.com/exploits/45010). After compiling it I uploaded it on the machine and executed it.

![Root](/assets/img/funbox-4/ROOT.png)

And yes we get root! Don't mind the partially broken shell. We can go get the root flag.

![Root flag](/assets/img/funbox-4/root_flag.png)

Let me know if you have any suggestions for the blog or anything. My contacts are in the footer. I'll see you in the next one!