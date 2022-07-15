---
title: "Doc - HackMyVM"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2021-08-27
description: "Doc - A boot2root machine with the goal of reading root flag"
tags: [Write-Ups]
---
## Introduction
<hr>
This is an easy room on [HackMyVM](https://hackmyvm.eu) made by [sml](https://twitter.com/x6cx61x63x61x73). You can find this room at [Doc - HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Doc).
<br>
This is a simple machine that has a web server using a vulnerable program that we can exploit to gain a initial foothold. The root part after it was pretty cool. I admit I also had to ask for a nudge to look at it clearly which helped me exploit it and get a root shell. Let's walk down the lane and see how it works.

## Enumeration
<blockquote>80/tcp open  http    syn-ack nginx 1.18.0</blockquote>
<br>
Okay so all we see is one port which is 80 open and it has a website on it. Going over to the actual website, we see this.

![Website](/assets/img/doc/website.png)

## Exploitation
So its using Online Traffic Offense Management System - PHP on the website. We can look for exploits that might have been available on google. And we find a Unauthenticated RCE exploit on the same app. Couldn't get more better than this.

![Exploit Database](/assets/img/doc/exploit.png)

Also by going to the Login page on the Vulnerable website, We can see that it points to a domain "doc.hmv". We can add it to our /etc/hosts. Now let's run the exploit.

![Web Shell](/assets/img/doc/webshell.png)

And here it is. We have what seems like a webshell on the box. Let's get a pty shell going on so we can stablize it and work with it.
<br>
So I dont know if you've heard of it, but there's this really amazing tool called [Pwncat](https://github.com/calebstewart/pwncat) which is made by [Caleb Stewart](https://twitter.com/calebjstewart) and [John Hammond](https://twitter.com/_johnhammond) and trust me, it is absolutely beautiful. Makes you life hella easy. It automatically stablizes the shell and makes upload and downlaoding from the connected machine a lot easy. It has alot of other features as well. I would suggest you watch this video in which both Caleb and John present Pwncat to get a better insight in the power of the tool, [Introducing Pwncat: Automating Linux Red Team Operations](https://www.youtube.com/watch?v=CISzI9klRkw). Okay back to the box.
<br>
I used the great [Revshell](https://www.revshells.com/) website to generate a Python3 reverse shell.

![Reverse Shell](/assets/img/doc/reverse_shell.png)

And we recieve a shell back to our pwncat.

![Pwncat Shell](/assets/img/doc/pwncat_shell.png)

Okay so from here on we can use CTRL+D to interact with the active session. We have www-data user and th eother user is bella. We can upload the linpeas binary to get a good look at what we can use for our advantage. Just to show you how easy it is to upload linpeas I'll upload it in the /tmp directory.

![Pwncat Linpeas Upload](/assets/img/doc/linpeas_upload.png)

(Garry says *ignore the typo or I'll steal your lunch money*) I got a new keyboard I'm still trying to get used to it.
<br>
The linpeas output shows the user bella's SQL Password.

![Bella's Password](/assets/img/doc/bella_password.png)

I thought to try it as the user password as well and We get in the user bella!

![Logged in as Bella](/assets/img/doc/bella_login.png)

## Privilege Escalation
From here on we can use sudo -l to see what we can run as root. And we see a weird binary doc that we can run.

![Sudo -l](/assets/img/doc/sudo.png)

When we run it, I couldn't see anything that might resemble this program. It was seemingly running a webserver locally on port 7890 with only 2 options. Either browse or quit. It didn't make sense. I tried to curl it after running the webserver to see what it actually serves. It was some sort of Pydoc's Index of Modules. And I was stuck. I asked in the Discord for a nudge and the creator of the box sml suggested to check for strings in the program to see what is actually doing.
<br>
This made everything clear. I found that the command it was running was 'PyDoc3.9 -p'.

![PyDoc](/assets/img/doc/pydoc.png)

And a simple Google search led me to this article [CVE-2021-3426: Information disclosure via pydoc -p](https://bugs.python.org/issue42988). This explains how "/getfile?key=" parameter is vulnerable and other users can see arbitratry files on the server.So I used curl to get the root flag using the same method.

![Root Command](/assets/img/doc/root_command.png)

And we can see the Root Flag in the HTML.

![ROOT](/assets/img/doc/ROOT.png)

And we're done! It was a pretty good box with a nice way to root. As always let me know if you have suggestions for the blogs or if you just wanna talk about anything. My contact info is in the footer. Till next time!