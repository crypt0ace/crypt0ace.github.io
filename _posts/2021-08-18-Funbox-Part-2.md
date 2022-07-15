---
title: "Funbox Part 2"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2021-08-18
description: "Funbox Part 2. The second part of a series of machines Funbox"
tags: [Write-Ups, Funbox Series]
---
## Introduction
<hr>
This is another easy rated box from Vulnhub created by [0815R2d2](https://twitter.com/@0815R2d2). Its the second part of a series of boxes called Funbox. Heres a link to this one and you can find the series on this page too: [Funbox 2](https://www.vulnhub.com/entry/funbox-rookie,520/).
<br>
Its a simple machine that starts off with a lot of work. This box is fairly easy and doesnt take long once you get through the initial part. You'll know what I'm talking about. After getting initial foothold you find the password for the user and then the classic 'sudo -l' process to get to root. Let's begin!

## Enumeration
As usual starting with the port scan we use Rustscan to scan the machine for open ports and we can find 3 ports open. 21 for FTP, 22 for SSH and 80 for HTTP.
<br>
<code>rustscan -a 192.168.57.30 -r 1-65530 -- -A -sC -vvv</code>
<blockquote> PORT      STATE SERVICE REASON  VERSION </blockquote>
<blockquote>21/tcp open  ftp     syn-ack ProFTPD 1.3.5e
| ftp-anon: Anonymous FTP login allowed (FTP code 230)</blockquote>
<blockquote>22/tcp    open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0) </blockquote>
<blockquote>80/tcp    open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
| http-robots.txt: 1 disallowed entry 
|_/logs/
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works</blockquote>
<br>
So let's start with the obvious FTP which has Anonymous Login enabled.

![FTP Anonymous Login](/assets/img/funbox-2/FTP_login.png)

We have a lot of zip files with random usernames available.
<br>
If we see the hidden listings as well, we can find a '.@admin' file among them.

![Hidden Files](/assets/img/funbox-2/ftp_ls.png)

The file was encoded in base 64 so I used the Base64 command to decode it.

![Admin File](/assets/img/funbox-2/admin_file.png)

And this where the work begins... I don't know if there was a way to make it easier or not, but I tried unzipping the zip file, then when it wasn't working used zip2john to get a hash and then tried to crack the hash using John the Ripper and Rockyou.txt. And I repeated it with every single one of them.. And the funny thing is, I didn't do it in order I was going randomly choosing. And I chose the one that actually work in the very last smh...
<br>
Here is it if it saves some time for you.

![Cracking Tom.zip](/assets/img/funbox-2/tom_unzip.png)

## Exploitation
We get a id_rsa file. Change the permissions on the file and then use it to login to SSH to get initial foothold.

![SSH Login](/assets/img/funbox-2/ssh_login.png)

And look what we get here. A ristricted bash shell. Just like in the last box. Used the same command as the last one to break out of it.

![Restricted Bash Escape](/assets/img/funbox-2/escaped_rbash.png)

After this the very first thing I did was look if we have a hidden file in our or if there is another user's directory. And I see something odd. The MYSQL_History file. I did ignore it for the first time and ran Linpeas around. But when I did'nt see anything good, went back the the history file and sure enough we found a clear text password in there.

## Privilege Escalation

![MYSQL Password](/assets/img/funbox-2/mysql_password.png)

To make it clear, the password is whatever is in read. the 040 is not in the password.
<br>
After getting the password I ran the classic 'sudo -l' to check sudo permissions and woah.. this guy can run any and all commands as root which makes it very easy for us. ALl we need to do is;

![ROOT!](/assets/img/funbox-2/root.png)

And just like that we rooted yet another Funbox Series Machine. Let me know if you liked it or want to give suggestions about the blog. Everything is welcomed. My contacts are in the footer right there. See you in the next one!