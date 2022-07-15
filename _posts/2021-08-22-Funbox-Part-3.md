---
title: "Funbox Part 3"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2021-08-22
description: "Funbox Part 3. Another easy beginner level boot2root machine"
tags: [Write-Ups, Funbox Series]
---
## Introduction
<hr>
Part 3 of a series of machines Funbox, which can be found [here](https://www.vulnhub.com/entry/funbox-easy,526/) created by [0815R2d2](https://twitter.com/@0815R2d2).
<br>
This is also a boot2root machine with a lot of rabit holes and can really cause a headache if you're too focused. But fortunately didnt happen with me by chance. Starts off with a book store what has default creds and a shell being uploaded to the website. Getting in it was pretty easy to get SSH access as user and then 'sudo -l' gives off privilege escalation tricks. Let's go.
<hr>

## Enumeration
Using rustscan for port scan:
<br>
<code>rustscan -a 192.168.57.36 -r 1-65530 -- -A -sC -vvv</code>
Not putting the whole output because it feels messy but these are the ports that were open:
<blockquote>22		ssh		OpenSSH 8.2p1 Ubuntu 4ubuntu0.1</blockquote>
<blockquote>80		http	Apache httpd 2.4.41</blockquote>
<blockquote>33060	sql		mysqlx</blockquote>
The HTTP website also hints at '/gym' directory which is in robots.txt. But just to be going through my methodology I'll start a gobuster scan as well.
<br>
The website shows a default webpage of apache. But my directory scan shows a lot more.

![Directory Scan](/assets/img/funbox-3/dir_scan.png)

## Exploitation
Okay there's a lot to go through. But I started with the obvious ones first. '/admin' looks good. Looked around, tried some default passwords. Nothing worked. Okay instead of wasting time here, let's move on. '/secret' seems sus. But it did'nt have anything other than a quote. We already know what robots.txt has. And I thought that obviously this looks like the only good way of entry. So let's eliminate the others first. MOving on to '/store', there is a admin login page as well. Tried default password of ADMMIN:ADMIN and oh we're in!
<br>
By looking at what we can edit in a book, I found that we can also add a image as book cover. Hmm.. Does it take anything other than a image? Let's upload a reverse shell php and test it.

![Shell Upload](/assets/img/funbox-3/shell_upload.png)

Ooop. Looks like it worked. To find where exactly did it go, I tried to view the image of any other book cover and found it.

![Image Folder](/assets/img/funbox-3/image_dir.png)

And it gave us a shell.

![Shell](/assets/img/funbox-3/shell.png)

Spawning a PTY Shell and stablizing the shell for better viewing

![PTY Shell](/assets/img/funbox-3/shell.png)

Looking around I found a tony directory in home directory. Which contained a 'password.txt' file. And this file contained SSH password for the user tony.

![SSH Password](/assets/img/funbox-3/ssh_tony.png)

## Privilege Escalation
So we SSH into the Tony user and use the command 'sudo -l' to see what this user can run as sudo

![Sudo Perms](/assets/img/funbox-3/sudo.png)

Okay we have a lot of things here. The best one that I see first is 'pkexec'. I have done this before and I know how we can use it to gain a root shell. Using the same method.

![ROOT](/assets/img/funbox-3/root.png)

And just like that this really easy machine is pwned. I'm glad I didn't go through the robots.txt rabbit hole becasue I know I would have wasted a lot of time on it. But anyways Part 3 is done. I'll see you in the next part. And as always if you ever need to contact me my contacts are down in th e footer below.