---
title: "Funbox Part 1"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2021-08-14
description: "Funbox Part 1. An easy beginner level boot2root machine"
tags: [Write-Ups, Funbox Series]
---
## Introduction
<hr>
This is a box rated easy from Vulnhub released on 20-Jul-2020, created by [0815R2d2](https://twitter.com/@0815R2d2). Its a part of a series of boxes called Funbox. Heres a link to this one and you can find the series on this page too: [Funbox 1](https://www.vulnhub.com/entry/funbox-1,518/).
<br>
The machine is a boot2root type machine in which we start from a simple user gained through bruteforce and move to another user to find a way to root a box. Pretty fun box. Learned a lot. Very good for beginners. Let's get to it now shall we?
<hr>

## Enumeration
So I was trying to do a complete enumeration on this box and try to find as many exploitation ideas I could get. Let me walk you through the process..
<br>
Starting with the obvious port scan. I used Rustscan by the very best [Bee-Sec-San](https://twitter.com/bee_sec_san) to do the port scanning because its pretty fast. You can get it from [here](https://github.com/RustScan/RustScan). Here's the command I used:
<br>
<code>rustscan -a 192.168.57.22 -r 1-65530 -- -A -sC -vvv</code>
<blockquote> PORT      STATE SERVICE REASON  VERSION </blockquote>
<blockquote>21/tcp    open  ftp     syn-ack ProFTPD</blockquote>
<blockquote>22/tcp    open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0</blockquote>
<blockquote>80/tcp    open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry
|_/secret/
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://funbox.fritz.box/</blockquote>
<blockquote>33060/tcp open  mysqlx? syn-ack</blockquote>
I found 4 Ports open. Port 21 for FTP, Port 22 for SSH, Port 80 for HTTP, Port 33060 for MySQL.
And from here I started to enumerate each service one by one. Starting by FTP.
<br>
I tried Anonymous Login first but it was disabled.

![FTP](/assets/img/funbox-1/ftp.png)

Next I tried finding the version of FTP so we could look for exploits if available. I found that Metasploit has a auxiliary module for it. 

![FTP Version Module](/assets/img/funbox-1/ftp_version.png)

So I ran it to see for FTP Version information.

![FTP Version Result](/assets/img/funbox-1/ftp_version_result.png)

Hmm.. Looks like we don't get much information here. Let's move to SSH for now.
<br>
So our scan results show that OpenSSH Version 8.2p1 is being used. Let's look it up searchsploit.

![Searchsploit OpenSSH](/assets/img/funbox-1/searchsploit-openssh-8.png)

Didn't find anything that looks interesting.
<br>
Moving over to Port 80 which has a website hosted. Found a WordPress website.

![Website](/assets/img/funbox-1/url_found.png)

We also found the same URL we had seen in the Nmap scan results if you looked closely. Time to add it up in the /etc/hosts file of ours.

![/etc/hosts Edit](/assets/img/funbox-1/etc_hosts.png)

Um.. I'm not sure if adding all the possible variations of the somain is good practice or not. I'm a noob. Maybe ask Google about this more before following as I will do the same as well.
<br>
So it being a WordPress website let's run a wpscan and see what we have here.

![WPScan](/assets/img/funbox-1/wpscan_run.png)

And while the wpscan is running, let's go ahead and check that robots.txt file we saw earlier in our port scan. You may or may not have missed it. But it was here.

![Robots.txt Found](/assets/img/funbox-1/robots.txt_found.png)

Visiting the robots.txt shows us a /secret/ directory being disallowed. This looks very good.

![Robots.txt](/assets/img/funbox-1/robots_value.png)

Lets try to see what it is.

![Secret Directory](/assets/img/funbox-1/secret_directory.png)


Okay that was nothing. I still looked around but found othing. Just a rabbit hole.
<br>
Okay back to the WPScan. The scan gave out 2 usernames. Joe and Admin.

![WPScan Initial Results](/assets/img/funbox-1/users_found.png)

## Exploitation
We can use this to perform a bruteforce attack againt the two users. I ran them one by one but it's possible to do 2 at the same time. Starting with the user Joe. Used the RockYou.txt as a wordlist and got the results.
<br>
And we got a hit. The user Joe's password.

![WPScan Bruteforce Results](/assets/img/funbox-1/wpscan_bruteforce_results.png)

(I accidently deleted the photo so used this editing photo XP)Logged into Wordpress and saw that the user Joe has very limited access.

![WordPress Dashboard](/assets/img/funbox-1/wordpress_dashboard.png)


Started looking for vulnerabilities I could find for the WordPress version. At the same time I also started running another bruteforce attack on the user admin using the same wordlist.
<br>
Couldn't find anything on the Wordpress version but we actually got a hit on the admin user on bruteforce.
<br>
So logged in using admin credentials. Tried to upload the reverse shell in 404.php page. But I couldn't.

![Reverse Shell WordPress](/assets/img/funbox-1/shell_upload.png)


So at this time I thought about Password Reusing. Maybe either Admin's or Joe's password is also being used at the SSH Service? Well I tried the user Joe with his password. And I got in.

![SSH Login](/assets/img/funbox-1/ssh_login.png)

Coming in tried to go a directory back and see what other users we may have. But this was a restricted bash shell.

![RBASH](/assets/img/funbox-1/rbash.png)

Could confirm this using:

![RBash Confirm](/assets/img/funbox-1/rbash_confirm.png)

I used pyhon to spawn another shell as bash and escape the rbash shell. Using this command:

![Escaped RBash](/assets/img/funbox-1/escaped_rbash.png)

Okay so now we can look around. In our hone directory I couldn't find anything.
I tried to do a 'sudo -l' to see if we have something in the sudoers file. No luck.
<br>
So I looked at the /etc/passwd file to see what other users we might have.

![/etc/passwd File](/assets/img/funbox-1/etc_passwd.png)

## Privilege Escalation
Okay so we have another user 'Funny' with their own home directory. Let's look what we have in there. And we can see a backup script in there.

![Home of Funny](/assets/img/funbox-1/backup_found.png)

Okay so anyone can read, write and execute this file. That's good. We can upload a reverse shell in there and see if we get a call back. But we need to be sure if we will be getting a call back. I cant see the cronjobs from this user so we will put pspy64 binary on the machine and see if there's something worth our while.

![PSPY64](/assets/img/funbox-1/pspy64.png)

Wait thats strange. It confirms that there is a cronjob running. But looking at this, it looks like the cron job is running once with UID:1000 and once with UID:0. Which means its running once with user funny as once as root user.
<br>
This means if we wait after uploading our shell, we can get root access. Let's test this out. First to generate a reverse shell, I'll be using the [Revshells](https://www.revshells.com/) Website by the very talented and awesome [Ryan Montgomery](https://twitter.com/0dayCTF).

![Reverse Shell Generate](/assets/img/funbox-1/0days_revshell.png)

Pretty easy when using the website. Okay so we write it to the backups script.And now we wait. After about 2 minutes and a couple of tries.. We got ROOOT! We finally successfuly pwned the box.

![ROOT!](/assets/img/funbox-1/ROOT.png)

Let me know if you liked it. My contacts are in the footer. Hope you enjoyed. All criticisms are welcomed btw. Let me know how I can make it better. Will be continuing this Funbox Series in the future (hopefully). See you in the next one!