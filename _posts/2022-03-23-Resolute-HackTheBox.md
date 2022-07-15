---
title: "Resolute - HackTheBox Walkthrough"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2022-03-23
description: "Resolute - A medium diffficulty box with active directory"
tags: [Write-Ups]
---
## Introduction
<hr>
Hello again. Today I will be looking into a medium box based on active directory from HackTheBox made by [egre55](https://twitter.com/egre55). 
<br>
This box starts with an easy foothold. The password is retrieved from RPC which gives us initial access. Then we move over to ryan user which is a part of DNS Admins group that has a priv esc route. Lets get into it.

## Enumeration
Nmap scan shows a lot of ports open. But the noteable ones are, DNS, WinRM, LDAP, And a bunch of RPC ports showing that it may be a domain controller. For a full port scan list you can refer to [this](https://github.com/crypt0ace/Write-Ups/blob/main/HTB/resolute/allports.nmap).
<br>
So first lets enumerate LDAP and see if we can leak some information about the machine.

![LdapSearch](/assets/img/resolute-hackthebox/ldapsearch.png)

It outputs a lot of information but the important one is that it gives us a domain name. We can add it to our /etc/hosts file. I tried looking for other domain names but no luck.
<br>
Now we can enumerate RPC and see if that leaks any information.

![RPCClient](/assets/img/resolute-hackthebox/rpcclient.png)

And it works! We have a list of users we can save. We can look at the groups too.

![Groups](/assets/img/resolute-hackthebox/groups.png)

We see all the normal ones except the "Contractors" group. Lets see whose part of that group.

![Contractors](/assets/img/resolute-hackthebox/contractors.png)

We see it only has one member Ryan Bertrand. Its good to keep it in the back of your head.
<br>
Now another thing we can do is display decription of user accounts. Maybe they contain passwords? Lets see.

![Display](/assets/img/resolute-hackthebox/display.png)

And we do have it! We can use the list of users and this password to do password spraying and see it if actually gets us access into anything. I'll use CrackMapExec for that.

![crackmapexec](/assets/img/resolute-hackthebox/crackmapexec.png)

Okay so after many errors we have one user. But it doesnt say pwned. Which means we can use something like psexec to get a shell in it. But we do have WinRM open on the box. We can try that using crackmapexec too.

![winrm](/assets/img/resolute-hackthebox/winrm.png)

We got it! We get the pwned sign which means we can get a shell now using Evil-WinRM

![initial](/assets/img/resolute-hackthebox/initial.png)

First thing we can look for is user.txt and retireive it. Lets look into users that have a home directory.

![users](/assets/img/resolute-hackthebox/users.png)

And we have ryan user. Which makes me wonder maybe we're supposed to escalate to this user before actually getting root. After several rabbit holes I used the command that shows the hidden files in powershell. And I found a folder named PSTranscripts.

![hidden](/assets/img/resolute-hackthebox/hidden.png)

I used the WinRM's download feature to get the powershell script I found.

![transcript](/assets/img/resolute-hackthebox/transcript.png)

And we find a password for ryan user.

![Ryans Password](/assets/img/resolute-hackthebox/ryan_password.png)

We can use it to get a shell using WinRM now.

![Ryan](/assets/img/resolute-hackthebox/ryan.png)

Now we can see the permissions and privileges the user Ryan has.

![DNS Admins](/assets/img/resolute-hackthebox/dnsadmin.png)

We have the user ryan in the DNS Admin group. Which can be vulnerable and is explained in this [article](https://medium.com/techzap/dns-admin-privesc-in-active-directory-ad-windows-ecc7ed5a21a2). So following the steps, we can try to escalate our priviliges to administrators. Making the malicious DLL and staring a SMB Server.

![Server](/assets/img/resolute-hackthebox/server.png)

Now we can inject the DLL and restart the service to see if we can get a shell back.

![Root](/assets/img/resolute-hackthebox/root.png)

And just like that we're ROOT!! We can now get the root flag and submit it!
<br>
If you have suggestions or if you wanna talk about anything. Contact me from the info in the footer. Till next time!