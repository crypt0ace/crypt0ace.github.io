---
title: "Blackfield - HackTheBox Walkthrough"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2022-07-17
description: "Blackfield - A hard diffficulty active directory box"
tags: [Write-Ups]
---
## Introduction
<hr>
This box is a hard difficulty box which has active directory installed made by [aas](https://app.hackthebox.com/users/6259).
<br>
This box starts with username enumeration to ASREP Roasting which gives us one user's hash. Cracking it and dumping bloodhound with it. Then moving to a new user which has access to a forensic share which contains lsass dump. We parse it to find another user's hash which gives us a shell on the machine. That user has some vulnerable backup privileges which we can exploit and get administrator access on the machine. Let's see how its done.

## Enumeration
`Nmap` scan shows us the following
```
Nmap scan report for 10.129.97.156
Host is up, received echo-reply ttl 127 (0.71s latency).
Scanned at 2022-05-29 08:44:58 PKT for 172s

PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-05-29 10:45:07Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m58s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2022-05-29T10:45:39
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 23438/tcp): CLEAN (Timeout)
|   Check 2 (port 41123/tcp): CLEAN (Timeout)
|   Check 3 (port 42695/udp): CLEAN (Timeout)
|   Check 4 (port 35589/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun May 29 08:47:50 2022 -- 1 IP address (1 host up) scanned in 173.13 seconds
```

We can see the usual active direcotry ports open. We can also identify the domain as `blackfield.local` which we can add to0 our `/etc/hosts` file. Going through my usual methodology we can see if RPC returns anything for anonymous login.
\
![RPC Enum](/assets/img/blackfield-hackthebox/rpc.png)
\
This returns nothing. We can move over to DNS enumeration by using the domain we found earlier to see if we can leak some other domains.
\
![DNS Enum](/assets/img/blackfield-hackthebox/dns.png)
\
We can see the `dc01` domain which confirms this is a domain controller we are working with. To also confirm the domain we can use LDAP queries. Sometimes the anonymous LDAP queries also reveal information about the users and the machines.
\
![LDAP Enum](/assets/img/blackfield-hackthebox/ldapsearch.png)
![LDAP Anonymous Queries](/assets/img/blackfield-hackthebox/anonymous_queries.png)
\
Now we can go ahead and look at the shares we have available. 
\
![SMB Enum](/assets/img/blackfield-hackthebox/smb.png)
\
We see 2 shares with read-only access. IPC and Profiles. If I see IPC share with read-only access I use the `lookupsid.py` from Impacket to see if we can perform bruteforcing of Windows SID’s to identify users/groups on the target machine.
<br>
This dumps a lot of usernames with the foramt of BLACKFIELD{some numbers}. My guess is that these accounts were generated through some script. Although we shouldn't be ignoring them because they might have some good stuff as well but for now lets remove them and generate a list of usernames we think are fit.
\
![IPC Enum](/assets/img/blackfield-hackthebox/ipc_enum.png)
\
After getting rid of the groups and other junk we get these usernames. Now we can look at the profile share. Looking at it we can see that it contains folders of usernames with nothing in them. We can get it directly from SMB but these huge files mess with me when I try to get them. So we can mount the shares and then copy them. A technique I saw from [0xdf's](https://twitter.com/0xdf_) blog [here](https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html).
\
![Mounting Shares](/assets/img/blackfield-hackthebox/mount.png)
\
Another thing I picked up from the blog is we can list the directories in one line using `ls -1`
\
![Listing Files](/assets/img/blackfield-hackthebox/ls.png)
\
We can add them to the wordlist of usernames we have from IPC to see if any of these may work.
\
![Creating a username list](/assets/img/blackfield-hackthebox/users.png)
![Appending to already made list](/assets/img/blackfield-hackthebox/mix.png)
\
Now we can check which one of these exist by using `kerbrute`
\
![Kerbrute](/assets/img/blackfield-hackthebox/kerbrute.png)
\
There are 3 duplicates which I believe are the ones from the profile share. So we the usernames from IPC are valid and only ones we have working.

## Exploitation
With the usernames in hand we can go ahead and do ASREP Roasting to see if we can get any users that dont require preauth which can give us their hashes. I'll be using `GetNPUsers.py` in a one liner I found from [0xdf's](https://twitter.com/0xdf_) blog post to see if we get any hashes back.
```bash
for user in $(cat creds-from-ipc.txt ); do GetNPUsers.py -no-pass -dc-ip 10.129.135.182 blackfield.local/${user} -format hashcat | grep -v Impacket; done
```
\
![AREP Roasting](/assets/img/blackfield-hackthebox/asrep.png)
\
And we find a hash for the user support. We can save it to a file and crack it using `hashcat` or `John`.
```bash
hashcat -m 18200 support.asrep ~/Desktop/rockyou.txt
john --format=krb5asrep -w=~/Desktop/rockyou.txt support.asrep
```
\
![Cracking Hash using John](/assets/img/blackfield-hackthebox/crack_hash.png)
\
And we find a password. We can then try to use it against the services that can give us a shell like SMB and WinRM.
\
![Testing Credentials](/assets/img/blackfield-hackthebox/testing_creds.png)
\
None of these say `pwned!` which is when you now you can crack a shell on the machine. SMB also shows NETLOGON and SYSVOL are new only which dont have anything good in them either. Tried RPC and Kerberoasting but no luck. After stumbling on it for a while I thought of running bloodhound to see anything new we can find.
\
![Dumping Bloodhound](/assets/img/blackfield-hackthebox/bloodhound_dump.png)
\
If we look at the Outbound Control Rights we can see that we have the `ForceChangePassword` authority over the user audit2020. Which means we can change its password.
\
![ForceChangePassword audit2020](/assets/img/blackfield-hackthebox/change_pass.png)
\
We can use RPC and its command `setuserinfo2` to change the password of audit2020. There's [this blog](https://room362.com/post/2017/reset-ad-user-password-with-linux/) that mentions how we can do that. Following it:
\
![Changed audit2020 Password](/assets/img/blackfield-hackthebox/rpc_pass.png)
\
We can test if we have access to services and the shares we can see now again.
\
![Forensic Share](/assets/img/blackfield-hackthebox/forensic_share.png)
\
We can see a new share forensic appearing. Let's see what it has.
\
![Forensic Share Enumeration](/assets/img/blackfield-hackthebox/forensic_share_enum.png)
\
It contains 3 different folers. We can get it again using mount to see what these have.
<br>
After some looking around I found a `lsass.zip` in the memory_analysis folder which seems interesting. After unzipping it I found a dump file of lsass process which we can parse using `pypykatz` on our machine. I wrote a blog detailing methods to dump lsass process if youre interested you can read it [here](https://crypt0ace.github.io/posts/Dumping-Lsass/).
\
![svc_backup Hash](/assets/img/blackfield-hackthebox/backup_hash.png)
\
And we can find another hash for user svc_backup. Testing it with the usual services and we can find that we can open a shell using WinRM.
\
![User.txt Found](/assets/img/blackfield-hackthebox/user.png)
\
And we found user.txt. 

## Privilege Escalation
For privilege escalation we can first check what privileges does this user have.
\
![Backup Privileges](/assets/img/blackfield-hackthebox/backup_privs.png)
\
We can see that there are backup privileges enables on this user. And we can find [this](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/) article that explains how this privilege is vulnerable. As [ARZ](https://twitter.com/arz_101) tipped me,  we can extract the `ntds.dit` file with this. The Ntds.dit file is a database that stores Active Directory data, including information about user objects, groups and group membership. To get it working we need the SYSTEM registry file as well. 
<br>
To get the SYSTEM file we can use `reg save` and then we can transfer them over using SMB.
\
![SYSTEM File](/assets/img/blackfield-hackthebox/system.png)
\
To get `ntds.dit` we will need to create a shadow copy of the C:\ directory which we can then use to get out `ntds.dit`
<br>
Got this script from the blog which creates a backup of the C:\ volume and names it E:\ and uploaded it to `C:\Windows\Temp`
```bash
set verbose onX
set metadata C:\Windows\Temp\meta.cabX
set context clientaccessibleX
set context persistentX
begin backupX
add volume C: alias cdriveX
createX
expose %cdrive% E:X
end backupX
```
Used `diskshadow` utility to make a shadow copy using this script.
\
![Diskshadow](/assets/img/blackfield-hackthebox/shaodw_copy_created.png)
\
Now we can use `robocopy` to copy the `ntds.dit` file from this copy we created to our share.
\
![NTDS Copy](/assets/img/blackfield-hackthebox/ntds.png)
\
It takes a while but after some time we get it in our machine and we can use `secretsdump.py` to parse it to get hashes. The results contain a lot of junk but we find our admin hash as well.
\
![Admin Hash](/assets/img/blackfield-hackthebox/admin_hash.png)
\
We can test the hash out using `crackmapexec`. Both SMB and WinRM show `pwned!` which means we can use `evil-winrm` or tools like `psexec.py` to get a shell. Easiest it WinRM so we can login and get root.txt.
\
![Root](/assets/img/blackfield-hackthebox/root.png)
\
Let me know if you would like to add something or give suggestions. You can contact me using the socials in the sidebar. Thanks!!