---
title: "Ways to Dump LSASS"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2022-07-16
description: "Here are list of ways that can be used to dump the lsass.exe process for credential harvesting"
tags: [Red Team]
---

## Introduction
In this post we are going to look at the methods we can use to dump LSASS. According to wikipedia "Local Security Authority Server Service (LSASS) is a process in Microsoft Windows operating systems that is responsible for enforcing the security policy on the system."
Basically, it stores the local usernames and passwords/hashes in it. So dumping this is one of the common things adversary and red teamers do. We can see the ways to dump it with and without the use of mimikatz.

### Mimikatz
Mimikatz is a very popular post exploitation tool which can be used to dump the lsass process and extract NTLM hashes from it.
First we can use the `sekurlsa::logonPasswords` if we are working with an old Windows machine. In the newer Windows versions we can not extract the plain text passwords.
![Dumping Logon Passwords](/assets/img/dump-lsass/dumping_logonpasswords.png)
This dumps a lot of information but we can see the values of WDigest passwords are empty. Which can mean that the Windows version is new. But the NTLM hashes do get dumped.
![Null Passwords](/assets/img/dump-lsass/null_passwords.png)
<br>
We can also use the `lsadump::lsa /patch` module to dump all the hashes from LSASS including the user accounts that were not dumped in logon passwords before.
![LSA Dump](/assets/img/dump-lsass/lsa_dump.png)
We can test the hashes or we can use hashcat to crack them
![Cracked Hash](/assets/img/dump-lsass/cracked.png)

### Task Manager
Bet you didnt knew task manager can be used to do something other than killing chrome did you? We can use it to create dump files of the lsass.exe process which we can then parse locally to extract passwords. Here's how. First you locate the process and right click it and create a dump file.
![Dumping lsass from Task Manager](/assets/img/dump-lsass/dumping_from_task_manager.png)
The dump file usually gets written to `C:\Users\Administrator\AppData\Local\Temp`. Once you retrieve it you can use tools like pypykatz or mimikatz itself to dump the hashes.
![Pypykatz parsing LSA.DUMP](/assets/img/dump-lsass/pypykatz_parsing.png)
![Found Admin Hash](/assets/img/dump-lsass/admin_hash.png)
To parse this using mimikatz we can use this
![Parsing dump using Mimikatz](/assets/img/dump-lsass/parse_using_mimikatz.png)

### Microsoft Signed Tools
Fortunately, Task Manager isnt the only Microsoft Signed binary we can use to dump lsass. We can use Procdump, ProcessExplorer, ProcessHacker etc. to dump lsass too. Ill show you how to do it using Procdump and leave the rest as a challenge for you.
When it comes to procdump there are different ways you can dump the lsass process. Here's the most basic way to do it.
![Dumping using procdump](/assets/img/dump-lsass/usual_procdump.png)
We can dump it by using a cloned process using
![Dumping Cloned Process using procdump](/assets/img/dump-lsass/cloned_lsass.png)
It can be done with using the process ID like this
![Dumping using Process ID](/assets/img/dump-lsass/process_id_dump.png)
![Dumping with Process ID](/assets/img/dump-lsass/process_dump.png)
We can use procdump to dump in a external share of ours as well
![Creating a share](/assets/img/dump-lsass/share_setup.png)
![Dumping to share](/assets/img/dump-lsass/dump_to_share.png)
After these dumps we can use the same methods to parse these and extract credentials as mentioned before.

### CrackmapExec
We can use crackmapexec to dump lsa secrets remotely as well.
![Crackmapexec to Dump LSA Secrets](/assets/img/dump-lsass/cme_lsa_dump.png)

### Comsvcs
We can use native comsvcs.dll DLL to dump lsass process using rundll32.exe
![Dumping using Comsvcs](/assets/img/dump-lsass/comsvc.png)

### Mini-Dump
We can use the Powersploit module [Out-Minidump.ps1](https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Out-Minidump.ps1) to dump lsass as well. 
![Dumping using Out-Minidump](/assets/img/dump-lsass/out-minidump.png)

### Dumpert
For more opsec safe and AV Bypassing dumping of lsass we can use the [dumpert](https://github.com/outflanknl/Dumpert) project by Outflank. It uses syscalls to avoid API hooking which can bypass some AVs/EDRs.
Theres two versions of it. A DLL and an executeable. Here's how we can use them.
![Dumping using Dumpert Executable](/assets/img/dump-lsass/dumpert_exec.png)
![Dumping using Dumpert DLL](/assets/img/dump-lsass/dumpert_dll.png)

## References
These are just some of the ways we can use to dump lsass without using mimikatz or any C2. Some other cool methods can be found [here](https://s3cur3th1ssh1t.github.io/Reflective-Dump-Tools/) by s3cur3th1ssh1t which are more opsec and AV/EDRs bypassed focused.

- [IRed.Team](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dump-credentials-from-lsass-process-without-mimikatz)
- [WhiteOakSecurity](https://www.whiteoaksecurity.com/blog/attacks-defenses-dumping-lsass-no-mimikatz/)
- [MarkMorig](https://medium.com/@markmotig/some-ways-to-dump-lsass-exe-c4a75fdc49bf)