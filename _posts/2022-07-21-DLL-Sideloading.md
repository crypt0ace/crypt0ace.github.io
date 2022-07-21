---
title: "Guide to DLL Sideloading"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2022-07-21
description: "This blog post talks about DLL Sideloading. A technique which is quite popular with the APTs"
tags: [Red Team]
---

## Introduction
DLL Sideloading is a technique related to DLL Hijacking. Its similar to search order hijacking but instead of dropping a malicious DLL, in this technique we drop a legitimate DLL and a malicious DLL. The malicious DLL loads our shellcode and then forwards every other call to the legitimate DLL. This way program gets executed as normal (unlike other DLL hijacking methods which mostly result in crashing the program) and our shellcode gets executed as well.
<br>
It's kind of a hit or miss thing. At least from what I've experienced. Finding the perfect DLL to attack, the application to attack all takes a lot of trial and error. To keep things simple I will not be going into protecting the payload or delivery mechanism or any of the advanced areas. I'll just be showing you how one can do this type of attack and why it seems so interesting (at least to me xd).
<br>
Recently the team at Palo Alto Networks [Unit 42](https://twitter.com/Unit42_Intel) released a blog documenting the TTPs of APT29 and how they used the DLL Search Order Hijacking and DLL Sideloading to attack users which you can read [here](https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/). This and a really cool blog post from [Sunggwan Choi](https://twitter.com/_choisec) which can be found [here](https://blog.sunggwanchoi.com/recreating-an-iso-payload-for-fun-and-no-profit/) spiked my interest and I wanted to showcase how I have been testing it out with the C2 sliver. I'm not that pro yet but still this method seems really good so let's look into it. 

## The Idea
So after a lot of trail and error I found out that the Notepad++ app has a updater file `GUP.exe` that is vulnerable. That said, I did try a lot of apps, mainly I wanted to test Microsoft Signed binaries but I couldn't get them to work (yet?). But this one seemed to work. The idea behind it is that we create a copy of the original DLL and a malicious DLL with our shellcode in it. When the program gets executed, our malicious DLL gets loaded triggering our shellcode. But at the same time, notmal calls that the binary will be making are forwarded to the original DLL like a "proxy" which makes the execution of the program successful. Which is also why it is mentioned as DLL Proxying in some cases. This has been tested to completely bypass Windows Defender on my testing machine as well.

## Methodology
The simple sequence goes like this

- Find a vulnerable DLL using Procmon
- Create a shellcode
- Create a proxy DLL of the original legitimate DLL
- Upload them to the machine and execute them

### Finding Vulnerable DLLs
As mentioned before it wass more of a trial and error for me but eventually I chose the Notepad++ program. In the updates directory, I found a `GUP.exe` binary which also reminded me of a DLL Sideloading article I read a while ago so I went with this. 
\
![GUP.exe](/assets/img/dll-sideloading/gup.png)
\
To find the DLLs we can utilize we use Procmon with the following filters.
\
![Procmon Filters](/assets/img/dll-sideloading/procmon_filters.png)
\
Among these we can select one DLL. The smaller the better. In this case `ncrypt.dll` is smaller so we will be going with it. These DLLs can be found in `C:\Windows\System32\` folder for x64 bit machines. But due to search order system in Windows they look for the DLLs in the current directory first. In the next step we will copy this DLL to our dev workstation to buld a proxy DLL.

### Building a Proxy DLL and Using Sliver C2
For the dev workstation I use Commando VM. You can get it from [here](https://github.com/mandiant/commando-vm). After copying the DLL here we are going to use [Flangvik's](https://twitter.com/flangvik) tool [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) which we can use to create a proxy DLL. After cloning the repository build it with Visual Studio. While it's building it we can go ahead and get our shellcode ready.
<br>
For this I am going to use Sliver C2. It's the new hotshot in town, everyones been talking about it and I've been using it for a while now. It's really impressive with a lot of features in it. You can get it from [here](https://github.com/BishopFox/sliver) and read the documents to see what interesting measures it has. I'll be using it to create the shellcode file. First we need to start a listener and then generate the shellcode.
\
![Sliver Shellcode](/assets/img/dll-sideloading/sliver_shellcode.png)
\
The payloads by sliver by default can be really big. In these cases we would idealy be using stagers to keep the size to minimum. However right now I'll just be continuing with the defaults. We can now send it over to our dev workstation. I renamed the payload to `payload.bin`
<br>
After sending it over we can now use `SharpDLLProxy.exe` to build a proxy DLL.
\
![Building Proxy DLL](/assets/img/dll-sideloading/proxy.png)
\
This outputs 2 files for us according to the photo.

- `tmpCA21.dll` = The original legitimate DLL
- `ncrypt_pragma.c` = The DLL that will execute the shellcode and forward the calls to original DLL

You can rename the tmp DLL to something sneaky but I'm going to keep it as it is. Next step is to build the C file we have for our sideloading DLL. Open Visual Studio and Select Dynamic Link Library for C++. Make sure to name the project with original DLL name. In our case it will be `ncrypt`
\
![Creating DLL](/assets/img/dll-sideloading/dll_project.png)
\
Copy the contents of `ncrypt_pragma.c` to `dllmain.cpp` and build it. In case you're wondering how this works, the DLL we create is going to use pragma comments and linkers to forward the calls to the legitimate DLL.
\
![Pragma Comments](/assets/img/dll-sideloading/pragma_comments.png)
\
We can see our tmp DLL which the calls will be forwarded to.
\
![Reading Payload](/assets/img/dll-sideloading/payload_read.png)
\
Then it reads our payload and executes it. We can build it now. This will give us a `ncrypt.dll`. Now we have all the contents, lets move to exploitaiton.

### Exploitation
Now we can move the files over to the target VM. We know that the path it looks for the DLL is `C:\Program Files\Notepad++\updater` so we will be dropping three files here

- `tmpCA21.dll` = The original legitimate DLL
- `ncrypt.dll` = The proxy DLL we created
- `payload.bin` = Our payload shellcode

After moving them over, we can now execute the `GUP.exe` and see the shell call back to our sliver C2.
\
![Spawning Shell](/assets/img/dll-sideloading/spawn_shell.gif)
\
And we have a shell on a fully patched Windows computer with Defender enabled. Obviously this can be improved a lot. It could be more stelthier, more APT like. For that I would recommend going through [this](https://blog.sunggwanchoi.com/recreating-an-iso-payload-for-fun-and-no-profit/) blog as it mimics the exact ways APT29 works with this.

### The Differences
The difference between this one and APT29 one is the fact that we cant actually use it anywhere. Ideally, like APT29, we would be looking for standalone executables. In our case `GUP.exe` wont work if its not in that folder. Secondly, this method is more like explaining how DLL Sideloading works. We would be needing to create a good delivery mechanism like APT29 uses ISO, to make this attack more real life compatible.

## References
Hope you guys learned something new. Let me know what you think. You can always contact me through methods in the left side bar.

- [DLL-Sideloading](https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/defense-evasion/untitled-5/dll-side-loading)
- [Hijack Execution Flow: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002/)
- [DLL Side-loading: A Thorn In The Side Of The Anti-virus Industry](https://www.mandiant.com/resources/dll-side-loading-a-thorn-in-the-side-of-the-anti-virus-industry)
- [Recreating an ISO Payload for Fun and No Profit](https://blog.sunggwanchoi.com/recreating-an-iso-payload-for-fun-and-no-profit/)
- [When Pentest Tools Go Brutal: Red-Teaming Tool Being Abused by Malicious Actors](https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/)