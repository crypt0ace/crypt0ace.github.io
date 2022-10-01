---
title: "Using D/Invoke for Offensive Tool Development in C#"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2022-10-01
description: "Using D/Invoke for Offensive Tool Development in C#"
tags: [Red Team]
---
## Introduction:
In this post we are going to have a look into the [D/Invoke](https://github.com/TheWover/DInvoke) project by [TheWover](https://github.com/TheWover). He also wrote a really good blog post which you can read [here](https://thewover.github.io/Dynamic-Invoke/) where he demonstrates in detail how the whole project works. It covers some really cool aspects so its highly recommended to check it out. This post mainly focuses on creating a shellcode injection tool using all the methods that he specifies in his blog.
<br>
Sharpsploit also has integrated D/Invoke in their project which can be read about [here](https://github.com/cobbr/SharpSploit/blob/master/SharpSploit/SharpSploit%20-%20Quick%20Command%20Reference.md#sharpsploitexecutiondynamicinvoke).

## What is D/Invoke
I have talked about what P/Invoke or Platform Invoke is in the previous posts ([here](https://crypt0ace.github.io/posts/WinAPI-and-PInvoke-in-CSharp/) if youre interested). Its a great way to use WinAPI and unmanaged code into our managed C# code. But it has some issues for us as offensive tool developers. Its not really OPSEC safe. A lot of AVs/EDRs catch these tools easily. In the last post, I talked about how EDRs usually work by hooking into processes and how we can try and evade their detections by unhooking DLLs. A good method but still not OPSEC safe. What if the defenders look at those specific imports that are made to unhook the DLLs? What is they are looking at the suspicious imports? Thats where D/Invoke comes in.
<br>
Using D/Invoke we can dynamically invoke (hence the name D/Invoke) during runtime from the DLL loaded in memory which can help us bypass API hooks and also the Import Address Table would not show any suspicious imports.
<br>
The inner workings of some methods used in D/Invoke are similar to what I already have posted about. The classic method uses delegates almost similar to what I discussed [here](https://crypt0ace.github.io/posts/Staying-under-the-Radar-Part-2/), the mapping method is similar to what was discussed [here](https://crypt0ace.github.io/posts/Staying-under-the-Radar-Part-3/). But it takes a whole lot of work and makes things very simple and easy and some other cool features as well.

## Using D/Invoke
There's 4 different ways we can use D/Invoke.

- Dynamic API Method (Classic Method)
- Manual Mapping Method
- Overload Mapping Method
- Syscalls Method

### Dynamic API or Classic Method
The simplest and easiest way to get started with D/Invoke is using teh dynamic API method. It is called using `DynamicAPIInvoke` and it uses `GetLibraryAddress` to locate the function specified from the module in memory or from disk. I have cloned the [D/Invoke](https://github.com/TheWover/DInvoke) repo from github and added the D/Invoke folder in my solution on Visual Studio. Should be noted that this project is also available in nuget so you can get the DLL directly and use that too. For our demo, we are using these API calls

- OpenProcess
- VirtualAllocEx
- WriteProcessMemory
- CreateRemoteThread

I'm using the same example from [here](https://github.com/crypt0ace/CS-ShellcodeInjection/) and porting it from P/Invoke to D/invoke so its going to follow the same logic.
<br>
For using `OpenProces`, we would need to use `GetLibraryAddress` with 2 parameters. the DLL or module name, and the function call we need. Then we need a delegate with the parameters that the function needs because we are going to get a function pointer for that delegate which we can pass the arguments we need. Remember to add the namespace with `using DInvoke;` and keep an eye from where the methods are being called like *`DInvoke.DynamicInvoke.Generic.`*`GetLibraryAddress()`.
```csharp
// The Delegate
[UnmanagedFunctionPointer(CallingConvention.StdCall)]
public delegate IntPtr OpenProcessD(UInt32 dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId);

// The Function Call
ptr = DInvoke.DynamicInvoke.Generic.GetLibraryAddress("kernel32.dll", "OpenProcess");
OpenProcessD OpenProcess = (OpenProcessD)Marshal.GetDelegateForFunctionPointer(ptr, typeof(OpenProcessD));
IntPtr procHandle = OpenProcess((uint)desiredAccess, false, (uint)processId);
```

Its this simple to get a dynamic API call working. Another way is to use this is to first create a object array to store our parameters. Then use `DynamicAPIInvoke` with 4 parameters. The DLL or module name, function call, the delegate and then a reference to the object array of arguments that were specified.
```csharp
// Also needs the delegate
object[] OpenProcessArgs = { (uint)desiredAccess, false, (uint)processId };
IntPtr procHandle = (IntPtr)DInvoke.DynamicInvoke.Generic.DynamicAPIInvoke("kernel32.dll", "OpenProcess", typeof(OpenProcessD), ref OpenProcessArgs);
```

Both of these are similar with how they work. Using the same method we can port all the other API calls to D/Invoke. The full source code is mentioned at the end.

### Manual Mapping
If you read the last post about unhooking DLLs in which we mapped a fresh copy of NTDLL in memory by getting a handle to the DLL on disk mapping it in memory using all sorts of APIs then manually rewritting the `.text` section with our new fresh DLL. Using D/Invoke, all this can be summarized in just 2 lines of code.
```csharp
PE.PE_MANUAL_MAP mappedDLL = new PE.PE_MANUAL_MAP();
mappedDLL = DInvoke.ManualMap.Map.MapModuleToMemory(@"C:\Windows\System32\kernel32.dll");
```

Best case is to use `ntdll.dll` because if `kernel32.dll` calls APIs from `NTDLL.dll` that are hooked by AV/EDR it will get caught but in this case Im going to be using `kernel32.dll` to make it simpler. 
<br>
The rest of the code is similar. We need to specify a delegate for our function just like before, and object array of arguments we need and then we use `CallMappedDLLModuleExport` with 6 arguments. The `PEINFO` struct of our newly mapped DLL, the module base address of our DLL, the function name we need, the delegate, function arguments and wether or not the DLLMain method is needed to be called. Calling from modules like `kernel32.dll` or `NTDLL.dll` etc set this to false.
```csharp
object[] OpenProcessArgs = { (uint)desiredAccess, false, (uint)processId };
IntPtr procHandle = (IntPtr)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "OpenProcess", typeof(OpenProcessD), OpenProcessArgs, false);
```

Using this way we can put together the other APIs as well and get our shellcode executed. No need to map the same module again. Just use the `CallMappedDLLModuleExport` in case you're using the same DLL.

### Overload Mapping
Very similar to manual mapping method with one key difference. According to the blog by TheWover
<br>
*Module Overloading allows you to store a payload in memory (in a byte array) into memory backed by a legitimate file on disk. That way, when you execute code from it, the code will appear to execute from a legitimate, validly signed DLL on disk.*
<br>
This method makes it more stealthier. Usuage is the same as manual mapping.
```csharp
PE.PE_MANUAL_MAP mappedDLL = new PE.PE_MANUAL_MAP();
mappedDLL = DInvoke.ManualMap.Overload.OverloadModule(@"C:\Windows\System32\kernel32.dll");
```

And then we can call the functions using the same way as before.
```csharp
object[] OpenProcessArgs = { (uint)desiredAccess, false, (uint)processId };
IntPtr procHandle = (IntPtr)DInvoke.DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase, "OpenProcess", typeof(OpenProcessD), OpenProcessArgs, false);
```

### Syscalls
Syscalls can be explained in a whole other blog. Its the hot topic and very much used by advanced malware authors in order to evade AVs/EDRs. The summary is that because AVs/EDRs hook API calls like `OpenProcess`, offensive developers started to use `NtOpenProcess` from `NTDLL.dll` to which `OpenProcess` gets transfered anyways for transition into kernel land. When AVs/EDRs caught up to this they started to hook into `Nt*` functions as well. Then came syscalls. Looking up the `NTDLL.dll` in memory and calculating where the syscall for the function is and using it to get directly to the kernel avoiding the hooks.
<br>
This small summary doent do justice to the whole theory of syscalls wo its recommended to read up further on this topic. SOme refernces are provided at the end.
<br>
This technique is a bit trickier and took some time until I figured it out. The issue were 2 things.

- Identifying what userland calls get forwarded to what kernel mode calls.
- What arguments are supposed to be provided to the `Nt*` calls.

We can use the `GetSyscallStub` function from D/Invoke with the function name we want. We dont need to provide any DLL because it will always look up form `NTDLL.dll`. Then next step is to get a funtion pointer for our delegate. And then we use the `NtOpenProcess` call. For the arguments that we need to provide i took a look at three resources.
 
- [PInvoke.net](https://www.pinvoke.net/index.aspx)
- [DInvoke.net](https://dinvoke.net/)
- [Undocumented APIs](http://undocumented.ntinternals.net/)

These calls also use the NTSTATUS struct. So we can initialize the syscall stub and the marshaling using this.
```csharp
IntPtr syscall = IntPtr.Zero;
syscall = DInvoke.DynamicInvoke.Generic.GetSyscallStub("NtOpenProcess");
NtOpenProcess NtOpenProcess = (NtOpenProcess)Marshal.GetDelegateForFunctionPointer(syscall, typeof(NtOpenProcess));
```

Then we can provide the arguments as this.
```csharp
var oa = new Native.OBJECT_ATTRIBUTES();
var cid = new Native.CLIENT_ID
{
  UniqueProcess = (IntPtr)processId
};
var procHandle = IntPtr.Zero;
Native.NTSTATUS status = NtOpenProcess(ref procHandle, desiredAccess, ref oa, ref cid);
```

This way we can do all the APIs as well.

## Code
The full source code demonstrating all the methods can be looked at [here](https://github.com/crypt0ace/CS-ShellcodeInjection/tree/main/DInvoke). Provide the tool with a process ID as argument and you can specify the method by uncomenting the method you want to use.

## References
Credits to the work these amazing researchers

- [D/Invoke - TheWover](https://github.com/TheWover/DInvoke)
- [Emulating Covert Operations - Dynamic Invocation (Avoiding PInvoke & API Hooks) - TheWover](https://thewover.github.io/Dynamic-Invoke/)
- [Dynamic Invocation in .NET to bypass hooks - NVISO Labs](https://blog.nviso.eu/2020/11/20/dynamic-invocation-in-net-to-bypass-hooks/)
- [Syscalls with D/Invoke - Rasta Mouse](https://offensivedefence.co.uk/posts/dinvoke-syscalls/)
- [A tale of EDR bypass methods - s3cur3th1ssh1t](https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/)
- [Dynamic API Invocation](https://ppn.snovvcrash.rocks/red-team/maldev/dinvoke)
- [Calling Syscalls Directly from Visual Studio to Bypass AVs/EDRs - IRedTeam](https://www.ired.team/offensive-security/defense-evasion/using-syscalls-directly-from-visual-studio-to-bypass-avs-edrs)
- [AV/EDR Evasion Using Direct System Calls (User-Mode vs kernel-Mode) - Usman Sikander](https://medium.com/@merasor07/av-edr-evasion-using-direct-system-calls-user-mode-vs-kernel-mode-fad2fdfed01a)
- [Bypassing Antivirus using Direct System Calls -  nag0mez](https://pwnedcoffee.com/blog/red-team-tactics/bypassing-antivirus-using-direct-system-calls/)