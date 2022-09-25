---
title: "Staying Under the Radar - Part 2 - Hiding IAT using Delegates"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2022-09-20
description: "Hiding imports using delegates in C#"
tags: [Red Team]
---
## Introduction
In this post we are going to loo kat another technique we can use in C# that can help us keep our imports hidden and the Import Address Table (IAT) clean. This is done by the use of delegates. This is not a technique you can use in mature environments and expect to get is past AVs/EDRs because they are quite smart. But still its a nice technique to know of and may confuse some defenders.

## Delegates
According to the Microsoft Docs, *A delegate is a type that represents references to methods with a particular parameter list and return type. When you instantiate a delegate, you can associate its instance with any method with a compatible signature and return type. You can invoke (or call) the method through the delegate instance. Delegates are used to pass methods as arguments to other methods. Event handlers are nothing more than methods that are invoked through delegates. You create a custom method, and a class such as a windows control can call your method when a certain event occurs.* 
<br>
We are going to use these delegates to create a reference of our API call with required parameters. And then use `Marshal.GetDelegateForFunctionPointer` to convert an unmanaged function pointer to our delegate.

### Imports
We need two APIs for this to work. `GetModuleHandleA` and `GetProcAddress`. The first one would be used to provide a handle to the DLL which we are getting the export from and then the other is used to specify the API to retreive from the the DLL.
```csharp
[DllImport("kernel32")]
public static extern IntPtr GetModuleHandleA(string lpModuleName);

[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
```

After this we need to create a delegate for our function API call. We can call it whatever we like. The parameters taht we are providing should be similar to the API call. For this POC I'm going to use a simple MessageBox.
```csharp
public delegate int box(IntPtr hWnd, string lpText, string lpCaption, uint uType);
```

### Main Method
With that set up we can use `GetModuleHandleA` and provide the module we are calling our API from. For `MessageBoxA` function. it's going to be `user32.dll`. The exports of this DLL can be parsed and used by `GetProcAddress` after providing it with the handle and the API we need.
```csharp
IntPtr handle = GetModuleHandleA("user32.dll");
IntPtr messageboxaddr = GetProcAddress(handle, "MessageBoxA");
```

Lastly we going to use `Marshal.GetDelegateForFunctionPointer` to convert the funtion pointer `messageboxaddr` to the type of our _box_ delegate.
```csharp
box message =  (box)Marshal.GetDelegateForFunctionPointer(messageboxaddr, typeof(box));
```

Then we can call the API as we normaly would but using the delegate.
```csharp
message(IntPtr.Zero, "hey", "yoooo", 0);
```

## Testing
We can test our code with comparison to a simple message box using the `MessageBoxA` call in PE Studio.
![MessageBoxA](/assets/img/staying-under-the-radar-2/messagebox.png)
We can see the Import being made clearly.
![Delegate](/assets/img/staying-under-the-radar-2/delegate.png)
But with delegates we only see the two API calls of `GetModuleHandleA` and `GetProcAddress`.
