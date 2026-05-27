---
title: "Hunting For Vulnerable Drivers - Part One"
author:
  name: crypt0ace
  link: https://twitter.com/crypt0acee
date: 2026-05-27
description: "Building and Understanding a Windows Kernel Driver"
tags: [Red Team, Vulnerable Drivers]
---

## Introduction

Hello there. This is a multi post thing where I try to explain Windows Drivers shenanigans. How they are built, what makes them insecure, how to hunt for these drivers and how they are exploited. For the first part, we need to understand what these drivers are. What other way to explain and understand it but by building our own driver and testing it in a machine?

### The Setup

For the setup, we are going with my Windows 10 host machine and a Windows 10 VirtualBox VM. We need to do all these funny little things in the VM because playing with fire (kernel mode) can lead to some disasters that we would like to avoid in our actual machine.

To prepare our scenario, we will want the VM to have test signing enabled. Since this driver is being developed for a controlled lab environment, it is not signed through Microsoft’s production driver signing process. Windows x64 enforces kernel mode driver signing by default, so we enable Test Signing Mode to allow our locally test-signed driver to load inside the VM.

```powershell
bcdedit /set testsigning on
```

Once this is done, the VM can be rebooted through GUI or this

```powershell
shutdown /r /t 0
```

I will be using Visual Studio IDE 2026 for the development part. And as per Microsoft, it lists down the components, like Windows Driver Kit, that need to be installed for writing drivers [here](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk). We will also be using WinDBG to debug the Windows VM kernel to see what’s happening under the hood.

To configure the debugging, we need to configure a serial port that we can use to connect WinDBG on our host machine to our VM. This command configures a virtual serial port inside the Windows VM and connects it to a named pipe on our host. 

```powershell
VBoxManage modifyvm "Your VM Name" --uart1 0x3F8 4 --uartmode1 server "\\.\pipe\VulnDr"
```

In our driver lab, we use this so the guest VM can send kernel debugging traffic through COM1, and the host machine can connect to that pipe using WinDBG. Once this is done, we also need to enable debugging and the debug settings to use this COM port.

```powershell
bcdedit /debug on
bcdedit /dbgsettings serial debugport:1 baudrate:115200
```

Then we can reboot the VM again.

Now once the VM is up, we can start WinDBG on our host machine and select `File → Start Debugging → Attach to Kernel` and set

```powershell
Port:       \\.\pipe\VulnDr
Baud rate:  115200
Pipe:       Checked
Reconnect:  Checked
Resets:     0
```

Or in an Administrator command line with

```powershell
windbgx -k com:pipe,port=\\.\pipe\huntdrv,baud=115200,resets=0,reconnect
```

Once its started, inside the WinDBG we can set up windows debugging symbols using `.symfix C:\Symbols` and just to test if its working we can use the GUI and click on the break option to pause the kernel and then `g` to resume. 

![image.png](/assets/img/Hunting-For-Vulnerable-Drivers/01.png)

## Building a Simple Driver

Right, so we have the setup ready. We can now start with a simple boilerplate driver to understand a few key points. Lets start with the initial code:

```c
#include <ntddk.h>

VOID VulnDrUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] DriverUnload called\n"
    );
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] DriverEntry called. DriverObject=%p RegistryPath=%wZ\n",
        DriverObject,
        RegistryPath
    );

    DriverObject->DriverUnload = VulnDrUnload;

    return STATUS_SUCCESS;
}
```

For the start, as we have `main()` functions, in case of a driver its *main* function will be `DriverEntry()` . This is what will be called when we start our driver. And whenever we stop the driver we will be calling `VulnDrUnload()` function. Instead of normal print functions, we see `DbgPrintEx()` being used. However, these are not printed on the terminal. We will be seeing them in WinDBG. 

What this driver does is that it just loads and tells the kernel its loaded and when its stopped it will say its unloaded. Pretty simple. In WinDBG, we need to use this.

```text
ed nt!Kd_IHVDRIVER_Mask 0xffffffff
```

This command turns on verbose kernel debug output for our driver so we can see what the driver is doing while we test `DriverEntry`, unload routines, and later IOCTL handling. Also, in case you are not able to type in WinDBG, use the break and then you can. Once done use `g` so you can use the VM. We can build it and then use the VM to run it like this:

```powershell
sc.exe create VulnDr type= kernel start= demand binPath= C:\DriverLab\VulnDr.sys
sc.exe start VulnDr
```

Once we start, we can see the output that will be shown in the WinDBG contains this

```text
[VulnDr] DriverEntry called. DriverObject=FFFFD98EFA211A80 RegistryPath=\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\VulnDr
```

This tells us that our driver was loaded. Once we stop the service, we will get the `DriverUnload Called` message as well. We can list our driver’s symbols by using this as well to find the entry and unload symbols.

```text
x VulnDr!*
```

![image.png](/assets/img/Hunting-For-Vulnerable-Drivers/02.png)

Perfect. Its working. Now we can move on to making the driver a bit more complex.

## Advancing Further

We modify the code with this

```c
#include <ntddk.h>

#define VULNDR_DEVICE_NAME      L"\\Device\\VulnDr"
#define VULNDR_DOS_DEVICE_NAME  L"\\DosDevices\\VulnDr"

static NTSTATUS VulnDrCompleteRequest(
    _Inout_ PIRP Irp,
    _In_ NTSTATUS Status,
    _In_ ULONG_PTR Information
)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS VulnDrCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] IRP_MJ_CREATE / IRP_MJ_CLOSE received\n"
    );

    return VulnDrCompleteRequest(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS VulnDrUnsupported(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] Unsupported IRP received\n"
    );

    return VulnDrCompleteRequest(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

VOID VulnDrUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING dosDeviceName;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] DriverUnload called\n"
    );

    RtlInitUnicodeString(&dosDeviceName, VULNDR_DOS_DEVICE_NAME);

    IoDeleteSymbolicLink(&dosDeviceName);

    if (DriverObject->DeviceObject != NULL)
    {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] Device and symbolic link deleted\n"
    );
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName;
    UNICODE_STRING dosDeviceName;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] DriverEntry called\n"
    );

    RtlInitUnicodeString(&deviceName, VULNDR_DEVICE_NAME);
    RtlInitUnicodeString(&dosDeviceName, VULNDR_DOS_DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[VulnDr] IoCreateDevice failed: 0x%X\n",
            status
        );

        return status;
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] Device created: %wZ\n",
        &deviceName
    );

    status = IoCreateSymbolicLink(
        &dosDeviceName,
        &deviceName
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[VulnDr] IoCreateSymbolicLink failed: 0x%X\n",
            status
        );

        IoDeleteDevice(deviceObject);
        return status;
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] Symbolic link created: %wZ -> %wZ\n",
        &dosDeviceName,
        &deviceName
    );

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        DriverObject->MajorFunction[i] = VulnDrUnsupported;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = VulnDrCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = VulnDrCreateClose;

    DriverObject->DriverUnload = VulnDrUnload;

    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] Driver loaded successfully\n"
    );

    return STATUS_SUCCESS;
}
```

To explain the change, here is the summarized version

```text
DriverEntry()
    ├── IoCreateDevice()
    ├── IoCreateSymbolicLink()
    ├── Register IRP handlers
    └── Register unload routine

IRP_MJ_CREATE / IRP_MJ_CLOSE handler

Unsupported IRP handler

DriverUnload()
    ├── IoDeleteSymbolicLink()
    └── IoDeleteDevice()
```

Previously, the driver only had load and unload options. This time, we have made it a bit more engaging.

It starts with the device name definitions. It creates a kernel device object named `\Device\VulnDr` and a user-accessible symbolic link named `\DosDevices\VulnDr`, which user mode can open as `\\.\VulnDr`. We will create a client to open this up as a user mode process as well. 

The function `VulnDrCompleteRequest()` is more of a helper function. Drivers receive the requests in form of I/O Request Packets or IRPs. Whenever user mode opens the device, closes it, sends an IOCTL, reads from it, or writes to it, Windows sends an IRP to the driver.  It sets the final NTSTATUS value, optionally reports the number of bytes returned, calls IoCompleteRequest, and returns the same status to the I/O Manager.

The Create/Close function handles two requests

```text
IRP_MJ_CREATE
IRP_MJ_CLOSE
```

These happen when the user mode program opens or closes a handle to the driver. For simplicity, both are handled by the same function. Since we do not need the pointer to the device object, we write as as unreferenced. In the end we use the complete request to mention that the open or close was completed successfully.

The unsupported function calls out if an IRP is not supported by our driver. Windows drivers can support the following Major Functions

```text
IRP_MJ_CREATE
IRP_MJ_CLOSE
IRP_MJ_READ
IRP_MJ_WRITE
IRP_MJ_DEVICE_CONTROL
IRP_MJ_CLEANUP
IRP_MJ_POWER
IRP_MJ_PNP
```

Our driver currently supports the open and close functions. 

The unload function does the same. It unloads the driver. It also cleans up the device name and symlinks that were created.

For the main entry point of this driver,  we start by initializing the variables. We then create a device object for the kernel driver. It also creates a symbolic link so that user mode programs can open the driver. The loop after this basically tells the kernel that any major functions if called should return unsupported. Because, well they’re unsupported. For the open and close functions, we map them to their respective functions. 

Now this will work, sure, but to test out the open and close functions we will need a user mode process to load the driver and call it up. For that we will create a simple program.

```c
#include <windows.h>
#include <stdio.h>

int wmain()
{
    wprintf(L"[+] Opening \\\\.\\VulnDr\n");

    HANDLE hDevice = CreateFileW(
        L"\\\\.\\VulnDr",
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[-] CreateFileW failed. Error: %lu\n", GetLastError());
        return 1;
    }

    wprintf(L"[+] Driver handle opened successfully\n");

    CloseHandle(hDevice);

    wprintf(L"[+] Driver handle closed\n");

    return 0;
}
```

First we run the same commands to create a service and then start it to run our kernel driver.

```powershell
sc.exe delete VulnDr
sc.exe create VulnDr type= kernel start= demand binPath= C:\DriverLab\VulnDr.sys
sc.exe start VulnDr
```

Then we use the user mode program to open and close the handle on the driver and we can see in WinDBG that the debug statements are getting logged and they state that the driver was loaded and opened/closed.

![image.png](/assets/img/Hunting-For-Vulnerable-Drivers/03.png)

## Getting into IOCTLs

This is where it takes up. Now we will introduce IOCTLs. IOCTL means Input/Output Control. In Windows drivers, an IOCTL is a custom command number that user mode programs send to a kernel driver to ask it to do something.

Think of it like this:

> `CreateFile()` opens a handle to the driver.
> 
> 
> `DeviceIoControl()` sends a command to the driver.
> 
> The driver receives that command inside `IRP_MJ_DEVICE_CONTROL`.
> 

### Driver Side

For this one, we are going with 3 simple IOCTLs. Our driver code will have the following changes.

```c
static NTSTATUS VulnDrHandleGetVersion(
    _Inout_ PIRP Irp,
    _In_ ULONG OutputBufferLength
)
{
    PVOID systemBuffer;
    PVULNDR_VERSION_INFO versionInfo;

    systemBuffer = Irp->AssociatedIrp.SystemBuffer;

    if (systemBuffer == NULL)
    {
        return VulnDrCompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    if (OutputBufferLength < sizeof(VULNDR_VERSION_INFO))
    {
        return VulnDrCompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    RtlZeroMemory(systemBuffer, OutputBufferLength);

    versionInfo = (PVULNDR_VERSION_INFO)systemBuffer;

    versionInfo->Major = 1;
    versionInfo->Minor = 0;
    versionInfo->Build = 1;

    RtlStringCchCopyW(
        versionInfo->Message,
        ARRAYSIZE(versionInfo->Message),
        L"Vulnerable Driver"
    );

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] IOCTL_VULNDR_GET_VERSION handled\n"
    );

    return VulnDrCompleteRequest(
        Irp,
        STATUS_SUCCESS,
        sizeof(VULNDR_VERSION_INFO)
    );
}

static NTSTATUS VulnDrHandleEcho(
    _Inout_ PIRP Irp,
    _In_ ULONG InputBufferLength,
    _In_ ULONG OutputBufferLength
)
{
    PVOID systemBuffer;
    PVULNDR_ECHO_REQUEST echoRequest;

    systemBuffer = Irp->AssociatedIrp.SystemBuffer;

    if (systemBuffer == NULL)
    {
        return VulnDrCompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    if (InputBufferLength < sizeof(VULNDR_ECHO_REQUEST))
    {
        return VulnDrCompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    if (OutputBufferLength < sizeof(VULNDR_ECHO_REQUEST))
    {
        return VulnDrCompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    echoRequest = (PVULNDR_ECHO_REQUEST)systemBuffer;

    if (echoRequest->InputLength > sizeof(echoRequest->Input))
    {
        return VulnDrCompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    echoRequest->Input[sizeof(echoRequest->Input) - 1] = '\0';

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] IOCTL_VULNDR_ECHO handled. InputLength=%lu Input=%s\n",
        echoRequest->InputLength,
        echoRequest->Input
    );

    return VulnDrCompleteRequest(
        Irp,
        STATUS_SUCCESS,
        sizeof(VULNDR_ECHO_REQUEST)
    );
}

static NTSTATUS VulnDrHandleGetStats(
    _Inout_ PIRP Irp,
    _In_ ULONG OutputBufferLength
)
{
    PVOID systemBuffer;
    PVULNDR_STATS stats;

    systemBuffer = Irp->AssociatedIrp.SystemBuffer;

    if (systemBuffer == NULL)
    {
        return VulnDrCompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    if (OutputBufferLength < sizeof(VULNDR_STATS))
    {
        return VulnDrCompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    RtlZeroMemory(systemBuffer, OutputBufferLength);

    stats = (PVULNDR_STATS)systemBuffer;

    stats->TotalIoctlsHandled = g_TotalIoctlsHandled;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] IOCTL_VULNDR_GET_STATS handled. Total=%ld\n",
        stats->TotalIoctlsHandled
    );

    return VulnDrCompleteRequest(
        Irp,
        STATUS_SUCCESS,
        sizeof(VULNDR_STATS)
    );
}

static NTSTATUS VulnDrDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack;
    ULONG ioctlCode;
    ULONG inputBufferLength;
    ULONG outputBufferLength;

    stack = IoGetCurrentIrpStackLocation(Irp);

    ioctlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = stack->Parameters.DeviceIoControl.OutputBufferLength;

    InterlockedIncrement(&g_TotalIoctlsHandled);

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] IRP_MJ_DEVICE_CONTROL received. IoctlCode=0x%X InputLength=%lu OutputLength=%lu\n",
        ioctlCode,
        inputBufferLength,
        outputBufferLength
    );

    switch (ioctlCode)
    {
    case IOCTL_VULNDR_GET_VERSION:
        return VulnDrHandleGetVersion(Irp, outputBufferLength);

    case IOCTL_VULNDR_ECHO:
        return VulnDrHandleEcho(Irp, inputBufferLength, outputBufferLength);

    case IOCTL_VULNDR_GET_STATS:
        return VulnDrHandleGetStats(Irp, outputBufferLength);

    default:
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[VulnDr] Unknown IOCTL received: 0x%X\n",
            ioctlCode
        );

        return VulnDrCompleteRequest(
            Irp,
            STATUS_INVALID_DEVICE_REQUEST,
            0
        );
    }
}

// The *main* function
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName;
    UNICODE_STRING dosDeviceName;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] DriverEntry called\n"
    );

    RtlInitUnicodeString(&deviceName, VULNDR_DEVICE_NAME);
    RtlInitUnicodeString(&dosDeviceName, VULNDR_DOS_DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[VulnDr] IoCreateDevice failed: 0x%X\n",
            status
        );

        return status;
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] Device created: %wZ\n",
        &deviceName
    );

    status = IoCreateSymbolicLink(
        &dosDeviceName,
        &deviceName
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[VulnDr] IoCreateSymbolicLink failed: 0x%X\n",
            status
        );

        IoDeleteDevice(deviceObject);
        return status;
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] Symbolic link created: %wZ -> %wZ\n",
        &dosDeviceName,
        &deviceName
    );

    for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
    {
        DriverObject->MajorFunction[i] = VulnDrUnsupported;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = VulnDrCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = VulnDrCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = VulnDrDeviceControl;

    DriverObject->DriverUnload = VulnDrUnload;

    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] Driver loaded successfully\n"
    );

    return STATUS_SUCCESS;
}
```

We have the following:

| IOCTL | Purpose |
| --- | --- |
| `IOCTL_VULNDR_GET_VERSION` | Returns driver version info |
| `IOCTL_VULNDR_ECHO` | Echoes user input back after size checks |
| `IOCTL_VULNDR_GET_STATS` | Returns how many IOCTLs were handled |

In this code, the `VulnDrDeviceControl` is the important bit. It acts as a handler that receives the user mode calls and routes them to respective IOCTLs. We already explicitly allow the 3 operation (major functions) in the `DriverEntry` function. The open, close and device control.

The device control, uses the following line to get the current IRP (I/O Request Packet) stack location.

```text
stack = IoGetCurrentIrpStackLocation(Irp);
```

This contains information about the request. We extract the important values here which come from the user mode program.

```text
ioctlCode = stack->Parameters.DeviceIoControl.IoControlCode;
inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
outputBufferLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
```

Then in the switch case, comes the actual routing. Based on the IOCTL code, it routes to the relevant function and rejects if unsupported. 

One other line to note in all the three handlers is this

```text
systemBuffer = Irp->AssociatedIrp.SystemBuffer;
```

This is a typical implementation of `METHOD_BUFFERED` (this will make sense in the `piblic.h` header file). In `METHOD_BUFFERED`, the I/O Manager allocates a kernel buffer, copies user input into it, gives the driver access through `Irp->AssociatedIrp.SystemBuffer`, and after the driver completes the IRP, copies the output bytes back to the caller. So the flow becomes

```text
User buffer
-> copied to kernel SystemBuffer
-> driver reads/writes SystemBuffer
-> copied back to user output buffer
```

Other methods and their basic implementation are follows

| Method | Driver receives input through | Driver returns output through | Implementation | Risk level |
| --- | --- | --- | --- | --- |
| `METHOD_BUFFERED` | `Irp->AssociatedIrp.SystemBuffer` | Same `SystemBuffer` | Easiest | Low if sizes are checked |
| `METHOD_IN_DIRECT` | `SystemBuffer` + MDL | MDL buffer | Medium | Medium |
| `METHOD_OUT_DIRECT` | `SystemBuffer` + MDL | MDL buffer | Medium | Medium |
| `METHOD_NEITHER` | Raw user pointer | Raw user pointer | Hardest | Highest |

So in short, windows IOCTLs support different transfer methods that decide how input and output buffers are passed between user mode and kernel mode. In this driver, the IOCTLs use `METHOD_BUFFERED`, which means the Windows I/O Manager creates a kernel-side buffer and exposes it to the driver through `Irp->AssociatedIrp.SystemBuffer`. User input is copied into this buffer before the driver is called, and when the driver completes the IRP, the number of bytes specified in `Irp->IoStatus.Information` is copied back to the user-mode output buffer. This makes `METHOD_BUFFERED` simple and safe for small structures such as version information, echo requests, and stats. Other methods include `METHOD_IN_DIRECT` and `METHOD_OUT_DIRECT`, where the second buffer is represented by an MDL for larger transfers, and `METHOD_NEITHER`, where raw user-mode pointers are passed directly to the driver. `METHOD_NEITHER` is flexible but dangerous because the driver becomes responsible for validating, probing, and safely accessing user-controlled pointers.
For this to work, we will also include a `public.h` header file.

```c
#pragma once

#include <ntddk.h>

#define VULNDR_DEVICE_NAME      L"\\Device\\VulnDr"
#define VULNDR_DOS_DEVICE_NAME  L"\\DosDevices\\VulnDr"
#define VULNDR_WIN32_NAME       L"\\\\.\\VulnDr"

#define IOCTL_VULNDR_GET_VERSION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA)

#define IOCTL_VULNDR_ECHO \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_VULNDR_GET_STATS \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

typedef struct _VULNDR_VERSION_INFO
{
    unsigned long Major;
    unsigned long Minor;
    unsigned long Build;
    wchar_t Message[128];
} VULNDR_VERSION_INFO, * PVULNDR_VERSION_INFO;

typedef struct _VULNDR_ECHO_REQUEST
{
    unsigned long InputLength;
    char Input[128];
} VULNDR_ECHO_REQUEST, * PVULNDR_ECHO_REQUEST;

typedef struct _VULNDR_STATS
{
    long TotalIoctlsHandled;
} VULNDR_STATS, * PVULNDR_STATS;
```

As before, we define the driver device name, object and symbolic link first. The we define the command a user mode program can use to send to driver using `DeviceIoControl`. This macro’s format is like this

```c
CTL_CODE(DeviceType, Function, Method, Access)
```

Here, the only thing that needs to be talked about are the function codes. We are self defining these codes to map out with our respective calls. These are chosen by us. The function code inside the `CTL_CODE` macro is a custom command number chosen by the driver developer. It does not directly refer to a C function. Instead, it becomes one field inside the final 32-bit IOCTL value. For custom drivers, function codes commonly start at `0x800`, because lower values are reserved for Microsoft-defined IOCTLs. In this driver, I assigned `0x800` to `GET_VERSION`, `0x801` to `ECHO`, and `0x802` to `GET_STATS`. When user mode calls `DeviceIoControl`, Windows passes the full encoded IOCTL value to the driver. The driver then compares that value in `VulnDrDeviceControl` and manually routes it to the correct handler function. So the function code is simply the numeric ID for a driver command, while the actual C function that handles it is chosen by our `switch` statement.

Below these, we are defining the structures that will hold the information that the driver returns. In short, the `public.h` header acts as the contract between the user-mode client and the kernel driver. It defines the device names used to create and open the driver, the IOCTL codes that represent supported commands, and the structures used to exchange data. The driver creates the real kernel device as `\Device\VulnDr`, exposes it through the symbolic link `\DosDevices\VulnDr`, and the user-mode client opens it using `\\.\VulnDr`. Each IOCTL is created using the `CTL_CODE` macro, which combines the device type, function number, transfer method, and required access rights into a single command value. In this driver, all IOCTLs use `METHOD_BUFFERED`, so the driver receives input and writes output through `Irp->AssociatedIrp.SystemBuffer`. The shared structures, such as `VULNDR_VERSION_INFO`, `VULNDR_ECHO_REQUEST`, and `VULNDR_STATS`, ensure that both user mode and kernel mode interpret the exchanged data in exactly the same way.

### Client Side

For the client, we need to make some changes to call the IOCTLs from user mode for our driver to process. We will be including the same `public.h` header in the program. The code will change to this.

```c
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <string.h>

#include "public.h"

static void PrintLastError(const wchar_t* Message)
{
    wprintf(L"[-] %ls failed. GetLastError()=%lu\n", Message, GetLastError());
}

int wmain()
{
    wprintf(L"[+] Opening %ls\n", VULNDR_WIN32_NAME);

    HANDLE hDevice = CreateFileW(
        VULNDR_WIN32_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        PrintLastError(L"CreateFileW");
        return 1;
    }

    wprintf(L"[+] Driver handle opened successfully\n");

    DWORD bytesReturned = 0;

    VULNDR_VERSION_INFO versionInfo = { 0 };

    BOOL ok = DeviceIoControl(
        hDevice,
        IOCTL_VULNDR_GET_VERSION,
        nullptr,
        0,
        &versionInfo,
        sizeof(versionInfo),
        &bytesReturned,
        nullptr
    );

    if (!ok)
    {
        PrintLastError(L"DeviceIoControl(IOCTL_VULNDR_GET_VERSION)");
    }
    else
    {
        wprintf(L"\n[+] IOCTL_VULNDR_GET_VERSION succeeded\n");
        wprintf(L"    Version: %lu.%lu.%lu\n", versionInfo.Major, versionInfo.Minor, versionInfo.Build);
        wprintf(L"    Message: %ls\n", versionInfo.Message);
        wprintf(L"    Bytes returned: %lu\n", bytesReturned);
    }

    VULNDR_ECHO_REQUEST echoRequest = { 0 };

    const char* message = "Hello, World!";

    echoRequest.InputLength = (unsigned long)strlen(message);

    strcpy_s(
        echoRequest.Input,
        sizeof(echoRequest.Input),
        message
    );

    bytesReturned = 0;

    ok = DeviceIoControl(
        hDevice,
        IOCTL_VULNDR_ECHO,
        &echoRequest,
        sizeof(echoRequest),
        &echoRequest,
        sizeof(echoRequest),
        &bytesReturned,
        nullptr
    );

    if (!ok)
    {
        PrintLastError(L"DeviceIoControl(IOCTL_VULNDR_ECHO)");
    }
    else
    {
        wprintf(L"\n[+] IOCTL_VULNDR_ECHO succeeded\n");
        printf("    Echo: %s\n", echoRequest.Input);
        wprintf(L"    InputLength: %lu\n", echoRequest.InputLength);
        wprintf(L"    Bytes returned: %lu\n", bytesReturned);
    }

    VULNDR_STATS stats = { 0 };
    bytesReturned = 0;

    ok = DeviceIoControl(
        hDevice,
        IOCTL_VULNDR_GET_STATS,
        nullptr,
        0,
        &stats,
        sizeof(stats),
        &bytesReturned,
        nullptr
    );

    if (!ok)
    {
        PrintLastError(L"DeviceIoControl(IOCTL_VULNDR_GET_STATS)");
    }
    else
    {
        wprintf(L"\n[+] IOCTL_VULNDR_GET_STATS succeeded\n");
        wprintf(L"    Total IOCTLs handled: %ld\n", stats.TotalIoctlsHandled);
        wprintf(L"    Bytes returned: %lu\n", bytesReturned);
    }

    CloseHandle(hDevice);

    wprintf(L"\n[+] Driver handle closed\n");

    return 0;
}
```

First, it opens the driver with `CreateFileW("\\\\.\\VulnDr", GENERIC_READ | GENERIC_WRITE, ...)`, which causes the driver to receive an `IRP_MJ_CREATE` request. Once the handle is open, the client sends commands using `DeviceIoControl`. Each call passes an IOCTL code, optional input buffer, optional output buffer, and receives a `bytesReturned` value. For `IOCTL_VULNDR_GET_VERSION`, the client sends no input and receives a `VULNDR_VERSION_INFO` structure. For `IOCTL_VULNDR_ECHO`, it sends a `VULNDR_ECHO_REQUEST` structure and receives the same structure back. For `IOCTL_VULNDR_GET_STATS`, it receives a `VULNDR_STATS` structure containing the number of IOCTLs handled by the driver. Finally, the program calls `CloseHandle`, which closes the device handle and causes the driver to receive an `IRP_MJ_CLOSE` request.
Pretty simple. We can build the driver and the user mode program, run it and then inspect the debugging output in WinDBG.

> I have been getting some kernel networking etc. noise in my WinDBG for which I ran these 2 to only see the debugging message from my driver: `ed nt!Kd_NDIS_Mask 0` and `ed nt!Kd_IHVDRIVER_Mask 0x1`
> 

![image.png](/assets/img/Hunting-For-Vulnerable-Drivers/04.png)

Everything is getting logged as expected. And the user mode program calls and returns everything as expected as well.

![image.png](/assets/img/Hunting-For-Vulnerable-Drivers/05.png)

We can further debug this using WinDBG as well. We can list loaded modules and then examine all the symbols loaded in our driver using these 2 commands in WinDBG.

```text
lm m VulnDr
x VulnDr!*
```

![image.png](/assets/img/Hunting-For-Vulnerable-Drivers/06.png)

All our IOCTL calls are present here. We can set up a breakpoint in the execution at the point where `DeviceIoControl` is called using this

```text
bp VulnDr!VulnDrDeviceControl
```

Then resuming the machine and invoking the client, we will hit that breakpoint. We can nicely see the execution being paused in WinDBG.

![image.png](/assets/img/Hunting-For-Vulnerable-Drivers/07.png)

Here, the first 2 arguments usually will be

```text
rcx = DeviceObject
rdx = Irp
```

So we can inspect these registers using the command

```text
r rcx
r rdx
```

We get the raw values

```text
1: kd> r rcx
rcx=ffffb58878d92a70
1: kd> r rdx
rdx=ffffb588785fcd70
```

We can inspect the IRP using this. It mentions `no MDL` which means we are using `METHOD_BUFFERED` and that the IRP is for DEVICE_CONTROL. The last part with the arguments show that the IoControlCode that was called is `0x226000` .

```text
1: kd> !irp @rdx
Irp is active with 1 stacks 1 is current (= 0xffffb588785fce40)
 No Mdl: System buffer=ffffb58872568ec0: Thread ffffb58878a37080:  Irp stack trace.  
     cmd  flg cl Device   File     Completion-Context
>[IRP_MJ_DEVICE_CONTROL(e), N/A(0)]
            5  0 ffffb58878d92a70 ffffb588906bb960 00000000-00000000    
       \Driver\VulnDr
            Args: 0000010c 00000000 0x226000 00000000
```

And the raw structure can be seen using this

```text
dt nt!_IRP @rdx
```

Which returns the follwoing. 

```text
1: kd> dt nt!_IRP @rdx
   +0x000 Type             : 0n6
   +0x002 Size             : 0x118
   +0x004 AllocationProcessorNumber : 1
   +0x006 Reserved         : 0
   +0x008 MdlAddress       : (null) 
   +0x010 Flags            : 0x60070
   +0x018 AssociatedIrp    : <anonymous-tag>
   +0x020 ThreadListEntry  : _LIST_ENTRY [ 0xffffb588`78a37530 - 0xffffb588`78a37530 ]
   +0x030 IoStatus         : _IO_STATUS_BLOCK
   +0x040 RequestorMode    : 1 ''
   +0x041 PendingReturned  : 0 ''
   +0x042 StackCount       : 1 ''
   +0x043 CurrentLocation  : 1 ''
   +0x044 Cancel           : 0 ''
   +0x045 CancelIrql       : 0 ''
   +0x046 ApcEnvironment   : 0 ''
   +0x047 AllocationFlags  : 0x6 ''
   +0x048 UserIosb         : 0x0000001d`abfef8c0 _IO_STATUS_BLOCK
   +0x050 UserEvent        : (null) 
   +0x058 Overlay          : <anonymous-tag>
   +0x068 CancelRoutine    : (null) 
   +0x070 UserBuffer       : 0x0000001d`abfef9c0 Void
   +0x078 Tail             : <anonymous-tag>
```

In simple, a user-mode program called `DeviceIoControl()` against our `\Driver\VulnDr` device. It sent no input buffer, provided a 268-byte output buffer, and used IOCTL code `0x226000`. Windows created a buffered IOCTL IRP, gave our driver a kernel system buffer at `ffffb58872568ec0`, and your driver is now expected to process the request, write output to that system buffer, set `IoStatus`, and complete the IRP.

The IOCTL code `0x226000` can be decoded like this

```text
Bits 31-16 = DeviceType
Bits 15-14 = Access
Bits 13-2  = Function
Bits 1-0   = Method
```

So in our case it becomes

```text
DeviceType = 0x22
Access     = 0x1
Function   = 0x800
Method     = 0x0
```

Or better yet

```text
DeviceType = FILE_DEVICE_UNKNOWN
Access     = FILE_READ_ACCESS
Function   = 0x800
Method     = METHOD_BUFFERED
```

Which matches our `IOCTL_VULNDR_GET_VERSION` that we have defined. We will come across these when we are finding our vulnerabilities because these IOCTL codes gives answers to questions like

```text
What device type is this?
What function number is being called?
Is it METHOD_BUFFERED, METHOD_NEITHER, or direct I/O?
Does it require read/write access?
```

The dangerous ones are

```text
METHOD_NEITHER
FILE_ANY_ACCESS
```

As this is an important point, we can dive a little deeper into it. In our driver code, above the function `VulnDrDeviceControl` we can add this code

```c
static const char* VulnDrMethodToString(
    _In_ ULONG Method
)
{
    switch (Method)
    {
    case METHOD_BUFFERED:
        return "METHOD_BUFFERED";

    case METHOD_IN_DIRECT:
        return "METHOD_IN_DIRECT";

    case METHOD_OUT_DIRECT:
        return "METHOD_OUT_DIRECT";

    case METHOD_NEITHER:
        return "METHOD_NEITHER";

    default:
        return "UNKNOWN_METHOD";
    }
}

static const char* VulnDrAccessToString(
    _In_ ULONG Access
)
{
    switch (Access)
    {
    case FILE_ANY_ACCESS:
        return "FILE_ANY_ACCESS";

    case FILE_READ_ACCESS:
        return "FILE_READ_ACCESS";

    case FILE_WRITE_ACCESS:
        return "FILE_WRITE_ACCESS";

    case FILE_READ_ACCESS | FILE_WRITE_ACCESS:
        return "FILE_READ_ACCESS | FILE_WRITE_ACCESS";

    default:
        return "UNKNOWN_ACCESS";
    }
}

static VOID VulnDrLogIoctlDetails(
    _In_ ULONG IoctlCode
)
{
    ULONG deviceType;
    ULONG access;
    ULONG function;
    ULONG method;

    deviceType = (IoctlCode >> 16) & 0xFFFF;
    access = (IoctlCode >> 14) & 0x3;
    function = (IoctlCode >> 2) & 0xFFF;
    method = IoctlCode & 0x3;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] IOCTL decode: Code=0x%X DeviceType=0x%X Function=0x%X Method=%s Access=%s\n",
        IoctlCode,
        deviceType,
        function,
        VulnDrMethodToString(method),
        VulnDrAccessToString(access)
    );
}
```

And we can add this line in the function after our debug statement

```c
VulnDrLogIoctlDetails(ioctlCode);
```

This code will basically print out the same details in WinDBG as debug output for us to understand the IOCTL calls and how they are decoded into values that we can understand.

![image.png](/assets/img/Hunting-For-Vulnerable-Drivers/08.png)

This time, we get the IOCTL code printed and its also decoded to show the parameters that are being used by each IOCTL call.

## Using IOCTLs for Safe Read/Write Basics

For the purpose of learning, we will make a dangerous looking IOCTL. This will have a read/write access but to make it safe for lab work, we will be doing this to a private fake buffer. The goal is to see how vulnerable drivers often expose read/write primitives, without touching real kernel memory yet. We can add the following two lines to specify the buffer size to be 256 bytes and the IOCTL to only read/write 64 bytes at a time. Just so the operation isnt huge.

```c
#define VULNDR_FAKE_REGION_SIZE          256
#define VULNDR_FAKE_REGION_MAX_TRANSFER  64
```

We will also add 2 new IOCTL codes in the same header file. One for read and one for write.

```c
#define IOCTL_VULNDR_SAFE_READ_FAKE_REGION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_VULNDR_SAFE_WRITE_FAKE_REGION \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
```

We will also define a shared structure between user mode and kernel just like before

```c
typedef struct _VULNDR_FAKE_RW_REQUEST
{
    unsigned long Offset;
    unsigned long Size;
    unsigned char Data[VULNDR_FAKE_REGION_MAX_TRANSFER];
} VULNDR_FAKE_RW_REQUEST, * PVULNDR_FAKE_RW_REQUEST;
```

Okay so now at the driver code end. We start by specifying a kernel region first. This buffer lives in the driver’s memory, but it is not sensitive kernel memory. It is just a fake region created for learning. 

```c
static unsigned char g_FakeKernelRegion[VULNDR_FAKE_REGION_SIZE] =
"VulnDr fake internal kernel buffer. This is not real kernel memory.";
```

These are the code changes that we will be making in our driver.

```c
static BOOLEAN VulnDrValidateFakeRegionRequest(
    _In_ PVULNDR_FAKE_RW_REQUEST Request
)
{
    if (Request->Size == 0)
    {
        return FALSE;
    }

    if (Request->Size > VULNDR_FAKE_REGION_MAX_TRANSFER)
    {
        return FALSE;
    }

    if (Request->Offset >= VULNDR_FAKE_REGION_SIZE)
    {
        return FALSE;
    }

    if (Request->Size > (VULNDR_FAKE_REGION_SIZE - Request->Offset))
    {
        return FALSE;
    }

    return TRUE;
}

static NTSTATUS VulnDrHandleSafeReadFakeRegion(
    _Inout_ PIRP Irp,
    _In_ ULONG InputBufferLength,
    _In_ ULONG OutputBufferLength
)
{
    PVOID systemBuffer;
    PVULNDR_FAKE_RW_REQUEST request;

    systemBuffer = Irp->AssociatedIrp.SystemBuffer;

    if (systemBuffer == NULL)
    {
        return VulnDrCompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    if (InputBufferLength < sizeof(VULNDR_FAKE_RW_REQUEST) ||
        OutputBufferLength < sizeof(VULNDR_FAKE_RW_REQUEST))
    {
        return VulnDrCompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    request = (PVULNDR_FAKE_RW_REQUEST)systemBuffer;

    if (!VulnDrValidateFakeRegionRequest(request))
    {
        return VulnDrCompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    RtlCopyMemory(
        request->Data,
        &g_FakeKernelRegion[request->Offset],
        request->Size
    );

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] SAFE_READ_FAKE_REGION Offset=0x%X Size=%lu\n",
        request->Offset,
        request->Size
    );

    return VulnDrCompleteRequest(
        Irp,
        STATUS_SUCCESS,
        sizeof(VULNDR_FAKE_RW_REQUEST)
    );
}

static NTSTATUS VulnDrHandleSafeWriteFakeRegion(
    _Inout_ PIRP Irp,
    _In_ ULONG InputBufferLength,
    _In_ ULONG OutputBufferLength
)
{
    PVOID systemBuffer;
    PVULNDR_FAKE_RW_REQUEST request;

    systemBuffer = Irp->AssociatedIrp.SystemBuffer;

    if (systemBuffer == NULL)
    {
        return VulnDrCompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    if (InputBufferLength < sizeof(VULNDR_FAKE_RW_REQUEST) ||
        OutputBufferLength < sizeof(VULNDR_FAKE_RW_REQUEST))
    {
        return VulnDrCompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    request = (PVULNDR_FAKE_RW_REQUEST)systemBuffer;

    if (!VulnDrValidateFakeRegionRequest(request))
    {
        return VulnDrCompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    RtlCopyMemory(
        &g_FakeKernelRegion[request->Offset],
        request->Data,
        request->Size
    );

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] SAFE_WRITE_FAKE_REGION Offset=0x%X Size=%lu\n",
        request->Offset,
        request->Size
    );

    return VulnDrCompleteRequest(
        Irp,
        STATUS_SUCCESS,
        sizeof(VULNDR_FAKE_RW_REQUEST)
    );
}
```

First, in the `VulnDrValidateFakeRegionRequest` function, we safely check the users request with multiple validators. In the `VulnDrHandleSafeReadFakeRegion` function, we can actually copy the data from kernel region to user mode.

```text
FROM (&g_FakeKernelRegion[request->Offset]) -> TO (request->Data)
```

The function `VulnDrHandleSafeWriteFakeRegion` does the same but it writes instead of reads. And the flow becomes like this.

```text
FROM (request->Data) -> TO (&g_FakeKernelRegion[request->Offset])
```

We will also add the case switch in the DeviceIoControl so these can be mapped to their respective functions and IOCTLs.

```c
case IOCTL_VULNDR_SAFE_READ_FAKE_REGION:
    return VulnDrHandleSafeReadFakeRegion(
        Irp,
        inputBufferLength,
        outputBufferLength
    );

case IOCTL_VULNDR_SAFE_WRITE_FAKE_REGION:
    return VulnDrHandleSafeWriteFakeRegion(
        Irp,
        inputBufferLength,
        outputBufferLength
    );
```

To test this scenario, we will be using the same client but add in the functions for testing teh read and write operations.

```c
static void TestFakeRegionReadWrite(HANDLE hDevice)
{
    BOOL ok;
    DWORD bytesReturned;
    VULNDR_FAKE_RW_REQUEST request;

    ZeroMemory(&request, sizeof(request));

    // Read first 48 bytes from fake kernel region
    request.Offset = 0;
    request.Size = 48;

    ok = DeviceIoControl(
        hDevice,
        IOCTL_VULNDR_SAFE_READ_FAKE_REGION,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        &bytesReturned,
        NULL
    );

    if (!ok)
    {
        printf("[!] SAFE_READ_FAKE_REGION failed. GetLastError=%lu\n", GetLastError());
    }
    else
    {
        printf("[+] SAFE_READ_FAKE_REGION succeeded. BytesReturned=%lu\n", bytesReturned);
        printf("[+] Data: ");
        PrintBytesAsText(request.Data, request.Size);
    }

    //Write controlled data into fake kernel region
    ZeroMemory(&request, sizeof(request));

    request.Offset = 0x20;
    request.Size = (ULONG)strlen("HELLO_FROM_USERMODE");

    memcpy(
        request.Data,
        "HELLO_FROM_USERMODE",
        request.Size
    );

    ok = DeviceIoControl(
        hDevice,
        IOCTL_VULNDR_SAFE_WRITE_FAKE_REGION,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        &bytesReturned,
        NULL
    );

    if (!ok)
    {
        printf("[!] SAFE_WRITE_FAKE_REGION failed. GetLastError=%lu\n", GetLastError());
    }
    else
    {
        printf("[+] SAFE_WRITE_FAKE_REGION succeeded. BytesReturned=%lu\n", bytesReturned);
    }

    // Read back from same offset to confirm write worked
    ZeroMemory(&request, sizeof(request));

    request.Offset = 0x20;
    request.Size = 32;

    ok = DeviceIoControl(
        hDevice,
        IOCTL_VULNDR_SAFE_READ_FAKE_REGION,
        &request,
        sizeof(request),
        &request,
        sizeof(request),
        &bytesReturned,
        NULL
    );

    if (!ok)
    {
        printf("[!] SAFE_READ_FAKE_REGION read-back failed. GetLastError=%lu\n", GetLastError());
    }
    else
    {
        printf("[+] SAFE_READ_FAKE_REGION read-back succeeded. BytesReturned=%lu\n", bytesReturned);
        printf("[+] Data: ");
        PrintBytesAsText(request.Data, request.Size);
    }
}
```

This essentially does 3 things. Reads the 48 bytes from kernel memory, writes a string into the kernel memory from user mode and then reads the same string to confirm it wrote successfully. We can see the debug output to check it works as we expect.

![image.png](/assets/img/Hunting-For-Vulnerable-Drivers/09.png)

The point of this is to explain how normally drivers have the read/write primitive workings. It just puts the pieces together and conceptually shows what you will see in the real world. At this stage, the driver exposes two safe fake read/write IOCTLs. These IOCTLs do not access arbitrary kernel memory. Instead, they operate only on a fixed 256-byte internal buffer called `g_FakeKernelRegion`. The user-mode client sends an offset, size, and data buffer to the driver. The driver validates the offset and size, then performs a controlled `RtlCopyMemory`. This demonstrates the basic shape of a driver read/write primitive while keeping the operation safe. The important lesson is that this pattern becomes dangerous only when the driver allows unchecked offsets, oversized copies, raw user pointers, or arbitrary kernel addresses.

We now understand the safe version of a driver-controlled memory copy. Next, we can intentionally break the safety rules and observe how the same pattern turns into a vulnerability.

## Making it Intentionally Vulnerable

Now we can introduce in a simple stack overflow bug within the logic of our driver. We add the following structure and IOCTL code in our `public.h`

```c
#define VULNDR_VULN_DATA_SIZE 512

#define IOCTL_VULNDR_VULN_STACK_OVERFLOW \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _VULNDR_VULN_STACK_REQUEST
{
    unsigned long Size;
    unsigned char Data[VULNDR_VULN_DATA_SIZE];
} VULNDR_VULN_STACK_REQUEST, * PVULNDR_VULN_STACK_REQUEST;
```

This is just setting up the following red flags.

```c
FILE_ANY_ACCESS
User-controlled Size
Fixed-size kernel stack buffer
No upper-bound check against destination buffer
```

This will be our vulnerable handle in the driver code.

```c
__declspec(noinline)
static VOID VulnDrUnsafeStackCopy(
    _In_ PVULNDR_VULN_STACK_REQUEST Request
)
{
    volatile unsigned char kernelStackBuffer[32];

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] Vulnerable copy starting. DestinationSize=32 UserSize=%lu\n",
        Request->Size
    );

    // This trusts Request->Size and copies into a fixed 32-byte stack buffer
    RtlCopyMemory(
        (PVOID)kernelStackBuffer,
        Request->Data,
        Request->Size
    );

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] Vulnerable copy completed\n"
    );
}

static NTSTATUS VulnDrHandleVulnStackOverflow(
    _Inout_ PIRP Irp,
    _In_ ULONG InputBufferLength
)
{
    PVOID systemBuffer;
    PVULNDR_VULN_STACK_REQUEST request;

    systemBuffer = Irp->AssociatedIrp.SystemBuffer;

    if (systemBuffer == NULL)
    {
        return VulnDrCompleteRequest(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    if (InputBufferLength < sizeof(VULNDR_VULN_STACK_REQUEST))
    {
        return VulnDrCompleteRequest(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }

    request = (PVULNDR_VULN_STACK_REQUEST)systemBuffer;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "[VulnDr] IOCTL_VULNDR_VULN_STACK_OVERFLOW received. Size=%lu\n",
        request->Size
    );

    VulnDrUnsafeStackCopy(request);

    return VulnDrCompleteRequest(Irp, STATUS_SUCCESS, 0);
}
```

We’re defining the stack buffer here.

```c
volatile unsigned char kernelStackBuffer[32];
```

When the user mode sends data more than 32 bytes in this buffer, it will result in a crash in case of a stack overflow. The copy happens here.

```c
RtlCopyMemory(
    (PVOID)kernelStackBuffer,
    Request->Data,
    Request->Size
);
```

The data from `Request->Data` is sent to the buffer without any validations. We can exploit is using this code.

```c
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <string.h>

#include "public.h"

int wmain()
{
    wprintf(L"[+] Opening %ls\n", VULNDR_WIN32_NAME);

    HANDLE hDevice = CreateFileW(
        VULNDR_WIN32_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[-] CreateFileW failed. Error=%lu\n", GetLastError());
        return 1;
    }

    VULNDR_VULN_STACK_REQUEST request = { 0 };

    request.Size = 256;

    memset(
        request.Data,
        'A',
        sizeof(request.Data)
    );

    DWORD bytesReturned = 0;

    wprintf(L"[+] Sending vulnerable IOCTL\n");
    wprintf(L"[+] Request.Size = %lu\n", request.Size);
    wprintf(L"[+] Destination kernel stack buffer is only 32 bytes\n");

    BOOL ok = DeviceIoControl(
        hDevice,
        IOCTL_VULNDR_VULN_STACK_OVERFLOW,
        &request,
        sizeof(request),
        nullptr,
        0,
        &bytesReturned,
        nullptr
    );

    if (!ok)
    {
        wprintf(L"[-] DeviceIoControl failed. Error=%lu\n", GetLastError());
    }
    else
    {
        wprintf(L"[+] DeviceIoControl returned successfully\n");
    }

    CloseHandle(hDevice);

    return 0;
}
```

We are basically just making a request with 256 bytes of `A` and then sending it to the driver by opening a handle to it. We will also set a breakpoint in WinDBG at `VulnDr!VulnDrHandleVulnStackOverflow` We use the following when our breakpoint hits.

```text
1: kd> k
 # Child-SP          RetAddr               Call Site
00 ffffeb8e`977aa8d8 fffff804`0c101656     VulnDr!VulnDrHandleVulnStackOverflow [G:\Visual Studio Codes\VulnDr\VulndDr.c @ 426] 
01 ffffeb8e`977aa8e0 fffff804`0f252f55     VulnDr!VulnDrDeviceControl+0x146 [G:\Visual Studio Codes\VulnDr\VulndDr.c @ 513] 
02 ffffeb8e`977aa940 fffff804`0f5fd928     nt!IofCallDriver+0x55
03 ffffeb8e`977aa980 fffff804`0f5fd1f5     nt!IopSynchronousServiceTail+0x1a8
04 ffffeb8e`977aaa20 fffff804`0f5fcbf6     nt!IopXxxControlFile+0x5e5
05 ffffeb8e`977aab60 fffff804`0f4077b5     nt!NtDeviceIoControlFile+0x56
06 ffffeb8e`977aabd0 00007ffe`b6fcce04     nt!KiSystemServiceCopyEnd+0x25
07 00000081`e4cff448 00007ffe`b46fac3b     ntdll!NtDeviceIoControlFile+0x14
08 00000081`e4cff450 00000000`00000000     0x00007ffe`b46fac3b
1: kd> r
rax=0000000000222080 rbx=ffffa185172a8770 rcx=ffffa185172a8770
rdx=0000000000000204 rsi=0000000000000001 rdi=ffffa1851ed1d5d0
rip=fffff8040c101b70 rsp=ffffeb8e977aa8d8 rbp=0000000000000002
 r8=000000000000004d  r9=0000000000000000 r10=0000000000000000
r11=0000000000000010 r12=0000000000000000 r13=0000000000000000
r14=ffffa1851ed1d5d0 r15=ffffa1851cbb5b70
iopl=0         nv up ei pl zr na pe nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00000246
VulnDr!VulnDrHandleVulnStackOverflow:
fffff804`0c101b70 89542410        mov     dword ptr [rsp+10h],edx ss:0018:ffffeb8e`977aa8e8=00000000
```

We can see that the execution is currently in this function in the current call stack (`k`)

> VulnDr!VulnDrHandleVulnStackOverflow

And it came through

> VulnDr!VulnDrDeviceControl+0x146

The complete flow from the stack can be explained like this from bottom to top

```text
User-mode client
    ↓
DeviceIoControl()
    ↓
ntdll!NtDeviceIoControlFile
    ↓
kernel syscall
    ↓
nt!NtDeviceIoControlFile
    ↓
Windows I/O manager
    ↓
nt!IofCallDriver
    ↓
VulnDr!VulnDrDeviceControl
    ↓
VulnDr!VulnDrHandleVulnStackOverflow
```

The `RIP` instruction in the command shows our current instruction pointer. The `RSP` matches the stack frame of our code from the stack frame as well. `RAX` contains our IOCTL code. 

The line here

```text
VulnDr!VulnDrHandleVulnStackOverflow:
fffff804`0c101b70 89542410        mov     dword ptr [rsp+10h],edx ss:0018:ffffeb8e`977aa8e8=00000000
```

Shows the current execution assembly code. Its putting the value in `RDX` which is `0x204` , into `RSP` + 0x10. The following aslo shows that currently the `RSP` is zero’ed out. 

![image.png](/assets/img/Hunting-For-Vulnerable-Drivers/10.png)

Oh and because we have the code on the same machine we can easily see the pseudo code on the side nicely. We can set breakpoints using that as well. We set another breakpoint at `VulnDr!VulnDrUnsafeStackCopy` and continue the execution. The first function argument passed should be in `RCX` so we do `dd @rcx L4`

```text
0: kd> dd @rcx L4
ffffa185`1e0aa780  00000100 41414141 41414141 41414141
```

As we can see, the request is filled with our `A` ’s or in hex `0x41` . We can see the local variables with zeros in our stack buffer using this.

```text
0: kd> dv /v
ffffeb8e`977aa908           Request = 0x00000000`00000000
ffffeb8e`977aa8b8 kernelStackBuffer = unsigned char [32] ""
```

If we keep using `p` to step over lines, we can eventually reach the vulnerable copy section. And checking the request now we get this

```text
0: kd> dv /v
ffffeb8e`977aa8a0           Request = 0xffffa185`1e0aa780
ffffeb8e`977aa850 kernelStackBuffer = unsigned char [32] "???"
0: kd> db 0xffffa185`1e0aa780 L80
ffffa185`1e0aa780  00 01 00 00 41 41 41 41-41 41 41 41 41 41 41 41  ....AAAAAAAAAAAA
ffffa185`1e0aa790  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffa185`1e0aa7a0  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffa185`1e0aa7b0  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffa185`1e0aa7c0  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffa185`1e0aa7d0  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffa185`1e0aa7e0  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffa185`1e0aa7f0  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
```

We can again use `p` and then check the `kernelStackBuffer` to see all our nice `A` ’s in the buffer.

```text
0: kd> dv /v
ffffeb8e`977aa8a0           Request = 0x41414141`41414141
ffffeb8e`977aa850 kernelStackBuffer = unsigned char [32] "AAAAAAAAAAAA......"
0: kd> db ffffeb8e`977aa850 L100
ffffeb8e`977aa850  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffeb8e`977aa860  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffeb8e`977aa870  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffeb8e`977aa880  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffeb8e`977aa890  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffeb8e`977aa8a0  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffeb8e`977aa8b0  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffeb8e`977aa8c0  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffeb8e`977aa8d0  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffeb8e`977aa8e0  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffeb8e`977aa8f0  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffeb8e`977aa900  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffeb8e`977aa910  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffeb8e`977aa920  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffeb8e`977aa930  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
ffffeb8e`977aa940  41 41 41 41 41 41 41 41-41 41 41 41 41 41 41 41  AAAAAAAAAAAAAAAA
```

Great its working. We have overflown the stack with our input because of an insecure driver. Continuing this will cause the VM to crash. WinDBG will pause on its own and let us analyze the crash. 

```text
!analyze -v
kv
```

The first command will spew out a lot of data but looking at it we can easily corelate the crash with our vulnerable driver.

At this point, we have gone from a completely empty WDM driver project to a working Windows kernel driver that can be loaded, unloaded, opened from user mode, controlled through IOCTLs, and observed through WinDbg. We started with safe functionality to understand how normal driver communication works, then added dangerous-looking but controlled IOCTLs to understand what real vulnerable driver interfaces often resemble. Finally, we introduced one intentionally vulnerable IOCTL to demonstrate how a simple trust-boundary mistake, such as copying a user-controlled size into a fixed kernel stack buffer, can turn normal driver functionality into a crashable bug. This gives us the foundation needed for the next part, where we will stop looking at the source code and start reversing the compiled driver like a real third-party target: finding device names, symbolic links, dispatch routines, IOCTL codes, and vulnerable paths directly from the binary.

## References

```text
https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/writing-a-driverentry-routine
https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-standard-driver-routines
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocreatedevice
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocreatesymboliclink
https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol
https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-i-o-control-codes
https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes
https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/buffer-descriptions-for-i-o-control-codes
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgprintex
https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/attaching-to-a-virtual-machine--kernel-mode-
https://docs.oracle.com/en/virtualization/virtualbox/6.0/user/serialports.html
https://github.com/microsoft/Windows-driver-samples/blob/main/general/ioctl/wdm/sys/sioctl.c
```

- A lot of the code was written using Github copilot or ChatGPT for easy understandable code and better explanation 😄
