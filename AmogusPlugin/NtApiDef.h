#pragma once
#include  "Struct.h"


NTSTATUS
NTAPI
NtSystemDebugControl
(

    IN SYSDBG_COMMAND       Command,
    IN PVOID                InputBuffer OPTIONAL,
    IN ULONG                InputBufferLength,
    OUT PVOID               OutputBuffer OPTIONAL,
    IN ULONG                OutputBufferLength,
    OUT PULONG              ReturnLength OPTIONAL
);




 


NTSTATUS
NTAPI
NtQueryInformationProcess
(
    IN HANDLE               ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID               ProcessInformation,
    IN ULONG                ProcessInformationLength,
    OUT PULONG              ReturnLength
);


NTSTATUS NTAPI NtSetInformationProcess
(
    IN HANDLE               ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN PVOID                ProcessInformation,
    IN ULONG                ProcessInformationLength
);


NTSTATUS NTAPI NtSetInformationThread
(
    HANDLE          ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength
);

NTSTATUS NTAPI NtQueryInformationThread
(
    HANDLE          ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength,
    PULONG          ReturnLength
);


NTSTATUS NTAPI NtCreateDebugObject
(
      PHANDLE DebugObjectHandle,
      ACCESS_MASK DesiredAccess,
      POBJECT_ATTRIBUTES ObjectAttributes,
      ULONG Flags
);

NTSTATUS NTAPI NtQueryObject
(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

NTSTATUS NTAPI NtClose
(
     HANDLE Handle
);

NTSTATUS NTAPI NtGetContextThread
(
    HANDLE ThreadHandle,
    PCONTEXT Context
);


NTSTATUS NTAPI NtSetContextThread
(
    HANDLE ThreadHandle,
    PCONTEXT Context
);
