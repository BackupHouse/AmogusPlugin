#pragma once


#include "lazy_importer.h"
#include "NtApiDef.h"
#include <iostream>

#define RaceCondition 1
bool RCHideDebugger = TRUE;
namespace BadCode
{
    __forceinline  int wtolower(int c)
    {
        if (c >= L'A' && c <= L'Z') return c - L'A' + L'a';
        if (c >= L'À' && c <= L'ß') return c - L'À' + L'à';
        if (c == L'¨') return L'¸';
        return c;
    }
    __forceinline int wstricmp(const wchar_t* cs, const wchar_t* ct)
    {
        if (cs && ct)
        {
            while (wtolower(*cs) == wtolower(*ct))
            {
                if (*cs == 0 && *ct == 0) return 0;
                if (*cs == 0 || *ct == 0) break;
                cs++;
                ct++;
            }
            return wtolower(*cs) - wtolower(*ct);
        }
        return -1;
    }

    __forceinline  int GetWindowsNumber()
    {

        auto NtMajorVersion = *(BYTE*)0x7FFE026C;
        if (NtMajorVersion == 10)
        {
            auto NtBuildNumber = *(int*)0x7FFE0260;//NtBuildNumber
            if (NtBuildNumber >= 22000)
            {
                return WINDOWS_NUMBER_11;
            }
            return WINDOWS_NUMBER_10;
        }
        else if (NtMajorVersion == 5)
        {
            return WINDOWS_NUMBER_XP;//Windows XP
        }
        else if (NtMajorVersion == 6)
        {
            /*
            https://www.godeye.club/2021/06/03/002-mhyprot-insider-callbacks.html
            */
            switch (*(BYTE*)0x7FFE0270)  //0x7FFE0270 NtMinorVersion
            {
            case 1:
                return WINDOWS_NUMBER_7;//windows 7
            case 2:
                return WINDOWS_NUMBER_8; //window 8
            case 3:
                return WINDOWS_NUMBER_8_1; //windows 8.1
            default:
                return WINDOWS_NUMBER_11;//windows 11
            }

        }

        return 0;
    }

    void MemFucntion()
    {
        __nop();
    }

 

    /*
    * https://github.com/mrexodia/TitanHide/issues/44
    *Detect SharpOD,ScyllaHide ,TitanHide
    */
    __forceinline bool IsBadHideContext()
    {
        const auto memAddress = reinterpret_cast<uint64_t>(&MemFucntion);
        CONTEXT ctx = {0};
        CONTEXT ctx2 = {0};
        ctx.Dr0 = memAddress;
        ctx.Dr7 = 1; 
        ctx.ContextFlags = 0x10;
        ctx2.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        /*
        Bug ScyllaHide:https://github.com/x64dbg/ScyllaHide/blob/a0e5b8f2b1d90be65022545d25288f389368a94d/HookLibrary/HookedFunctions.cpp#L468
        Crash ScyllaHide / SharpOD
        */
        if (NT_SUCCESS(LI_FN(NtSetContextThread).nt_cached()(NtCurrentThread, (PCONTEXT)1)))
            return TRUE;
        if (NT_SUCCESS(LI_FN(NtGetContextThread).nt_cached()(NtCurrentThread, (PCONTEXT)1)))
            return TRUE;

        if (!NT_SUCCESS(LI_FN(NtSetContextThread).nt_cached()(NtCurrentThread, &ctx)))
            return FALSE;
        if (!NT_SUCCESS(LI_FN(NtGetContextThread).nt_cached()(NtCurrentThread, &ctx2)))
            return FALSE;
        if (ctx2.Dr0 != ctx.Dr0 || 
            ctx2.Dr0 != memAddress  ||
            ctx2.Dr1 ||
            ctx2.Dr2 ||
            ctx2.Dr3 ||
            !ctx2.Dr7 )
            return TRUE;
       
        ctx2.Dr0 = 0;
        ctx2.Dr7 = 0;
        ctx2.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        LI_FN(NtGetContextThread).nt_cached()(NtCurrentThread, &ctx);
        return FALSE;
    }

    /*
    Detect   HyperHide and need check windows >= 8.1+
    https://github.com/Air14/HyperHide/blob/11d9ebc7ce5e039e890820f8712e3c678f800370/HyperHideDrv/HookedFunctions.cpp#L624
    */
    __forceinline bool  IsSystemDebugHook()
    {

        auto bufferFake = NULL;
        auto bufferFake2 = NULL;
        ULONG RetLenght = NULL;

        //SysDbgGetLiveKernelDump 

        auto   nt_status = LI_FN(NtSystemDebugControl).cached()((SYSDBG_COMMAND)0x25, &bufferFake, 0x10, &bufferFake2, 0x10, &RetLenght);

        if (GetWindowsNumber() >= WINDOWS_NUMBER_10 && nt_status == STATUS_DEBUGGER_INACTIVE)
        {

            return TRUE;
        }
        return FALSE;

    }

    /*
    Detect TitanHide and SharpOD
    https://github.com/HighSchoolSoftwareClub/Windows-Research-Kernel-WRK-/blob/26b524b2d0f18de703018e16ec5377889afcf4ab/WRK-v1.2/base/ntos/ps/psquery.c#L2784=
    */
    __forceinline  bool IsDebugFlagHooked()
    {


        uint32_t DebugFlag = NULL;

        NTSTATUS status = LI_FN(NtQueryInformationProcess).cached()(NtCurrentProcess, ProcessDebugFlags, &DebugFlag, sizeof(DebugFlag), 0);


        uint32_t  SafeValue = DebugFlag; //Safe value for present some problem 

        if (!NT_SUCCESS(status))
        {
            return FALSE;
        }
        DebugFlag = !DebugFlag;

        /*
        Crash ScyllaHide 
       */
        status = LI_FN(NtSetInformationProcess).cached()(NtCurrentProcess, ProcessDebugFlags, (PVOID)1, sizeof(DebugFlag));
        if (NT_SUCCESS(status))
        {
            return TRUE;
        }

        status = LI_FN(NtSetInformationProcess).cached()(NtCurrentProcess, ProcessDebugFlags, &DebugFlag, sizeof(DebugFlag));

        //Can't set value
        if (!NT_SUCCESS(status))
        {
            return FALSE;
        }

        status = LI_FN(NtQueryInformationProcess).cached()(NtCurrentProcess, ProcessDebugFlags, &DebugFlag, sizeof(DebugFlag), 0);


        if (NT_SUCCESS(status) && DebugFlag != 0)
        {
            return TRUE;
        }
        /*
        or check only hook
         if (NT_SUCCESS(status) && DebugFlag == SafeValue)
        {
            return TRUE;
        }
        
        */
        status = LI_FN(NtSetInformationProcess).cached()(NtCurrentProcess, ProcessDebugFlags, &SafeValue, sizeof(SafeValue));

        if (!NT_SUCCESS(status))
        {
            return FALSE;
        }
        return FALSE;
    }
    
    /*
    Detect SharpOD,ScyllaHide,TitanHide
    */
    __forceinline bool IsBadThreadHide()
    {

        bool IsThreadHide = FALSE;
        ULONG returnLenght = 0;
        NTSTATUS Status = 0;
#if RaceCondition == 1
        /*
        https://github.com/mrexodia/TitanHide/blob/93f3bf218b8bb69680a50d28411cd881a8a17580/TitanHide/hooks.cpp#L113
        Race condition TitanHide and the thread should not be hidden before checking ;)
        */
        if (RCHideDebugger)
        {


            Status = LI_FN(NtQueryInformationThread).nt()(NtCurrentThread, ThreadHideFromDebugger, &IsThreadHide, sizeof(IsThreadHide), &returnLenght);

            if ( (NT_SUCCESS(Status) && (IsThreadHide || returnLenght != 1)) || Status == STATUS_INFO_LENGTH_MISMATCH)
            {
               return TRUE;
            }
            IsThreadHide = FALSE;
            RCHideDebugger = FALSE;
        }
#endif // RaceCondition

         Status = LI_FN(NtSetInformationThread).nt()(NtCurrentThread, ThreadHideFromDebugger, &IsThreadHide, 0xDEADC0DE);
        if (NT_SUCCESS(Status))
        {
          return TRUE;
        }

        Status = LI_FN(NtSetInformationThread).nt()((HANDLE)0xFFFF, ThreadHideFromDebugger, NULL, 0);
        if (NT_SUCCESS(Status))
        {
             return TRUE;

        }
        Status = LI_FN(NtSetInformationThread).nt()(NtCurrentThread, ThreadHideFromDebugger, NULL, 0);

        if (NT_SUCCESS(Status))
        {
            Status = LI_FN(NtQueryInformationThread).nt()(NtCurrentThread, ThreadHideFromDebugger, &IsThreadHide,sizeof(IsThreadHide), &returnLenght);
            //ScyllaHide and SharpOD don'h hook NtQueryInformationThread(ThreadHideFromDebugger)
            if ((NT_SUCCESS(Status) && returnLenght != 1) || Status == STATUS_INFO_LENGTH_MISMATCH)
            {
                return TRUE;
            }  
            return !IsThreadHide && NT_SUCCESS(Status);
        }
        else
        { 
            return TRUE;
        } 
        return FALSE;
    }

    /*
    HyperHide bug:https://github.com/Air14/HyperHide/blob/11d9ebc7ce5e039e890820f8712e3c678f800370/HyperHideDrv/HookedFunctions.cpp#L594
    SchyllaHide bug:https://github.com/x64dbg/ScyllaHide/blob/2276f1477132e99c96f31552bce7b4d2925fb918/HookLibrary/HookedFunctions.cpp#L1041
    TitanHide bug:https://github.com/mrexodia/TitanHide/blob/77337790dac809bde3ff8d739deda24d67979668/TitanHide/hooks.cpp#L426
    SharpOD -  detect

    https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiDebug/NtQueryObject_AllTypesInformation.cpp
    Explanation: we create a debug object, but go through all the objects and
    if their number is less than 1 (we created at least 1), then there is a hook
    */
    __forceinline bool IsBadHookNumberObject()
    {
        HANDLE debugObject = NULL;
        OBJECT_ATTRIBUTES object_attrib;
        DWORD Lenght = NULL;
        PVOID buffer = NULL; 
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        DWORD maxNumberOfObjects = NULL;
        InitializeObjectAttributes(&object_attrib, 0, 0, 0, 0);
        status = LI_FN(NtCreateDebugObject).nt_cached()(&debugObject, DEBUG_ALL_ACCESS, &object_attrib, 0);
        if (NT_SUCCESS(status))
        {
            //Get correct lenght
            status = LI_FN(NtQueryObject).nt_cached()(NULL, ObjectTypesInformation, &Lenght, sizeof(ULONG), &Lenght);

            buffer = VirtualAlloc(NULL, Lenght, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (buffer == NULL)
            {
                LI_FN(NtClose).nt_cached()(debugObject);
                return FALSE;
            }

            //https://github.com/HighSchoolSoftwareClub/Windows-Research-Kernel-WRK-/blob/26b524b2d0f18de703018e16ec5377889afcf4ab/WRK-v1.2/base/ntos/ob/obquery.c#L406
            status = LI_FN(NtQueryObject).nt_cached()(NtCurrentProcess, ObjectTypesInformation, buffer, Lenght, NULL);

            if (!NT_SUCCESS(status))
            {
                LI_FN(NtClose).nt_cached()(debugObject);
                VirtualFree(buffer, 0, MEM_RELEASE);
                return FALSE;
            } 

           auto  objectAllInfo = (POBJECT_ALL_INFORMATION)buffer;
           UCHAR* objInfoLocation = (UCHAR*)objectAllInfo->ObjectTypeInformation;
            for (UINT i = 0; i < objectAllInfo->NumberOfObjectsTypes; i++)
            {

                POBJECT_TYPE_INFORMATION objectTypeInfo = (POBJECT_TYPE_INFORMATION)objInfoLocation;

                // The debug object will always be present
                if (wstricmp(L"DebugObject", objectTypeInfo->TypeName.Buffer) == 0)
                {
                    // Are there any objects?
                    if (objectTypeInfo->TotalNumberOfObjects > 0)
                    {
                        maxNumberOfObjects += objectTypeInfo->TotalNumberOfObjects;
                    }
                }

                objInfoLocation = (unsigned char*)objectTypeInfo->TypeName.Buffer;

             
                objInfoLocation += objectTypeInfo->TypeName.MaximumLength;
                 ULONG_PTR tmp = ((ULONG_PTR)objInfoLocation) & -(int)sizeof(void*);
                  
                if ((ULONG_PTR)tmp != (ULONG_PTR)objInfoLocation)
                    tmp += sizeof(void*);
                objInfoLocation = ((unsigned char*)tmp);
            }


            VirtualFree(buffer, 0, MEM_RELEASE);
            LI_FN(NtClose).nt_cached()(debugObject);
            return maxNumberOfObjects < 1;
            

            
        }
        else
        {
            return FALSE;
        }
    }
    
}