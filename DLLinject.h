#pragma once
#ifndef _DLLINJECT
#define _DLLINJECT
#include <windows.h>
#include <string>
#include <tlhelp32.h>

typedef NTSTATUS(NTAPI* MyZwCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    ULONG_PTR ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );
typedef struct _CLIENT_ID_
{
    HANDLE         UniqueProcess;
    HANDLE         UniqueThread;
} CLIENT_ID_DLL, * PCLIENT_ID_DLL;

typedef struct _UNICODE_STRING_
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_DLL, * PUNICODE_STRING_DLL;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING_DLL ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* MyNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID_DLL ClientId
    );


#ifdef _WIN64
// NtWriteVirtualMemory 函数类型定义
typedef NTSTATUS(NTAPI* MyWriteVirtualMemory)(
    HANDLE ProcessHandle,
    LPVOID BaseAddress,
    LPCVOID Buffer,
    ULONG64 NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten
    );
#else
typedef
DWORD
(NTAPI* MyWriteVirtualMemory)(
    HANDLE ProcessHandle,
    LPVOID BaseAddress,
    LPCVOID Buffer,
    ULONG BufferLength,
    PULONG ReturnLength OPTIONAL
    );
#endif // _WIN64


class DLLinject
{
public:
    HMODULE m_ntadr;
    MyNtOpenProcess NtOpenProcess;
    MyWriteVirtualMemory NtWriteVirtualMemory;
    MyZwCreateThreadEx ZwCreateThreadEx;
    NTSTATUS LZwCreatThread(HANDLE _hProcess, LPTHREAD_START_ROUTINE _funAdr, LPVOID _paramAdr, PHANDLE _RetThreadID)
    {
        return this->ZwCreateThreadEx(_RetThreadID, THREAD_ALL_ACCESS, NULL, _hProcess, (LPTHREAD_START_ROUTINE)_funAdr, _paramAdr, NULL, NULL, NULL, NULL, NULL);
    }
    HANDLE LZwOpenProcess(DWORD dwPid, DWORD dwDesiredAccess = PROCESS_ALL_ACCESS, BOOL bInheritHandle = false)
    {
        ULONGLONG ullv5;
        struct _OBJECT_ATTRIBUTES obj_attr = {};
        obj_attr.Length = sizeof(_OBJECT_ATTRIBUTES);//48
        CLIENT_ID_DLL pPid = {};
        pPid.UniqueProcess = (HANDLE)dwPid;
        obj_attr.Attributes = bInheritHandle ? 2 : 0;
        HANDLE handle = 0;
        LONG lret = this->NtOpenProcess(&handle, dwDesiredAccess, &obj_attr, &pPid);
        if (lret >= 0)
        {
            return handle;
        }
        else
        {
            return NULL;
        }
    }
    template <typename _Num>
    DWORD LNtWriteVirtualMemory(DWORD _pid, LPVOID _address, _Num& _num) {
        DWORD status = 0;
        DWORD OldProtect;
        DWORD BufferLength = sizeof(_num);
        HANDLE hProcess = this->LZwOpenProcess(_pid);

        if (hProcess != 0) { // 使用 hProcess 而不是 _hProcess
            // 修改内存保护属性以允许写入
            if (VirtualProtectEx(hProcess, _address, BufferLength, PAGE_READWRITE, &OldProtect) == 0) {
                CloseHandle(hProcess);
                return GetLastError(); // 如果失败，返回错误代码
            }

            // 写入内存
            status = this->NtWriteVirtualMemory(hProcess, _address, (LPCVOID)&_num, BufferLength, nullptr); // 传递 &_num

            // 恢复内存的原始保护属性
            if (VirtualProtectEx(hProcess, _address, BufferLength, OldProtect, nullptr) == 0) {
                CloseHandle(hProcess);
                return GetLastError(); // 如果恢复失败，返回错误代码
            }

            // 检查写入结果
            if (status >= 0) { // 检查 NTSTATUS 是否为成功状态
                CloseHandle(hProcess);
                return 0; // 返回 0 表示成功
            }
            else {
                CloseHandle(hProcess);
                return status; // 返回具体的 NTSTATUS 错误代码
            }
        }

        return GetLastError(); // 如果无法打开进程，返回错误代码
    }
    template <typename _Num>
    DWORD LNtWriteVirtualMemory(DWORD _pid, LPVOID _address, _Num& _num, DWORD _BufferLength) {
        DWORD status = 0;
        DWORD OldProtect;
        HANDLE hProcess = this->LZwOpenProcess(_pid);

        if (hProcess != 0) { // 使用 hProcess 而不是 _hProcess
            // 修改内存保护属性以允许写入
            if (VirtualProtectEx(hProcess, _address, _BufferLength, PAGE_READWRITE, &OldProtect) == 0) {
                CloseHandle(hProcess);
                return GetLastError(); // 如果失败，返回错误代码
            }

            // 写入内存
            status = this->NtWriteVirtualMemory(hProcess, _address, (LPCVOID)&_num, _BufferLength, nullptr); // 传递 &_num

      


            // 恢复内存的原始保护属性
            if (VirtualProtectEx(hProcess, _address, _BufferLength, OldProtect, nullptr) == 0) {
                CloseHandle(hProcess);
                return GetLastError(); // 如果恢复失败，返回错误代码
            }

            // 检查写入结果
            if (status >= 0) { // 检查 NTSTATUS 是否为成功状态
                CloseHandle(hProcess);
                return 0; // 返回 0 表示成功
            }
            else {
                CloseHandle(hProcess);
                return status; // 返回具体的 NTSTATUS 错误代码
            }
        }

        return GetLastError(); // 如果无法打开进程，返回错误代码
    }
    DWORD LNtWriteVirtualMemory(DWORD _pid, LPVOID _address, LPCVOID _num, DWORD _BufferLength) 
    {
        DWORD status = 0;
        DWORD OldProtect;
        HANDLE hProcess = this->LZwOpenProcess(_pid);

        if (hProcess != 0) { // 使用 hProcess 而不是 _hProcess
            // 修改内存保护属性以允许写入
            if (VirtualProtectEx(hProcess, _address, _BufferLength, PAGE_READWRITE, &OldProtect) == 0) {
                CloseHandle(hProcess);
                return GetLastError(); // 如果失败，返回错误代码
            }

            // 写入内存
            status = this->NtWriteVirtualMemory(hProcess, _address, _num, _BufferLength, nullptr); // 传递 &_num

            // 恢复内存的原始保护属性
            if (VirtualProtectEx(hProcess, _address, _BufferLength, OldProtect, nullptr) == 0) {
                CloseHandle(hProcess);
                return GetLastError(); // 如果恢复失败，返回错误代码
            }

            // 检查写入结果
            if (status >= 0) { // 检查 NTSTATUS 是否为成功状态
                CloseHandle(hProcess);
                return 0; // 返回 0 表示成功
            }
            else {
                CloseHandle(hProcess);
                return status; // 返回具体的 NTSTATUS 错误代码
            }
        }

        return GetLastError(); // 如果无法打开进程，返回错误代码

    }
private:
    BOOL m_isX64;
    DWORD m_size = 0, m_ssss = 0;
    uint64_t* m_Memx;
    WORD* m_MemData;


public:
    void SetSystemFarme(BOOL _isx64) { m_isX64 = _isx64;}
public:
    DLLinject() {
        this->m_ntadr = GetModuleHandle("ntdll.dll");
        this->NtOpenProcess = reinterpret_cast<MyNtOpenProcess>(GetProcAddress(this->m_ntadr, "NtOpenProcess"));
        this->NtWriteVirtualMemory = reinterpret_cast<MyWriteVirtualMemory>(GetProcAddress(this->m_ntadr, "NtWriteVirtualMemory"));
        this->ZwCreateThreadEx = reinterpret_cast<MyZwCreateThreadEx>(GetProcAddress(this->m_ntadr, "ZwCreateThreadEx"));
    }
    ~DLLinject() {}
    BOOL NTThreadInject(DWORD _pid, LPCSTR _DLLPath);
    BOOL ThreadInject(DWORD _pid,LPCSTR _DLLPath);
    BOOL ReflectInject(DWORD _pid, LPCSTR _DLLPath);
    BOOL ReflectInject(DWORD _pid, LPVOID _lpBuffer, size_t _bufsize);
    BOOL MemInject(DWORD _pid, LPCSTR _DLLPath);
    BOOL MemInjectPro(DWORD _pid, LPCSTR _DLLPath);
};
namespace SupInject {

    class ReflectInject : DLLinject
    {
    public:
        ReflectInject() {};
        ~ReflectInject() {};
        HANDLE LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter);
        DWORD GetLoaderOffset(VOID* lpReflectiveDllBuffer);
        DWORD RvaToOffset(DWORD dwRva, UINT_PTR uiBaseAddress);
        HMODULE LoadLibraryR(LPVOID lpBuffer, DWORD dwLength);
        FARPROC WINAPI GetProcAddressR(HANDLE hModule, LPCSTR lpProcName);
    private:
        #define DEREF( name )*(UINT_PTR *)(name)
        #define DEREF_64( name )*(DWORD64 *)(name)
        #define DEREF_32( name )*(DWORD *)(name)
        #define DEREF_16( name )*(WORD *)(name)
        #define DEREF_8( name )*(BYTE *)(name)

        typedef ULONG_PTR(WINAPI* REFLECTIVELOADER)(VOID);
        typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);

        #define DLL_QUERY_HMODULE		6
    };
    namespace MemInject {
        #ifdef _WIN64
                typedef  DWORD64 DWORDX;
        #else
                typedef  DWORD32 DWORDX;
        #endif
        #include <Winternl.h>
        typedef NTSTATUS(WINAPI* LdrGetProcedureAddressT)(IN PVOID DllHandle, IN PANSI_STRING ProcedureName OPTIONAL, IN ULONG ProcedureNumber OPTIONAL, OUT FARPROC* ProcedureAddress);
        typedef VOID(WINAPI* RtlFreeUnicodeStringT)(_Inout_ PUNICODE_STRING UnicodeString);
        typedef  VOID(WINAPI* RtlInitAnsiStringT)(_Out_    PANSI_STRING DestinationString, _In_opt_ PCSZ         SourceString);
        typedef NTSTATUS(WINAPI* RtlAnsiStringToUnicodeStringT)(_Inout_ PUNICODE_STRING DestinationString, _In_ PCANSI_STRING SourceString, _In_ BOOLEAN AllocateDestinationString);
        typedef NTSTATUS(WINAPI* LdrLoadDllT)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
        typedef BOOL(APIENTRY* ProcDllMain)(LPVOID, DWORD, LPVOID);
        typedef NTSTATUS(WINAPI* NtAllocateVirtualMemoryT)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN ULONG ZeroBits, IN OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG Protect);
        struct PARAMX
        {
            PVOID lpFileData;
            DWORD DataLength;
            LdrGetProcedureAddressT LdrGetProcedureAddress;
            NtAllocateVirtualMemoryT dwNtAllocateVirtualMemory;
            LdrLoadDllT pLdrLoadDll;
            RtlInitAnsiStringT RtlInitAnsiString;
            RtlAnsiStringToUnicodeStringT RtlAnsiStringToUnicodeString;
            RtlFreeUnicodeStringT RtlFreeUnicodeString;
        };
        static DWORD size = 0;
        DWORDX WINAPI MemLoadLibrary(PARAMX* X);
        static WORD* Memx = (WORD*)MemLoadLibrary;
    }

    namespace MemInject2 {
        #ifdef _WIN64
        #define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
        #else
        #define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
        #endif
        using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
        using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
        using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);
        struct MANUAL_MAPPING_DATA
        {
            f_LoadLibraryA pLoadLibraryA;
            f_GetProcAddress pGetProcAddress;
            BYTE* pbase;
            HINSTANCE hMod;
            DWORD fdwReasonParam;
            LPVOID reservedParam;
        };
        #define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
        #define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

        #ifdef _WIN64
        #define RELOC_FLAG RELOC_FLAG64
        #else
        #define RELOC_FLAG RELOC_FLAG32
        #endif

        void WINAPI Shellcode(MANUAL_MAPPING_DATA* pData);
        bool WINAPI ManualMapDll(DWORD _pid, HANDLE& _retthread, BYTE* pSrcData);

    }
}
#endif // _DLLINJECT
