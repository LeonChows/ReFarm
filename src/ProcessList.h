#pragma once
#ifndef _PROCESS_LIST
#define _PROCESS_LIST
#include <Windows.h>
#include <vector>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS              ((NTSTATUS) 0x00000000)
#define SystemProcessesAndThreadsInformation    5 // 功能号
#define NTAPI    __stdcall

// 线程状态的枚举常量
typedef enum _THREADINFOCLASS
{
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    MaxThreadInfoClass
}THREADINFOCLASS;

// 线程处于等待的原因的枚举常量
typedef enum _KWAIT_REASON
{
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    Spare2,
    Spare3,
    Spare4,
    Spare5,
    Spare6,
    WrKernel,
    MaximumWaitReason
}KWAIT_REASON;

typedef LONG   NTSTATUS;
typedef LONG   KPRIORITY;

typedef struct _CLIENT_ID
{
    HANDLE         UniqueProcess;
    HANDLE         UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _VM_COUNTERS
{
    SIZE_T        PeakVirtualSize;
    SIZE_T        VirtualSize;
    ULONG         PageFaultCount;
    SIZE_T        PeakWorkingSetSize;
    SIZE_T        WorkingSetSize;
    SIZE_T        QuotaPeakPagedPoolUsage;
    SIZE_T        QuotaPagedPoolUsage;
    SIZE_T        QuotaPeakNonPagedPoolUsage;
    SIZE_T        QuotaNonPagedPoolUsage;
    SIZE_T        PagefileUsage;
    SIZE_T        PeakPagefileUsage;
} VM_COUNTERS;

// 线程信息结构体
typedef struct _THREAD_BASIC_INFORMATION
{
    LONG ExitStatus;              //退出状态
    PVOID TebBaseAddress;         //Teb基地址
    CLIENT_ID ClientId;           //客户端ID
    KAFFINITY AffinityMask;       //关联掩码
    KPRIORITY Priority;           //优先级
    KPRIORITY BasePriority;       //基本优先级
}THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


// 进程信息结构体
typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;//链表头
    ULONG NumberOfThreads;//进程中的线程数。
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;//进程的图像名称
    KPRIORITY BasePriority;//进程中创建的线程的启动优先级
    HANDLE UniqueProcessId;//包含进程的唯一进程 ID
    PVOID Reserved2;
    ULONG HandleCount;//进程正在使用的句柄总数
    ULONG SessionId;//进程会话的会话标识符
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;//虚拟内存的峰值大小（以字节为单位）
    SIZE_T VirtualSize;//虚拟内存的当前大小（以字节为单位）
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;//进程工作集的峰值大小（以千字节为单位）
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;//进程收取的分页池使用的当前配额
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;//进程收取的非分页池使用的当前配额
    SIZE_T PagefileUsage;//页面文件存储的字节数
    SIZE_T PeakPagefileUsage;//页面文件存储的最大字节数
    SIZE_T PrivatePageCount;//进程使用的内存页数
    LARGE_INTEGER Reserved7[6];
}SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;
// NtQuerySystemInformation 函数的原型
// 由于该没有导出,所以得自己定义函数的原型
typedef DWORD(WINAPI* MyNtQuerySystemInformation)(UINT, PVOID, DWORD, PDWORD);


typedef NTSTATUS(WINAPI* MyZwQueryInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );

class ProcessList
{
	HMODULE m_ntAdr;
	ULONG m_bufferSize{};
	MyNtQuerySystemInformation NtQuerySystemInformation;
    MyZwQueryInformationThread ZwQueryInformationThread;
    PVOID m_startaddr;                    // 用来接收线程入口地址
    NTSTATUS status;
    std::vector<DWORD> m_threadIds; //线程容器
    HANDLE m_hThread;
    THREAD_BASIC_INFORMATION m_threadBasicInfo{};
public:
	ProcessList() {
        m_ntAdr = GetModuleHandle(TEXT("ntdll.dll"));
		this->NtQuerySystemInformation = reinterpret_cast<MyNtQuerySystemInformation>(GetProcAddress(this->m_ntAdr, "NtQuerySystemInformation"));
        this->ZwQueryInformationThread = reinterpret_cast<MyZwQueryInformationThread>(GetProcAddress(this->m_ntAdr, "ZwQueryInformationThread"));
    };
	~ProcessList() {};
    void EnumerateThreadsInModule(DWORD dwProcessId, std::vector<DWORD>& m_threadIds);
	PSYSTEM_PROCESS_INFORMATION GetSystemInfo();
    void GetProcessThreadStruct(DWORD _pid , THREAD_BASIC_INFORMATION& _threadinfo, PVOID& _threadadr);
    void GetThreadInfo(DWORD _pid, DWORD _dwThreadID, THREAD_BASIC_INFORMATION& _threadinfo, PVOID& _threadadr);
};
#endif // !_PROCESS_LIST