#include "ProcessList.h"
#include <tchar.h>
#include <thread>
#include <string>
#include <locale>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
PSYSTEM_PROCESS_INFORMATION ProcessList::GetSystemInfo()
{
    NTSTATUS Status = 0;
    std::string Temperror;
    if (this->NtQuerySystemInformation == NULL)
        return nullptr;

    PSYSTEM_PROCESS_INFORMATION pInfo = nullptr;
    DWORD dwSize = 0;

    // 获取信息所需的缓冲区大小
    Status = NtQuerySystemInformation(SystemProcessesAndThreadsInformation, nullptr, 0, &dwSize);

    if (!NT_SUCCESS(Status) && Status != STATUS_INFO_LENGTH_MISMATCH) {
        Temperror = "Failed to get the buffer size for process information, Status: ";
        Temperror += std::to_string(Status);
        OutputDebugString(Temperror.c_str());
        return nullptr;
    }

    // 申请缓冲区
    char* pBuff = new char[dwSize];
    if (pBuff == nullptr) {
        Temperror = "Memory allocation failed.";
        OutputDebugString(Temperror.c_str());
        return nullptr;
    }
    pInfo = (PSYSTEM_PROCESS_INFORMATION)pBuff;

    // 多次重试机制 为了避免系统缓存刷新不合格
    int retryCount = 2;
    while (retryCount--) {
        Status = NtQuerySystemInformation(SystemProcessesAndThreadsInformation, pInfo, dwSize, &dwSize);
        if (NT_SUCCESS(Status)) {
            break;
        }
        else {
            Temperror = "Failed to get process information, Status: ";
            Temperror += std::to_string(Status);
            OutputDebugString(Temperror.c_str());
            if (retryCount > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100)); // 添加延迟
            }
        }
    }

    if (!NT_SUCCESS(Status)) {
        delete[] pBuff;
        return nullptr;
    }

    return pInfo;
}
void ProcessList::EnumerateThreadsInModule(DWORD dwProcessId, std::vector<DWORD>& m_threadIds) //枚举所有线程 判断线程是否属于该进程
{
    // 创建线程快照
    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnapshot == INVALID_HANDLE_VALUE)
        return;
    THREADENTRY32 te{};
    te.dwSize = sizeof(THREADENTRY32);

    // 遍历线程快照
    if (Thread32First(hThreadSnapshot, &te))
    {
        do
        {
            if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
            {
                // 检查线程是否属于指定进程
                if (te.th32OwnerProcessID == dwProcessId)
                {
                    m_threadIds.push_back(te.th32ThreadID);
                }
            }
            te.dwSize = sizeof(THREADENTRY32);
        } while (Thread32Next(hThreadSnapshot, &te));
    } 
    CloseHandle(hThreadSnapshot);
}
void ProcessList::GetProcessThreadStruct(DWORD _pid,THREAD_BASIC_INFORMATION& _threadinfo, PVOID& _threadadr)
{
    EnumerateThreadsInModule(_pid, m_threadIds);
    for (DWORD dwThreadId : m_threadIds) //取出容器数值
    {
        if (dwThreadId == 0)
            continue;
        this->m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
        // 将区域设置设置为从操作系统获取的ANSI代码页
        setlocale(LC_ALL, ".ACP");
        if (ZwQueryInformationThread == NULL) {
            MessageBoxA(NULL, "内部错误 未能获取到函数地址", "Caption", MB_OK);
            return;
        }
        // 获取线程的所有信息
        status = ZwQueryInformationThread(
            this->m_hThread,
            ThreadBasicInformation,
            &this->m_threadBasicInfo,
            sizeof(this->m_threadBasicInfo),
            NULL
        );
        if (status != 0) {
            return;
        }
        status = ZwQueryInformationThread(
            this->m_hThread,                            // 线程句柄
            ThreadQuerySetWin32StartAddress,            // 线程信息类型，ThreadQuerySetWin32StartAddress ：线程入口地址
            &this->m_startaddr,                         // 指向缓冲区的指针
            sizeof(this->m_startaddr),                  // 缓冲区的大小
            NULL
        );
        if (status != 0) {
            return;
        }
        CloseHandle(this->m_hThread);
    }
    _threadinfo = this->m_threadBasicInfo;
    _threadadr = m_startaddr;
}
void ProcessList::GetThreadInfo(DWORD _pid, DWORD _dwThreadID, THREAD_BASIC_INFORMATION& _threadinfo, PVOID& _threadadr)
{
    this->m_hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, _dwThreadID);
    // 将区域设置设置为从操作系统获取的ANSI代码页
    setlocale(LC_ALL, ".ACP");
    if (ZwQueryInformationThread == NULL) {
        MessageBoxA(NULL, "内部错误 未能获取到函数地址", "Caption", MB_OK);
        return;
    }
    // 获取线程的所有信息
    status = ZwQueryInformationThread(
        this->m_hThread,
        ThreadBasicInformation,
        &this->m_threadBasicInfo,
        sizeof(this->m_threadBasicInfo),
        NULL
    );
    if (status != 0) {
        return;
    }
    status = ZwQueryInformationThread(
        this->m_hThread,                            // 线程句柄
        ThreadQuerySetWin32StartAddress,            // 线程信息类型，ThreadQuerySetWin32StartAddress ：线程入口地址
        &this->m_startaddr,                         // 指向缓冲区的指针
        sizeof(this->m_startaddr),                  // 缓冲区的大小
        NULL
    );
    if (status != 0) {
        return;
    }
    CloseHandle(this->m_hThread);
    _threadinfo = this->m_threadBasicInfo;
    _threadadr = m_startaddr;
}