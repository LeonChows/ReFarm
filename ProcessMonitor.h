#ifndef _PROCESS_MONITOR
#define _PROCESS_MONITOR

#include <afxcmn.h>
#include <string>
#include <atomic>
#include <vector>
#include "src/ProcessList.h"
#include "src/FileHelp.h"
#include "DLLinject.h"

typedef struct _processInfoex
{
    DWORD m_ThreadNum;              //线程数
    DWORD m_Conversation;           //会话
    DWORD m_PorcessID;              //线程ID
    HANDLE m_Phandle;               //进程句柄
    std::vector<DWORD>* m_ThreadID; // 将引用成员改为指针
    std::string m_WinFram;          //软件位数
    std::string m_ExePath;          //软件路径
    std::string m_PName;            //软件名字
    _processInfoex(std::vector<DWORD>* _ThreadID) : m_ThreadID(_ThreadID) {} // 构造函数改为初始化指针
} PROCESS_INFO, * PPROCESS_INFO;

class ProcessMonitor
{
public:
    ProcessMonitor(CListCtrl* listHandle) : m_ListHandle(listHandle) {
        this->m_PL = new ProcessList;
        this->m_File = new FileHelp;
        this->m_DLLinject = new DLLinject;
    }

    ~ProcessMonitor() {
        if (m_PL != nullptr)
            delete this->m_PL;
            delete this->m_File;
            delete this->m_DLLinject;
    }

    ProcessMonitor() {
        this->m_PL = new ProcessList;
        this->m_File = new FileHelp;
        this->m_DLLinject = new DLLinject;
    }

    void monitorProcesses();//进程所有信息
    void monitorThread(DWORD _pid, THREAD_BASIC_INFORMATION& _te, PVOID& _threadadr);//线程所有信息
    void GetProceeAllThreadID(DWORD pid, std::vector<DWORD>& _threadID);//所在进程的所有线程ID
    //设置线程结构体
    void SetThreadStruct(DWORD _pid, DWORD _dwThreadID, THREAD_BASIC_INFORMATION& _te, PVOID& _threadadr);
    //强删除文件
    bool DelFile(std::string _DirPath);
    //nt 注入dll
    BOOL inject_nt(DWORD _pid, LPCSTR _path,BOOL _isX64);
    //注入dll
    BOOL inject(DWORD _pid, LPCSTR _path, BOOL _isX64);
    //反射注入
    BOOL reflectinject(DWORD _pid, LPCSTR _path);
    BOOL reflectinject(DWORD _pid, LPVOID _buf, size_t _size);
    //内存注入
    BOOL meminject(DWORD _pid, LPCSTR _path);
    //NT打开进程
    HANDLE OpenProcessNt(DWORD _pid, DWORD flags = PROCESS_ALL_ACCESS);
private:
    CListCtrl* m_ListHandle;
    ProcessList* m_PL;
    FileHelp* m_File;
    DLLinject* m_DLLinject;
};

#endif // !_PROCESS_MONITOR
