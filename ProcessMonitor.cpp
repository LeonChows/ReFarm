#include "ProcessMonitor.h"

//错误处理
CString GetErrorNum(DWORD num) {
	char Tempstr[16]{};
	return "error" + CString(_itoa(num, Tempstr, sizeof(Tempstr)));
}

void ProcessMonitor::monitorProcesses() {
	PSYSTEM_PROCESS_INFORMATION m_Plist = m_PL->GetSystemInfo();
	if (!m_Plist) {
		AfxMessageBox(GetErrorNum(GetLastError()));
		return;
	}
	this->m_ListHandle->DeleteAllItems(); //再次遍历删除所有项
	for (PSYSTEM_PROCESS_INFORMATION pInfo = m_Plist; ; ) {
		DWORD processId = (DWORD)(pInfo->UniqueProcessId);
		// 获取当前列表项
		int i = 0;
		this->m_ListHandle->InsertItem(i, "");
		this->m_ListHandle->SetItemText(i, 0, CW2A(pInfo->ImageName.Buffer));
		this->m_ListHandle->SetItemText(i, 1, std::to_string(processId).c_str());
		this->m_ListHandle->SetItemText(i, 2, std::to_string(pInfo->SessionId).c_str());
		this->m_ListHandle->SetItemText(i, 3, std::to_string(pInfo->NumberOfThreads).c_str());
		//HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
		HANDLE pHandle = this->OpenProcessNt(processId);
		if (pHandle != NULL) {
			BOOL isWOW;
			IsWow64Process(pHandle, &isWOW);
			if (isWOW)
				this->m_ListHandle->SetItemText(i, 4, "x86");
			else
				this->m_ListHandle->SetItemText(i, 4, "x64");
			CloseHandle(pHandle);
		}
		i++;
		if (pInfo->NextEntryOffset == 0) break;
		pInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG64)pInfo + pInfo->NextEntryOffset);
	}
}

void ProcessMonitor::monitorThread(DWORD _pid, THREAD_BASIC_INFORMATION& _te, PVOID& _threadadr)
{
	m_PL->GetProcessThreadStruct(_pid, _te, _threadadr);
}
void ProcessMonitor::GetProceeAllThreadID(DWORD pid,std::vector<DWORD>& _threadID)
{
	m_PL->EnumerateThreadsInModule(pid, _threadID);
}
void ProcessMonitor::SetThreadStruct(DWORD _pid, DWORD _dwThreadID,THREAD_BASIC_INFORMATION& _te, PVOID& _threadadr) 
{
	m_PL->GetThreadInfo(_pid, _dwThreadID, _te, _threadadr);
}

bool ProcessMonitor::DelFile(std::string _DirPath)
{
	return m_File->ForcedFileDeletion(_DirPath);
}
BOOL ProcessMonitor::inject_nt(DWORD _pid, LPCSTR _path, BOOL _isX64) {
	this->m_DLLinject->SetSystemFarme(_isX64);
	return this->m_DLLinject->NTThreadInject(_pid, _path);
}
BOOL ProcessMonitor::inject(DWORD _pid, LPCSTR _path, BOOL _isX64) {

	this->m_DLLinject->SetSystemFarme(_isX64);
	return this->m_DLLinject->ThreadInject(_pid, _path);
}

BOOL ProcessMonitor::reflectinject(DWORD _pid, LPCSTR _path)
{
	return this->m_DLLinject->ReflectInject(_pid, _path);
}
HANDLE ProcessMonitor::OpenProcessNt(DWORD _pid, DWORD flags)
{
	return this->m_DLLinject->LZwOpenProcess(_pid, flags);
}
BOOL ProcessMonitor::reflectinject(DWORD _pid, LPVOID _buf,size_t _size)
{
	return this->m_DLLinject->ReflectInject(_pid, _buf, _size);
}
BOOL ProcessMonitor::meminject(DWORD _pid, LPCSTR _path)
{
	return this->m_DLLinject->MemInject(_pid, _path);
}

BOOL ProcessMonitor::meminjectPro(DWORD _pid, LPCSTR _path)
{
	return this->m_DLLinject->MemInjectPro(_pid, _path);	
}
