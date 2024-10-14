// LookThread_Window.cpp: 实现文件
//

#include "pch.h"
#include "ReFarm.h"
#include "afxdialogex.h"
#include "LookThread_Window.h"

// LookThread_Window 对话框

IMPLEMENT_DYNAMIC(LookThread_Window, CDialogEx)

LookThread_Window::LookThread_Window(CWnd* pParent/*=nullptr*/)
	: CDialogEx(IDD_LOOK_THREAD, pParent)
{
}

LookThread_Window::LookThread_Window(DWORD _pid) :m_pid_t(_pid)
{
}

LookThread_Window::~LookThread_Window()
{
	if (this->m_pm_t != NULL)
		delete this->m_pm_t;
}

void LookThread_Window::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BOOL LookThread_Window::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	this->ListInit_t();
	this->m_pm_t = new ProcessMonitor();
	this->SetThreadStruct();
	this->SetList();
	return TRUE;  
}

BEGIN_MESSAGE_MAP(LookThread_Window, CDialogEx)
	ON_WM_DESTROY()
	ON_WM_CLOSE()
	ON_NOTIFY(NM_RCLICK, IDC_THREAD_LIST, &LookThread_Window::OnNMRClickThreadList)
	ON_NOTIFY(LVN_COLUMNCLICK, IDC_THREAD_LIST, &LookThread_Window::OnLvnColumnclickThreadList)
	ON_COMMAND(ID_THREAD_PAUSE, &LookThread_Window::OnThreadPause)
	ON_COMMAND(ID_THREAD_REAGIN, &LookThread_Window::OnThreadReagin)
	ON_COMMAND(ID_THREAD_END, &LookThread_Window::OnThreadEnd)
	ON_COMMAND(ID_Thread_Refresh, &LookThread_Window::OnThreadRefresh)
	ON_COMMAND(ID_THREAD_COPY, &LookThread_Window::OnThreadCopy)
	ON_COMMAND(ID_THREAD_COPY_ALL, &LookThread_Window::OnThreadCopyAll)
END_MESSAGE_MAP()
bool LookThread_Window::m_method_t = false;// 类外定义
void LookThread_Window::OnLvnColumnclickThreadList(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);

	// TODO: 在此添加控件通知处理程序代码

	this->m_sort_column_t = pNMLV->iSubItem;//点击的列

	int count = m_ListHandle_t->GetItemCount();
	for (int i = 0; i < count; i++)
		m_ListHandle_t->SetItemData(i, i);

	DATA_t data;
	data.subitem = this->m_sort_column_t;
	data.plist = m_ListHandle_t;

	m_method_t = !m_method_t;
	m_ListHandle_t->SortItems(listCompare_t, (LPARAM)&data);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
}

int LookThread_Window::listCompare_t(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
	DATA_t* pListCtrl = (DATA_t*)lParamSort;
	SHORT col = pListCtrl->subitem; // 点击的列项传递给 col，用来判断点击了第几列

	// 获取该列的前2项
	CString strItem1 = (pListCtrl->plist)->GetItemText(lParam1, col);
	CString strItem2 = (pListCtrl->plist)->GetItemText(lParam2, col);

	// 检查字符串是否为空
	bool strItem1IsEmpty = strItem1.IsEmpty();
	bool strItem2IsEmpty = strItem2.IsEmpty();

	// 升序时将空字符串排在最前面，降序时将空字符串排在最后面
	if (strItem1IsEmpty || strItem2IsEmpty) {
		if (strItem1IsEmpty && !strItem2IsEmpty) return m_method_t ? -1 : 1;
		if (!strItem1IsEmpty && strItem2IsEmpty) return m_method_t ? 1 : -1;
		return 0; // 都为空时相等
	}

	// 检查字符串是否为十六进制文本
	auto isHexText = [](const CString& str) -> bool {
		if (str.GetLength() > 2 && str.Left(2).CompareNoCase(_T("0x")) == 0) {
			for (int i = 2; i < str.GetLength(); ++i) {
				if (!isxdigit(str[i])) return false;
			}
			return true;
		}
		return false;
		};

	bool strItem1IsHex = isHexText(strItem1);
	bool strItem2IsHex = isHexText(strItem2);

	// 比较函数
	auto compare = [&](const __int64& n1, const __int64& n2) -> int {
		if (m_method_t) return n1 < n2 ? -1 : (n1 > n2 ? 1 : 0);
		return n1 > n2 ? -1 : (n1 < n2 ? 1 : 0);
		};

	// 如果两个字符串都是十六进制文本，按十六进制数值比较
	if (strItem1IsHex && strItem2IsHex) {
		__int64 n1 = _tcstoi64(strItem1, nullptr, 16);
		__int64 n2 = _tcstoi64(strItem2, nullptr, 16);
		return compare(n1, n2);
	}

	// 检查字符串是否以数字开头
	auto startsWithDigit = [](const CString& str) -> bool {
		return isdigit(str[0]);
		};

	bool strItem1StartsWithDigit = startsWithDigit(strItem1);
	bool strItem2StartsWithDigit = startsWithDigit(strItem2);

	// 如果两个字符串都以数字开头，按数字比较
	if (strItem1StartsWithDigit && strItem2StartsWithDigit) {
		__int64 n1 = _atoi64(strItem1);
		__int64 n2 = _atoi64(strItem2);
		return compare(n1, n2);
	}

	// 如果一个字符串以数字开头，另一个不是，则将其排在最小的位置
	if (strItem1StartsWithDigit || strItem2StartsWithDigit) {
		if (strItem1StartsWithDigit && !strItem2StartsWithDigit) return m_method_t ? -1 : 1;
		if (!strItem1StartsWithDigit && strItem2StartsWithDigit) return m_method_t ? 1 : -1;
	}

	// 比较两个字符串中字母和数字的数量
	auto countLettersAndDigits = [](const CString& str) -> std::pair<int, int> {
		int letters = 0, digits = 0;
		for (int i = 0; i < str.GetLength(); ++i) {
			if (isalpha(str[i])) ++letters;
			if (isdigit(str[i])) ++digits;
		}
		return { letters, digits };
		};

	auto [letters1, digits1] = countLettersAndDigits(strItem1);
	auto [letters2, digits2] = countLettersAndDigits(strItem2);

	// 比较字母和数字的数量
	if ((letters1 > digits1 && letters2 > digits2) || (letters1 <= digits1 && letters2 <= digits2)) {
		int result = strItem1.CompareNoCase(strItem2);
		return m_method_t ? result : -result;
	}

	// 根据字母和数字的数量进行比较
	return compare(letters1 - digits1, letters2 - digits2);

}
// LookThread_Window 消息处理程序

void LookThread_Window::ListInit_t()
{
	this->m_ListHandle_t = (CListCtrl*)GetDlgItem(IDC_THREAD_LIST);
	this->m_ListHandle_t->GetWindowRect(&this->m_rectL_t);
	this->m_widL_t = this->m_rectL_t.right - this->m_rectL_t.left;
	this->m_nColL_t = this->m_widL_t / 5;  //列宽
	this->m_ListHandle_t->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);  // 整行选择、网格线
	//this->m_ListHandle_t->SetTextBkColor(RGB(224, 238, 238));  //设置文本颜色
	this->m_ListHandle_t->ModifyStyle(LVS_SORTASCENDING | LVS_SORTDESCENDING, 0);

	// 插入列标题
	this->m_ListHandle_t->InsertColumn(0, _T("线程ID"), LVCFMT_LEFT, this->m_nColL_t);
	this->m_ListHandle_t->InsertColumn(1, _T("线程优先级"), LVCFMT_LEFT, this->m_nColL_t);
	this->m_ListHandle_t->InsertColumn(2, _T("线程起始地址"), LVCFMT_LEFT, this->m_nColL_t);
	this->m_ListHandle_t->InsertColumn(3, _T("线程TEB地址"), LVCFMT_LEFT, this->m_nColL_t);
	this->m_ListHandle_t->InsertColumn(4, _T("线程退出状态"), LVCFMT_LEFT, this->m_nColL_t);
}

void LookThread_Window::SetThreadStruct()
{
	this->m_pm_t->monitorThread(this->m_pid_t, this->m_te_t, this->m_threadr_t);
}

void LookThread_Window::GetThreadID()
{
	this->m_pm_t->GetProceeAllThreadID(this->m_pid_t, this->m_threadID_t);
}

void LookThread_Window::SetList()
{
	// 使用 lambda 表达式将 uint64_t 转换为十六进制 CString，格式化为 16 位宽的十六进制字符串
	auto DWORDToHexCString = [](uint64_t value) -> CString {
		CString hexString;
		hexString.Format(_T("0x%016llX"), value); // 格式化为 16 位宽的十六进制字符串
		return hexString;
		};
	this->GetThreadID();
	for (DWORD dwThreadId : this->m_threadID_t)
	{
		GetThreadStruct(dwThreadId);
		// 获取当前列表项
		int i = 0;
		this->m_ListHandle_t->InsertItem(i, "");
		this->m_ListHandle_t->SetItemText(i, 0, std::to_string(dwThreadId).c_str());
		this->m_ListHandle_t->SetItemText(i, 1, DWORDToHexCString((uint64_t)this->m_te_t.Priority));
		this->m_ListHandle_t->SetItemText(i, 2, DWORDToHexCString((uint64_t)this->m_threadr_t));
		this->m_ListHandle_t->SetItemText(i, 3, DWORDToHexCString((uint64_t)this->m_te_t.TebBaseAddress));
		this->m_ListHandle_t->SetItemText(i, 4, DWORDToHexCString((uint64_t)this->m_te_t.ExitStatus));
		i++;
	}
}

void  LookThread_Window::GetThreadStruct(DWORD _dwThreadID) 
{
	this->m_pm_t->SetThreadStruct(this->m_pid_t, _dwThreadID, this->m_te_t, this->m_threadr_t);
}

void LookThread_Window::OnDestroy()
{
	CDialog::OnDestroy();
	delete this;
}

void LookThread_Window::OnClose()
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	CDialogEx::OnClose();
	delete this;
}

void LookThread_Window::OnNMRClickThreadList(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	CPoint point;
	GetCursorPos(&point);
	// 将屏幕坐标转换为列表控件的客户区坐标
	this->m_ListHandle_t->ScreenToClient(&point);
	// 获取点击的项和子项
	LVHITTESTINFO hitTestInfo;
	hitTestInfo.pt = point;
	this->m_nSelectedItem_t = this->m_ListHandle_t->SubItemHitTest(&hitTestInfo); // 行
	this->m_nSelectedSubItem_t = hitTestInfo.iSubItem; // 列

	if (this->m_nSelectedItem_t != -1 && this->m_nSelectedSubItem_t != -1)
	{
		// 加载右键菜单
		CMenu m_PinfoMenu;
		m_PinfoMenu.LoadMenu(IDR_MENU_THREAD);

		// 获取菜单项的文本
		CString ListColumnStr, MenuListStr, CheatText;
		m_PinfoMenu.GetMenuStringA(ID_THREAD_COPY, MenuListStr, NULL);

		// 动态分配内存
		LPMENUITEMINFO MenuListadr = new MENUITEMINFO;
		ZeroMemory(MenuListadr, sizeof(MENUITEMINFO));
		MenuListadr->cbSize = sizeof(MENUITEMINFO);
		MenuListadr->fMask = MIIM_STRING; // 设置文本宏

		LVCOLUMNA ListColumnadr;
		ZeroMemory(&ListColumnadr, sizeof(LVCOLUMNA));
		ListColumnadr.mask = LVCF_TEXT; // 设置文本宏

		// 使用一个固定大小的缓冲区来获取列的文本
		char buffer[MAX_PATH] = { 0 };
		ListColumnadr.pszText = buffer; // 设置指向缓冲区
		ListColumnadr.cchTextMax = MAX_PATH;


		// 获取列文本
		this->m_ListHandle_t->GetColumn(this->m_nSelectedSubItem_t, &ListColumnadr);
		ListColumnStr = buffer; // 将缓冲区内容赋值给 CString

		CheatText.Format("%s\"%s\"\0", MenuListStr.GetBuffer(), ListColumnStr.GetBuffer());

		// 分配一个新的缓冲区来保存 CheatText 内容
		char* menuBuffer = new char[CheatText.GetLength() + 1]; // +1 for null terminator
		strcpy_s(menuBuffer, CheatText.GetLength() + 1, CheatText.GetBuffer()); // 复制内容到新的缓冲区

		MenuListadr->dwTypeData = menuBuffer; // 设置要更改的文本
		m_PinfoMenu.SetMenuItemInfoA(ID_THREAD_COPY, MenuListadr);

		// 释放 menuBuffer 内存
		delete[] menuBuffer;
		

		this->m_gthreadID_t = _atoi64(this->m_ListHandle_t->GetItemText(m_nSelectedItem_t, 0));
		this->m_te_t.Priority = _atoi64(this->m_ListHandle_t->GetItemText(m_nSelectedItem_t, 1));
		this->m_threadr_t = (LPVOID)_atoi64(this->m_ListHandle_t->GetItemText(m_nSelectedItem_t, 2));
		this->m_te_t.TebBaseAddress = (LPVOID)_atoi64(this->m_ListHandle_t->GetItemText(m_nSelectedItem_t, 3));
		this->m_te_t.ExitStatus = _atoi64(this->m_ListHandle_t->GetItemText(m_nSelectedItem_t, 4));


		CMenu* pPopup = m_PinfoMenu.GetSubMenu(0);
		ASSERT(pPopup != nullptr);

		this->m_ListHandle_t->ClientToScreen(&point);
		pPopup->TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON, point.x, point.y, this);
		// 释放动态分配的内存
		delete MenuListadr;
	}
	*pResult = 0;
}

void LookThread_Window::OnThreadPause()
{
	HANDLE thandle = OpenThread(THREAD_ALL_ACCESS, false, this->m_gthreadID_t);
	SuspendThread(thandle);
	CloseHandle(thandle);
}

void LookThread_Window::OnThreadReagin()
{
	HANDLE thandle = OpenThread(THREAD_ALL_ACCESS, false, this->m_gthreadID_t);
	ResumeThread(thandle);
	CloseHandle(thandle);
}

void LookThread_Window::OnThreadEnd()
{
	HANDLE thandle = OpenThread(THREAD_ALL_ACCESS, false, this->m_gthreadID_t);
	TerminateThread(thandle, 0);
	CloseHandle(thandle);
}

void LookThread_Window::OnThreadRefresh()
{
	this->m_ListHandle_t->DeleteAllItems(); //再次遍历删除所有项
	this->m_threadID_t.clear(); //先清除旧数据
	this->SetList();
}

void LookThread_Window::CopyText(LPCSTR _str) {
	if (OpenClipboard()) {
		EmptyClipboard();
		HGLOBAL hglbCopy = GlobalAlloc(GMEM_MOVEABLE, (strlen(_str) + 1) * sizeof(char));
		if (hglbCopy == NULL) {
			CloseClipboard();
			return;
		}
		char* lptstrCopy = (char*)GlobalLock(hglbCopy);
		memcpy(lptstrCopy, _str, strlen(_str) + 1);
		lptstrCopy[strlen(_str) + 1 - 1] = (char)0;    // null character 
		GlobalUnlock(hglbCopy);
		SetClipboardData(CF_TEXT, hglbCopy);
		CloseClipboard();
	}
}

void LookThread_Window::OnThreadCopy()
{
	CopyText(this->m_ListHandle_t->GetItemText(this->m_nSelectedItem_t, this->m_nSelectedSubItem_t).GetString());
}

void LookThread_Window::OnThreadCopyAll()
{
	CHeaderCtrl* pHeadCtrl = this->m_ListHandle_t->GetHeaderCtrl();
	if (pHeadCtrl != NULL)
	{
		CString Liststr;
		DWORD Listnum = pHeadCtrl->GetItemCount();
		for (size_t i = 0; i < Listnum; i++)
		{
			Liststr.Append(this->m_ListHandle_t->GetItemText(this->m_nSelectedItem_t, i));
			Liststr.Append("\t\t");
		}
		CopyText(Liststr.GetString());
	}
}
