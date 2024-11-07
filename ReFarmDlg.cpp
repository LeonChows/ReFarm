#include "pch.h"
#include "framework.h"
#include "ReFarm.h"
#include "ReFarmDlg.h"
#include "afxdialogex.h"
#include <string>
#include <psapi.h>
#include <tchar.h>
#include "LookThread_Window.h"
#pragma comment(lib, "psapi.lib")
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
// CReFarmDlg 对话框
CReFarmDlg::CReFarmDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_REFARM_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}
CReFarmDlg::~CReFarmDlg()
{
	if (m_pm != NULL)
		delete m_pm;
	if (m_ExeInfo != NULL)
		delete m_ExeInfo;
}
void CReFarmDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_MAIN_TAB, m_CTAB_MAIN);
}
BEGIN_MESSAGE_MAP(CReFarmDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CReFarmDlg::OnBnClickedOk)
	ON_NOTIFY(LVN_COLUMNCLICK, IDR_PROCESS_INFO, &CReFarmDlg::OnLvnColumnclickList1)
	ON_NOTIFY(TCN_SELCHANGE, IDC_MAIN_TAB, &CReFarmDlg::OnTcnSelchangeTab1)
	ON_NOTIFY(NM_RCLICK, IDR_PROCESS_INFO, &CReFarmDlg::OnNMRClickList1)
	ON_COMMAND(ID_SYSTEM_EXIT, &CReFarmDlg::OnSystemExit)
	ON_COMMAND(ID_CLOSE_PROCESS, &CReFarmDlg::OnCloseProcess)
	ON_COMMAND(ID_OPEN_PROCESS_FILE, &CReFarmDlg::OnOpenProcessFile)
	ON_COMMAND(ID_DEL_PROCESS_FILE, &CReFarmDlg::OnDelProcessFile)
	ON_COMMAND(ID_SUSPEND_PROCESS, &CReFarmDlg::OnSuspendProcess)
	ON_COMMAND(ID_REPROCESS, &CReFarmDlg::OnReprocess)
	ON_COMMAND(ID_LOOK_THREAD, &CReFarmDlg::OnLookThread)
	ON_WM_CLOSE()
	ON_BN_CLICKED(IDCANCEL, &CReFarmDlg::OnBnClickedCancel)
	ON_COMMAND(ID_NTTHREAD_INJECT, &CReFarmDlg::OnNtthreadInject)
	ON_COMMAND(ID_THREAD_INJECT, &CReFarmDlg::OnThreadInject)
	ON_COMMAND(ID_PROCESS_COPY, &CReFarmDlg::OnProcessCopy)
	ON_COMMAND(ID_PROCESS_COPY_ALL, &CReFarmDlg::OnProcessCopyAll)
	ON_COMMAND(ID_MEM_INJECT, &CReFarmDlg::OnMemInject)
	ON_COMMAND(ID_FANSHE_INJECT, &CReFarmDlg::OnFansheInject)
	ON_COMMAND(ID_THREAD_HOOK, &CReFarmDlg::OnThreadHook)
	ON_COMMAND(ID_MEM_INJECY_PRO, &CReFarmDlg::OnMemInjecyPro)
END_MESSAGE_MAP()

BOOL CReFarmDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	//ShowWindow(SW_MAXIMIZE); //最大化
	//ShowWindow(SW_SHOW); //显示窗口
	//ShowWindow(SW_MINIMIZE); //最小化
	// TODO: 在此添加额外的初始化代码
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES priv = { 0 };
	//提权操作
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return 0;
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
		AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
	CloseHandle(hToken);

	this->MenuInit();
	this->ListInit();
	this->TabInit();
	this->BtnInit();
	this->m_pm = new ProcessMonitor(m_ListHandle);
	this->m_ExeInfo = new PROCESS_INFO(&m_thread);
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}
// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。
void CReFarmDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CReFarmDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CReFarmDlg::ListInit()
{
	this->m_ListHandle = (CListCtrl*)GetDlgItem(IDR_PROCESS_INFO);
	this->m_ListHandle->GetWindowRect(&this->m_rectL);
	this->m_widL = this->m_rectL.right - this->m_rectL.left;
	this->m_nColL = this->m_widL / 5;  //列宽
	this->m_ListHandle->SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);  // 整行选择、网格线
	
	
	//this->m_ListHandle->SetTextBkColor(RGB(224, 238, 238));  //设置文本颜色
	this->m_ListHandle->ModifyStyle(LVS_SORTASCENDING | LVS_SORTDESCENDING, 0);
	
	// 插入列标题
	this->m_ListHandle->InsertColumn(0, _T("进程名"), LVCFMT_LEFT, this->m_nColL);
	this->m_ListHandle->InsertColumn(1, _T("进程ID"), LVCFMT_LEFT, this->m_nColL);
	this->m_ListHandle->InsertColumn(2, _T("会话"), LVCFMT_LEFT, this->m_nColL);
	this->m_ListHandle->InsertColumn(3, _T("线程数"), LVCFMT_LEFT, this->m_nColL);
	this->m_ListHandle->InsertColumn(4, _T("架构"), LVCFMT_LEFT, this->m_nColL);
}

void CReFarmDlg::TabInit()
{
	this->m_TabHandle = (CTabCtrl*)GetDlgItem(IDC_MAIN_TAB);
	m_TabHandle->GetClientRect(&m_rec);
	m_rec.top += 31;  // 稍微为页面留出一些空间，避免紧贴选项卡
	m_rec.bottom += 5;
	m_rec.left += 1;
	m_rec.right -= 3;
	m_TabHandle->InsertItem(0, _T("进程功能"));
	m_TabHandle->InsertItem(1, _T("内存功能"));
	m_TabHandle->InsertItem(2, _T("解密功能"));
	//创建窗口
	m_page1.Create(IDD_TAB_ONE, GetDlgItem(IDC_MAIN_TAB));
	m_page2.Create(IDD_TAB_TWO, GetDlgItem(IDC_MAIN_TAB));
	m_page1.MoveWindow(&m_rec);
	m_page2.MoveWindow(&m_rec);
}

void CReFarmDlg::MenuInit()
{
	this->m_SysMenu.LoadMenu(IDR_MENU_SYSTEM);
	SetMenu(&this->m_SysMenu);
}

void CReFarmDlg::BtnInit()
{
	this->m_btnHanlde = (CButton*)GetDlgItem(IDOK);
	this->m_btnHanlde2 = (CButton*)GetDlgItem(IDCANCEL);
}

void CReFarmDlg::OnBnClickedOk()
{
	m_pm->monitorProcesses();
}

bool CReFarmDlg::m_method = false;// 类外定义

void CReFarmDlg::OnLvnColumnclickList1(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);

	// TODO: 在此添加控件通知处理程序代码

	m_sort_column = pNMLV->iSubItem;//点击的列

	int count = m_ListHandle->GetItemCount();
	for (int i = 0; i < count; i++)
		m_ListHandle->SetItemData(i, i);

	DATA data;
	data.subitem = m_sort_column;
	data.plist = m_ListHandle;

	m_method = !m_method;
	m_ListHandle->SortItems(listCompare, (LPARAM)&data);
	*pResult = 0;
}

int CReFarmDlg::listCompare(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
	DATA* pListCtrl = (DATA*)lParamSort;
	SHORT col = pListCtrl->subitem; // 点击的列项传递给 col，用来判断点击了第几列
	// 获取该列的前2项
	CString strItem1 = (pListCtrl->plist)->GetItemText(lParam1, col);
	CString strItem2 = (pListCtrl->plist)->GetItemText(lParam2, col);

	// 检查字符串是否为空
	bool strItem1IsEmpty = strItem1.IsEmpty();
	bool strItem2IsEmpty = strItem2.IsEmpty();

	// 升序时将空字符串排在最前面，降序时将空字符串排在最后面
	if (strItem1IsEmpty || strItem2IsEmpty) {
		if (strItem1IsEmpty && !strItem2IsEmpty) return m_method ? -1 : 1;
		if (!strItem1IsEmpty && strItem2IsEmpty) return m_method ? 1 : -1;
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
		if (m_method) return n1 < n2 ? -1 : (n1 > n2 ? 1 : 0);
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
		if (strItem1StartsWithDigit && !strItem2StartsWithDigit) return m_method ? -1 : 1;
		if (!strItem1StartsWithDigit && strItem2StartsWithDigit) return m_method ? 1 : -1;
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
		return m_method ? result : -result;
	}

	// 根据字母和数字的数量进行比较
	return compare(letters1 - digits1, letters2 - digits2);
}

void CReFarmDlg::OnTcnSelchangeTab1(NMHDR* pNMHDR, LRESULT* pResult)
{
	int CurSel = this->m_TabHandle->GetCurSel();
	switch (CurSel)
	{
	case 0:
		this->m_page1.ShowWindow(SW_HIDE);
		this->m_page2.ShowWindow(SW_HIDE);
		this->m_ListHandle->UpdateWindow();
		this->m_ListHandle->ShowWindow(SW_SHOW);
		break;
	case 1:
		this->m_page1.ShowWindow(SW_SHOW);
		this->m_page2.ShowWindow(SW_HIDE);
		this->m_ListHandle->ShowWindow(SW_HIDE);
		break;
	case 2:
		this->m_page1.ShowWindow(SW_HIDE);
		this->m_page2.ShowWindow(SW_SHOW);
		this->m_ListHandle->ShowWindow(SW_HIDE);
		break;
	default:
		break;
	}

	*pResult = 0;
}

void CReFarmDlg::OnNMRClickList1(NMHDR* pNMHDR, LRESULT* pResult)
{
	// 加载菜单资源
	this->m_PinfoMenu.LoadMenuA(IDR_MENU_PROCESS);
	// 获取鼠标点击的位置
	CPoint point;
	GetCursorPos(&point);
	// 将屏幕坐标转换为列表控件的客户区坐标
	this->m_ListHandle->ScreenToClient(&point);

	// 获取点击的项和子项
	LVHITTESTINFO hitTestInfo;
	hitTestInfo.pt = point;
	this->m_nSelectedItem = this->m_ListHandle->SubItemHitTest(&hitTestInfo); // 行
	this->m_nSelectedSubItem = hitTestInfo.iSubItem; // 列
	// 根据选中的子项列，获取并设置列文本
	if (m_nSelectedItem != -1 && m_nSelectedSubItem != -1) {
		// 获取项的值
		this->m_ExeInfo->m_PName = this->m_ListHandle->GetItemText(m_nSelectedItem, 0); // 名字
		this->m_ExeInfo->m_PorcessID = _atoi64(this->m_ListHandle->GetItemText(m_nSelectedItem, 1)); // PID
		this->m_ExeInfo->m_Conversation = _atoi64(this->m_ListHandle->GetItemText(m_nSelectedItem, 2));
		this->m_ExeInfo->m_ThreadNum = _atoi64(this->m_ListHandle->GetItemText(m_nSelectedItem, 3));
		this->m_ExeInfo->m_WinFram = this->m_ListHandle->GetItemText(m_nSelectedItem, 4);

		// 遍历线程
		this->m_pm->GetProceeAllThreadID(this->m_ExeInfo->m_PorcessID, this->m_thread);

		

		// 打开进程
		//this->m_ExeInfo->m_Phandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, this->m_ExeInfo->m_PorcessID);
		this->m_ExeInfo->m_Phandle = this->m_pm->OpenProcessNt(this->m_ExeInfo->m_PorcessID);
		
		if (this->m_ExeInfo->m_Phandle != NULL)
		{
			CHAR szModName[MAX_PATH];
			GetModuleFileNameEx(this->m_ExeInfo->m_Phandle, NULL, szModName, sizeof(szModName));
			this->m_ExeInfo->m_ExePath = szModName;
			CloseHandle(this->m_ExeInfo->m_Phandle);
		}

		// 获取菜单项的文本
		CString MenuListStr;
		this->m_PinfoMenu.GetMenuStringA(ID_PROCESS_COPY, MenuListStr, NULL); // 获取菜单某个项的文本

		// 创建菜单项信息结构
		MENUITEMINFO MenuListadr = { 0 };
		MenuListadr.cbSize = sizeof(MENUITEMINFO); // 设置结构大小
		MenuListadr.fMask = MIIM_STRING; // 设置文本宏

		// 创建列信息结构
		LVCOLUMNA ListColumnadr = { 0 };
		ListColumnadr.mask = LVCF_TEXT; // 设置文本宏

		// 使用一个足够大的缓冲区来获取列的文本
		char buffer[MAX_PATH] = { 0 };
		ListColumnadr.pszText = buffer; // 设置指向缓冲区
		ListColumnadr.cchTextMax = MAX_PATH;


		// 获取列文本
		this->m_ListHandle->GetColumn(this->m_nSelectedSubItem, &ListColumnadr);
		CString ListColumnStr = buffer; // 将缓冲区内容赋值给 CString

		CString CheatText;
		CheatText.Format("%s\"%s\"\0", MenuListStr, ListColumnStr);

		// 分配一个新的缓冲区来保存 CheatText 内容
		std::vector<char> menuBuffer(CheatText.GetLength() + 1); // +1 for null terminator
		strcpy_s(menuBuffer.data(), menuBuffer.size(), CheatText.GetBuffer()); // 复制内容到新的缓冲区

		MenuListadr.dwTypeData = menuBuffer.data(); // 设置要更改的文本
		m_PinfoMenu.SetMenuItemInfoA(ID_PROCESS_COPY, &MenuListadr);
	

		// 获取弹出菜单的子菜单
		CMenu* pPopup = this->m_PinfoMenu.GetSubMenu(0);
		ASSERT(pPopup != nullptr);

		// 显示菜单
		this->m_ListHandle->ClientToScreen(&point);
		pPopup->TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON, point.x, point.y, this);
	}
	this->m_PinfoMenu.SetDefaultItem(IDR_MENU_PROCESS);
	*pResult = 0;
}

void CReFarmDlg::OnSystemExit()
{
	// TODO: 在此添加命令处理程序代码
	this->OnClose();
}

void CReFarmDlg::OnBnClickedCancel()
{
	// TODO: 在此添加控件通知处理程序代码
	this->OnClose();
}

void CReFarmDlg::OnCloseProcess()
{
	
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, this->m_ExeInfo->m_PorcessID);
	if (!hProcess)
		AfxMessageBox(_T("打开进程失败！"));

	if (TerminateProcess(hProcess, 0)){
		Sleep(500);
		m_pm->monitorProcesses();
	}
	else
	{
		AfxMessageBox("进程结束失败");
	}
	CloseHandle(hProcess);
}

void CReFarmDlg::OnOpenProcessFile()
{
	CStringW strPath(this->m_ExeInfo->m_ExePath.c_str());
	int pos = strPath.ReverseFind(_T('\\'));
	// 解析文件夹路径
	PIDLIST_ABSOLUTE pidlFolder;
	HRESULT hr = SHParseDisplayName(strPath.Left(pos), nullptr, &pidlFolder, 0, nullptr);
	if (SUCCEEDED(hr))
	{
		// 解析文件路径
		PIDLIST_RELATIVE pidlFile;
		hr = SHParseDisplayName(strPath, nullptr, &pidlFile, 0, nullptr);
		if (SUCCEEDED(hr))
		{
			// 将文件 PIDL 放入数组中
			LPCITEMIDLIST rgPidl[] = { pidlFile };

			// 打开文件夹并选择文件
			hr = SHOpenFolderAndSelectItems(pidlFolder, ARRAYSIZE(rgPidl), rgPidl, 0);
			if (FAILED(hr))
			{
				AfxMessageBox(_T("未能打开文件夹并选择文件 错误代码：") + this->GetErrorNum(hr));
			}
			// 释放文件 PIDL
			CoTaskMemFree(pidlFile);
		}
		else
		{
			AfxMessageBox(_T("解析文件名失败，错误代码:") + this->GetErrorNum(hr));
		}
		// 释放文件夹 PIDL
		CoTaskMemFree(pidlFolder);
	}
	else
	{
		AfxMessageBox(_T("解析文件夹路径失败，错误代码:") + this->GetErrorNum(hr));
	}
}

void CReFarmDlg::OnDelProcessFile()
{
	BOOL isDel = this->m_pm->DelFile(this->m_ExeInfo->m_ExePath);
	if (!isDel)
		AfxMessageBox("请管理员运行！");
	else
		AfxMessageBox("成功删除...!");
}

void CReFarmDlg::OnSuspendProcess()
{
	for (DWORD dwThreadID : this->m_thread)
	{
		HANDLE ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadID);
		SuspendThread(ThreadHandle);
		CloseHandle(ThreadHandle);
	}
}

void CReFarmDlg::OnReprocess()
{
	for (DWORD dwThreadID : this->m_thread)
	{
		HANDLE ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadID);
		ResumeThread(ThreadHandle);
		CloseHandle(ThreadHandle);
	}
}

void CReFarmDlg::OnLookThread()
{
	LookThread_Window* win = new LookThread_Window(this->m_ExeInfo->m_PorcessID);
	//win->DoModal();
	win->Create(IDD_LOOK_THREAD);
	CString str(_T("线程列表    "));
	str.Append(this->m_ExeInfo->m_PName.c_str());
	win->SetWindowText(str);
	win->ShowWindow(SW_SHOW);
}

void CReFarmDlg::OnClose()
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	OnCancel();
}

std::string OpenFileDialog() {
	// 初始化OPENFILENAME结构体
	OPENFILENAME ofn;
	std::vector<char> fileNames(80 * MAX_PATH, 0);
	ZeroMemory(&ofn, sizeof(ofn));

	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = NULL;
	ofn.lpstrFile = fileNames.data();
	ofn.nMaxFile = static_cast<DWORD>(fileNames.size());
	ofn.lpstrFilter = "可执行文件 (*.exe)\0*.exe\0动态链接库 (*.dll)\0*.dll\0所有文件 (*.*)\0*.*\0";
	ofn.nFilterIndex = 2;
	ofn.lpstrTitle = "选择文件";
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_ALLOWMULTISELECT | OFN_HIDEREADONLY | OFN_EXPLORER;

	// 打开文件选择对话框
	if (!GetOpenFileName(&ofn)) {
		// 如果对话框取消或出错，返回空字符串
		return "";
	}

	// 处理文件路径和名称
	std::string result;
	std::string directory(fileNames.data());

	// 如果选择了多个文件
	if (fileNames[ofn.nFileOffset - 1] == '\0') {
		// 获取目录路径
		std::string path(fileNames.data(), ofn.nFileOffset - 1);
		// 拼接每个文件的完整路径
		for (char* p = fileNames.data() + ofn.nFileOffset; *p; p += lstrlenA(p) + 1) {
			result += path + "\\" + p + " ";
		}
		// 移除最后一个多余的空格
		if (!result.empty()) {
			result.pop_back();
		}
	}
	else {
		// 如果只选择了一个文件，直接获取文件路径
		result = fileNames.data();
	}

	return result;
}

void CReFarmDlg::OnNtthreadInject()
{
	char dllpath[MAX_PATH];
	std::string _Tpath = OpenFileDialog();
	if (_Tpath.empty())
		return;
	strcpy(dllpath, _Tpath.c_str());

	if (this->m_ExeInfo->m_WinFram == "x64")
		this->m_pm->inject_nt(this->m_ExeInfo->m_PorcessID, dllpath, 1);
	else
		this->m_pm->inject_nt(this->m_ExeInfo->m_PorcessID, dllpath, 0);

}

void CReFarmDlg::OnThreadInject()
{
	char dllpath[MAX_PATH];
	std::string _Tpath = OpenFileDialog();
	if (_Tpath.empty())
		return;
	strcpy(dllpath, _Tpath.c_str());

	if (this->m_ExeInfo->m_WinFram == "x64")
		this->m_pm->inject(this->m_ExeInfo->m_PorcessID, dllpath, 1);
	else
		this->m_pm->inject(this->m_ExeInfo->m_PorcessID, dllpath, 0);
}

void CReFarmDlg::CopyText(LPCSTR _str) {
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

void CReFarmDlg::OnProcessCopy()
{
	CopyText(this->m_ListHandle->GetItemText(this->m_nSelectedItem, this->m_nSelectedSubItem).GetString());
}

void CReFarmDlg::OnProcessCopyAll()
{
	CHeaderCtrl* pHeadCtrl = this->m_ListHandle->GetHeaderCtrl();
	if (pHeadCtrl != NULL)
	{
		CString Liststr;
		DWORD Listnum = pHeadCtrl->GetItemCount();
		for (size_t i = 0; i < Listnum; i++)
		{
			Liststr.Append(this->m_ListHandle->GetItemText(this->m_nSelectedItem, i));
			Liststr.Append("\t\t");
		}
		CopyText(Liststr.GetString());
	}
}

void CReFarmDlg::OnMemInject()
{
	char dllpath[MAX_PATH];
	std::string _Tpath = OpenFileDialog();
	if (_Tpath.empty())
		return;
	strcpy(dllpath, _Tpath.c_str());
	this->m_pm->meminject(this->m_ExeInfo->m_PorcessID, dllpath);
}

void CReFarmDlg::OnFansheInject()
{
	AfxMessageBox("反射内存注入是一种特殊的注入方式 你的dll需要本程序目录下的文件 否则无法注入成功！");
	char dllpath[MAX_PATH];
	std::string _Tpath = OpenFileDialog();
	if (_Tpath.empty())
		return;
	strcpy(dllpath, _Tpath.c_str());
	this->m_pm->reflectinject(this->m_ExeInfo->m_PorcessID, dllpath);
}

void CReFarmDlg::OnThreadHook()
{
#ifdef _WIN64
#include "src/dll_datax64.h"
#else
#include "src/dll_datax.h"
#endif // _WIN64
	this->m_pm->reflectinject(this->m_ExeInfo->m_PorcessID, dll_data, dll_data_len);
}

void CReFarmDlg::OnMemInjecyPro()
{
	char dllpath[MAX_PATH];
	std::string _Tpath = OpenFileDialog();
	if (_Tpath.empty())
		return;
	strcpy(dllpath, _Tpath.c_str());
	this->m_pm->meminjectPro(this->m_ExeInfo->m_PorcessID, dllpath);
}
