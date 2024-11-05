
// ReFarmDlg.h: 头文件
//

#pragma once
#include "ProcessMonitor.h"
// CReFarmDlg 对话框
class CReFarmDlg : public CDialogEx
{
// 构造
public:

	CReFarmDlg(CWnd* pParent = nullptr);	// 标准构造函数
	~CReFarmDlg();	// 标准构造函数
// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_REFARM_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;
	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
private:
	CRect m_rectL;
	int m_widL;
	int m_nColL;
	int m_sort_column;  // 表示需要排序的列
	static bool m_method;  //类内申明
	ProcessMonitor* m_pm;
	struct DATA
	{
		int subitem;
		CListCtrl* plist;
	};
	//错误处理
	CString GetErrorNum(DWORD num) {
		char Tempstr[16]{};
		return "error" + CString(_itoa(num, Tempstr, sizeof(Tempstr)));
	}
	std::vector<DWORD>m_thread;
public://function
	PPROCESS_INFO m_ExeInfo;
public: //按钮
	CButton* m_btnHanlde;
	CButton* m_btnHanlde2;
	afx_msg void BtnInit();
	afx_msg void OnBnClickedOk();
public://列表
	CListCtrl* m_ListHandle;
	afx_msg void ListInit();
	afx_msg void OnLvnColumnclickList1(NMHDR* pNMHDR, LRESULT* pResult);//单机排序
	static int CALLBACK listCompare(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);//自定义处理函数
	afx_msg void OnNMRClickList1(NMHDR* pNMHDR, LRESULT* pResult);
private:
	int m_nSelectedItem;   // 选中的项索引
	int m_nSelectedSubItem; // 选中的子项索引

public://表
	CTabCtrl* m_TabHandle;
	afx_msg void TabInit();
	int m_CurSelTab;
	CDialog  m_page1;
	CDialog  m_page2;
	CDialog* pDialog[2];  //用来保存对话框对象指针
	afx_msg void OnTcnSelchangeTab1(NMHDR* pNMHDR, LRESULT* pResult);

public: // Menu
	CMenu m_SysMenu;
	CMenu m_PinfoMenu;
	HANDLE m_ChProcess;
	afx_msg void MenuInit();
	afx_msg void OnSystemExit();
	afx_msg void OnCloseProcess();
	afx_msg void OnOpenProcessFile();
	afx_msg void OnDelProcessFile();
	afx_msg void OnSuspendProcess();
	afx_msg void OnReprocess();
	afx_msg void OnLookThread();
	afx_msg void OnClose();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnNtthreadInject();
	afx_msg void OnThreadInject();
	afx_msg void OnProcessCopy();
	virtual void CopyText(LPCSTR _str);
	afx_msg void OnProcessCopyAll();
	afx_msg void OnMemInject();
	afx_msg void OnFansheInject();
	afx_msg void OnThreadHook();
	afx_msg void OnMemInjecyPro();
};
