#pragma once
#include "afxdialogex.h"
#include "ProcessMonitor.h"
// LookThread_Window 对话框

class LookThread_Window : public CDialogEx
{
	DECLARE_DYNAMIC(LookThread_Window)

public:
	LookThread_Window(CWnd* pParent = nullptr);   // 标准构造函数
	LookThread_Window(DWORD _pid);				  // get pid
	virtual ~LookThread_Window();
// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_LOOK_THREAD };
#endif

protected:
	virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	DECLARE_MESSAGE_MAP()
public://窗口

private://列表框
	struct DATA_t
	{
		DWORD subitem;
		CListCtrl* plist;
	};

	CListCtrl* m_ListHandle_t;
	DWORD m_sort_column_t;
	static bool m_method_t;
	DWORD m_widL_t;
	RECT m_rectL_t;
	DWORD m_nColL_t;
	afx_msg void ListInit_t();
private:
	int m_nSelectedItem_t;   // 选中的项索引
	int m_nSelectedSubItem_t; // 选中的子项索引
private://function

	std::vector<DWORD>m_threadID_t;
	DWORD m_gthreadID_t;
	DWORD m_pid_t;
	THREAD_BASIC_INFORMATION m_te_t;
	LPVOID m_threadr_t;
	ProcessMonitor* m_pm_t;
	void SetThreadStruct();
	void GetThreadID();
	void SetList();
	void GetThreadStruct(DWORD _dwThreadID);
	DWORD m_dwThreadId;
public:
	afx_msg void OnDestroy();
	afx_msg void OnClose();
	afx_msg void OnNMRClickThreadList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnLvnColumnclickThreadList(NMHDR* pNMHDR, LRESULT* pResult);
	static int CALLBACK listCompare_t(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);//自定义处理函数
	afx_msg void OnThreadPause();
	afx_msg void OnThreadReagin();
	afx_msg void OnThreadEnd();
	afx_msg void OnThreadRefresh();
	afx_msg void OnThreadCopy();
	virtual void CopyText(LPCSTR _str);
	afx_msg void OnThreadCopyAll();
};
