#pragma once
#include "afxdialogex.h"


// mem_tab_one 对话框

class mem_tab_one : public CDialogEx
{
	DECLARE_DYNAMIC(mem_tab_one)

public:
	mem_tab_one(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~mem_tab_one();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_TAB_ONE };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
};
