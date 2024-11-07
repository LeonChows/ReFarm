#pragma once
#include "afxdialogex.h"
// TAB_TWO 对话框
#include <thread>
#include <vector>
#include <atomic>
#include <string>
#include <time.h>
#include <chrono>
#include <codecvt>
class TAB_TWO : public CDialogEx
{
	DECLARE_DYNAMIC(TAB_TWO)

public:
	TAB_TWO(CWnd* pParent = nullptr);   // 标准构造函数
	virtual ~TAB_TWO();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_TAB_TWO };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	//初始化
	virtual BOOL OnInitDialog();

public:
	//控件
	CComboBox* m_CryptoModelBom;
	CComboBox* m_KeyModelBom;
	CComboBox* m_IvModelBom;
	CEdit* m_input_pEdit;
	CEdit* m_out_pEdit;
	CEdit* m_iv_pEdit;

	afx_msg void OnBnClickedInputgroup();
	afx_msg void OnBnClickedOutgroup();
	int m_input_group;
	int m_out_group;
	afx_msg void OnBnClickedEncodeButton();
	afx_msg void OnBnClickedDecodeButton();
	afx_msg void OnBnClickedSuohaButton();
	virtual BOOL PreTranslateMessage(MSG* pMsg);
//diy
	afx_msg bool suoha(CString key);
	void suoha2(std::string _path);

	void startThreads() 
	{
		std::thread threads(&TAB_TWO::suoha2, this,"a");
		threads.detach();
	}

	afx_msg void OnContextMenu(CWnd* /*pWnd*/, CPoint /*point*/);
};
