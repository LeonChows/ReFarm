// mem_tab_one.cpp: 实现文件
//

#include "pch.h"
#include "ReFarm.h"
#include "afxdialogex.h"
#include "mem_tab_one.h"


// mem_tab_one 对话框

IMPLEMENT_DYNAMIC(mem_tab_one, CDialogEx)

mem_tab_one::mem_tab_one(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_TAB_ONE, pParent)
{

}

mem_tab_one::~mem_tab_one()
{
}

void mem_tab_one::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(mem_tab_one, CDialogEx)
END_MESSAGE_MAP()


// mem_tab_one 消息处理程序
