// TAB_TWO.cpp: 实现文件
//

#include "pch.h"
#include "ReFarm.h"
#include "afxdialogex.h"
#include "TAB_TWO.h"
#include "src\FileHelp.h"
enum _INPUT
{
	STRING = 0,
	HEX = 1,
	BASE64 = 2,
	UTF8 = 3,
};
// TAB_TWO 对话框

IMPLEMENT_DYNAMIC(TAB_TWO, CDialogEx)

TAB_TWO::TAB_TWO(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_TAB_TWO, pParent)
	, m_input_group(0)
	, m_out_group(0)
{

}

TAB_TWO::~TAB_TWO()
{
}

void TAB_TWO::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Radio(pDX, IDC_INPUT_STRING_RADIO, m_input_group);
	DDX_Radio(pDX, IDC_OUT_STRING_RADIO, m_out_group);
}


BEGIN_MESSAGE_MAP(TAB_TWO, CDialogEx)
	ON_BN_CLICKED(IDC_INPUT_STRING_RADIO, &TAB_TWO::OnBnClickedInputgroup)
	ON_BN_CLICKED(IDC_INPUT_HEX_RADIO, &TAB_TWO::OnBnClickedInputgroup)
	ON_BN_CLICKED(IDC_INPUT_BASE64_RADIO, &TAB_TWO::OnBnClickedInputgroup)

	ON_BN_CLICKED(IDC_OUT_STRING_RADIO, &TAB_TWO::OnBnClickedOutgroup)
	ON_BN_CLICKED(IDC_OUT_HEX_RADIO, &TAB_TWO::OnBnClickedOutgroup)
	ON_BN_CLICKED(IDC_OUT_BASE64_RADIO, &TAB_TWO::OnBnClickedOutgroup)

	ON_BN_CLICKED(IDC_ENCODE_BUTTON, &TAB_TWO::OnBnClickedEncodeButton)
	ON_BN_CLICKED(IDC_DECODE_BUTTON, &TAB_TWO::OnBnClickedDecodeButton)


	ON_BN_CLICKED(IDC_SUOHA_BUTTON, &TAB_TWO::OnBnClickedSuohaButton)
	ON_WM_CONTEXTMENU()
END_MESSAGE_MAP()


// TAB_TWO 消息处理程序


BOOL TAB_TWO::OnInitDialog()
{
	CDialogEx::OnInitDialog();
	//初始化组件
	this->m_CryptoModelBom = (CComboBox*)GetDlgItem(IDC_Crypto_COMBO);
	this->m_IvModelBom = (CComboBox*)GetDlgItem(IDC_IV_COMBO);
	this->m_KeyModelBom = (CComboBox*)GetDlgItem(IDC_KEY_COMBO);
	this->m_CryptoModelBom->SetCurSel(0);
	this->m_IvModelBom->SetCurSel(0);
	this->m_KeyModelBom->SetCurSel(0);
	m_input_pEdit = (CEdit*)GetDlgItem(IDC_INPUT_EDIT);
	m_out_pEdit = (CEdit*)GetDlgItem(IDC_OUT_EDIT);
	m_iv_pEdit = (CEdit*)GetDlgItem(IDC_IV_EDIT);
	// 垂直滚动条自动下移
	m_input_pEdit->LineScroll(m_input_pEdit->GetLineCount());
	m_out_pEdit->LineScroll(m_out_pEdit->GetLineCount());
	m_iv_pEdit->SetWindowTextA("0000000000000000");
	
	return TRUE; 
}
#include "AES.hpp"
#include "base64.hpp"
#include "md5.hpp"

void TAB_TWO::OnBnClickedInputgroup()
{
	UpdateData(true);
}

void TAB_TWO::OnBnClickedOutgroup()
{
	UpdateData(true);
}
// 函数：将字符串转化为十六进制格式输出
std::string string_to_hex(const std::string& str) {
	char tempstr[2] = {};
	std::string retbuf;
	for (size_t i = 0; i < str.length(); ++i) {
		// 输出每个字符的十六进制值，设置宽度为2，填充零
		sprintf(tempstr, "%02X", static_cast<unsigned char>(str[i]));
		retbuf.append(tempstr);
		retbuf.append(" ");
	}
	return retbuf;
}
// 函数：将十六进制转化为字符串格式输出
std::string hex_to_string(const std::string& hexStr) {
	std::string result;
	std::string cleanedHexStr = hexStr;

	// 删除所有空格
	cleanedHexStr.erase(std::remove_if(cleanedHexStr.begin(), cleanedHexStr.end(), ::isspace), cleanedHexStr.end());

	size_t len = cleanedHexStr.length();

	// 确保十六进制字符串的长度是偶数
	if (len % 2 != 0) {
		throw std::invalid_argument("Invalid hex string: length must be even.");
	}

	// 逐对处理每两个字符
	for (size_t i = 0; i < len; i += 2) {
		// 解析每对十六进制字符并转换为一个字节
		unsigned char byte = 0;
		for (int j = 0; j < 2; ++j) {
			char hexChar = cleanedHexStr[i + j];
			byte = byte * 16 + (std::isdigit(hexChar) ? hexChar - '0' : std::toupper(hexChar) - 'A' + 10);
		}
		// 将转换后的字节添加到结果字符串中
		result.push_back(byte);
	}

	return result;
}
// 函数：string转wstring
std::wstring stringTowstring(const std::string& wide_str) {
	std::wstring wide_string(wide_str.begin(), wide_str.end());
	return wide_string;
}
// 函数：wstring转string
std::string wstringTostring(const std::wstring& wide_str) {
	std::string wide_string(wide_str.begin(), wide_str.end());
	return wide_string;
}
// 加密
void TAB_TWO::OnBnClickedEncodeButton()
{
	// 0 = ECB; 1 = CBC;2 = CFB;3 = OFB;4 = CTR;
	int Cryptomodel = this->m_CryptoModelBom->GetCurSel();
	int Ivmodel = this->m_IvModelBom->GetCurSel();
	int Keymodel = this->m_KeyModelBom->GetCurSel();
	std::string key, Iv, inputbuf;
	CString key2, Iv2, inputbuf2;
	GetDlgItemTextA(IDC_KEY_EDIT, key2);
	GetDlgItemTextA(IDC_IV_EDIT, Iv2);
	GetDlgItemTextA(IDC_INPUT_EDIT, inputbuf2);
	key = key2.GetBuffer();
	Iv = Iv2.GetBuffer();
	inputbuf = inputbuf2.GetBuffer();
	switch (Ivmodel)
	{
	case STRING:
		break;
	case HEX:
		Iv = hex_to_string(Iv);
		break;
	case BASE64:
		Iv = base64_decode(Iv);
		break;
	default:
		break;
	}
	switch (Keymodel)
	{
	case STRING:
		break;
	case HEX:
		key = hex_to_string(key);
		break;
	case BASE64:
		key = base64_decode(key);
		break;
	default:
		break;
	}
	switch (m_input_group)
	{
	case STRING:
		break;
	case HEX:
		inputbuf = hex_to_string(inputbuf);
		break;
	case BASE64:
		inputbuf = base64_decode(inputbuf);
		break;
	default:
		break;
	}
	try
	{
		//init crypto library
		if (Cryptomodel == ECB)
		{
			AES AESCrypto(key);
			std::string RetStr = AESCrypto.encrypt(inputbuf, Cryptomodel);
			switch (m_out_group)
			{
			case STRING:
				break;
			case HEX:
				RetStr = string_to_hex(RetStr);
				break;
			case BASE64:
				RetStr = base64_encode((unsigned const char*)RetStr.c_str(), RetStr.length());
				break;
			default:
				break;
			}
			// 获取复选框控件对象
			CButton* pCheckBox = (CButton*)GetDlgItem(IDC_OUT_UTF8_CHECK);
			// 获取复选框的当前状态
			BOOL bChecked = pCheckBox->GetCheck();
			if (bChecked)
			{
				RetStr = wstringTostring(std::wstring(RetStr.begin(), RetStr.end()));
			}
			SetDlgItemTextA(IDC_OUT_EDIT, RetStr.c_str());
		}
		else
		{
			AES AESCrypto(key, Iv);
			std::string RetStr = AESCrypto.encrypt(inputbuf, Cryptomodel);
			switch (m_out_group)
			{
			case STRING:
				break;
			case HEX:
				RetStr = string_to_hex(RetStr);
				break;
			case BASE64:
				RetStr = base64_encode((unsigned const char*)RetStr.c_str(), RetStr.length());
				break;
			default:
				break;
			}
			// 获取复选框控件对象
			CButton* pCheckBox = (CButton*)GetDlgItem(IDC_OUT_UTF8_CHECK);
			// 获取复选框的当前状态
			BOOL bChecked = pCheckBox->GetCheck();
			if (bChecked)
			{
				RetStr = wstringTostring(std::wstring(RetStr.begin(), RetStr.end()));
			}
			SetDlgItemTextA(IDC_OUT_EDIT, RetStr.c_str());
		}

	}
	catch (const std::exception& e)
	{
		MessageBox(e.what());
	}
}
// 解密
void TAB_TWO::OnBnClickedDecodeButton()
{
	// 0 = ECB; 1 = CBC;2 = CFB;3 = OFB;4 = CTR;
	int Cryptomodel = this->m_CryptoModelBom->GetCurSel();
	int Ivmodel = this->m_IvModelBom->GetCurSel();
	int Keymodel = this->m_KeyModelBom->GetCurSel();
	std::string key, Iv, inputbuf;
	CString key2, Iv2, inputbuf2;
	GetDlgItemTextA(IDC_KEY_EDIT, key2);
	GetDlgItemTextA(IDC_IV_EDIT, Iv2);
	GetDlgItemTextA(IDC_INPUT_EDIT, inputbuf2);
	key = key2.GetBuffer();
	Iv = Iv2.GetBuffer();
	inputbuf = inputbuf2.GetBuffer();
	switch (Ivmodel)
	{
	case STRING:
		break;
	case HEX:
		Iv = hex_to_string(Iv);
		break;
	case BASE64:
		Iv = base64_decode(Iv);
		break;
	default:
		break;
	}
	switch (Keymodel)
	{
	case STRING:
		break;
	case HEX:
		key = hex_to_string(key);
		break;
	case BASE64:
		key = base64_decode(key);
		break;
	default:
		break;
	}
	m_input_group = 2;
	switch (m_input_group)
	{
	case STRING:
		break;
	case HEX:
		inputbuf = hex_to_string(inputbuf);
		break;
	case BASE64:
		inputbuf = base64_decode(inputbuf);
		break;
	default:
		break;
	}
	// 获取复选框控件对象
	CButton* pCheckBox = (CButton*)GetDlgItem(IDC_INPUT_UTF8_CHECK);
	// 获取复选框的当前状态
	BOOL bChecked = pCheckBox->GetCheck();
	if (bChecked)
	{
		std::string temp = inputbuf;
		temp = wstringTostring(std::wstring(temp.begin(), temp.end()));
		inputbuf = temp.c_str();
	}
	try
	{
		//init crypto library
		if (Cryptomodel == ECB)
		{
			AES AESCrypto(key);
			std::string RetStr = AESCrypto.decrypt(inputbuf, Cryptomodel);
			switch (m_out_group)
			{
			case STRING:
				break;
			case HEX:
				RetStr = string_to_hex(RetStr);
				break;
			case BASE64:
				RetStr = base64_encode((unsigned const char*)RetStr.c_str(), RetStr.length());
				break;
			case UTF8:
				RetStr = wstringTostring(std::wstring(RetStr.begin(), RetStr.end()));
				break;
			default:
				break;
			}
			SetDlgItemTextA(IDC_OUT_EDIT, RetStr.c_str());
		}
		else
		{
			AES AESCrypto(key, Iv);
			std::string RetStr = AESCrypto.decrypt(inputbuf, Cryptomodel);
			switch (m_out_group)
			{
			case STRING:
				break;
			case HEX:
				RetStr = string_to_hex(RetStr);
				break;
			case BASE64:
				RetStr = base64_encode((unsigned const char*)RetStr.c_str(), RetStr.length());
				break;
			case UTF8:
				RetStr = wstringTostring(std::wstring(RetStr.begin(), RetStr.end()));
				break;
			default:
				break;
			}
			SetDlgItemTextA(IDC_OUT_EDIT, RetStr.c_str());
		}

	}
	catch (const std::exception& e)
	{
		MessageBox(e.what());
	}
}
// 过滤不可见字符
bool checkVisibleCharacters(const std::string& input)
{
	for (size_t i = input.size() / 2; i < input.size(); ++i) {
		char ch = input[i];
		// 检查字符是否是可见字符（ASCII 值在 32 到 126 之间）
		if (ch < 32 || ch > 126) {
			return false;  // 如果有不可见字符，返回 false
		}
	}
	return true;  // 如果前五个字符全部是可见字符，返回 true
}
// 梭哈主函数
bool TAB_TWO::suoha(CString key) {
	// 0 = ECB; 1 = CBC;2 = CFB;3 = OFB;4 = CTR;
	int Cryptomodel = this->m_CryptoModelBom->GetCurSel();
	int Ivmodel = this->m_IvModelBom->GetCurSel();
	std::string Iv, inputbuf;
	CString Iv2, inputbuf2;
	GetDlgItemTextA(IDC_IV_EDIT, Iv2);
	GetDlgItemTextA(IDC_INPUT_EDIT, inputbuf2);
	Iv = Iv2.GetBuffer();
	inputbuf = inputbuf2.GetBuffer();
	switch (Ivmodel)
	{
	case STRING:
		break;
	case HEX:
		Iv = hex_to_string(Iv);
		break;
	case BASE64:
		Iv = base64_decode(Iv);
		break;
	default:
		break;
	}
	switch (m_input_group)
	{
	case STRING:
		break;
	case HEX:
		inputbuf = hex_to_string(inputbuf);
		break;
	case BASE64:
		inputbuf = base64_decode(inputbuf);
		break;
	default:
		break;
	}
	// 获取复选框控件对象
	CButton* pCheckBox = (CButton*)GetDlgItem(IDC_INPUT_UTF8_CHECK);
	// 获取复选框的当前状态
	BOOL bChecked = pCheckBox->GetCheck();
	if (bChecked)
	{
		std::string temp = inputbuf;
		temp = wstringTostring(std::wstring(temp.begin(), temp.end()));
		inputbuf = temp.c_str();
	}
	try
	{
		//init crypto library
		if (Cryptomodel == ECB)
		{
			AES AESCrypto(key.GetBuffer());
			std::string RetStr = AESCrypto.decrypt(inputbuf, Cryptomodel);
			switch (m_out_group)
			{
			case STRING:
				break;
			case HEX:
				RetStr = string_to_hex(RetStr);
				break;
			case BASE64:
				RetStr = base64_encode((unsigned const char*)RetStr.c_str(), RetStr.length());
				break;
			case UTF8:
				RetStr = wstringTostring(std::wstring(RetStr.begin(), RetStr.end()));
				break;
			default:
				break;
			}
			if (checkVisibleCharacters(RetStr))
			{
				std::string tempStr = "\r\n明文可能是:";
				std::string keyStr = "\r\nKey可能是:";
				tempStr += RetStr;
				tempStr += keyStr;
				tempStr += key.GetBuffer();
				tempStr.append("\r\n");
				m_out_pEdit->ReplaceSel(tempStr.c_str());
				return true;
			}

		}
		else
		{
			AES AESCrypto(key.GetBuffer(), Iv);
			std::string RetStr = AESCrypto.decrypt(inputbuf, Cryptomodel);
			std::wstring temp = stringTowstring(RetStr);
			switch (m_out_group)
			{
			case STRING:
				break;
			case HEX:
				RetStr = string_to_hex(RetStr);
				break;
			case BASE64:
				RetStr = base64_encode((unsigned const char*)RetStr.c_str(), RetStr.length());
				break;
			case UTF8:
				RetStr = wstringTostring(std::wstring(RetStr.begin(), RetStr.end()));
				break;
			default:
				break;
			}
			if (checkVisibleCharacters(RetStr))
			{
				std::string tempStr = "\r\n明文可能是:";
				std::string keyStr = "\r\nKey可能是:";
				tempStr += RetStr;
				tempStr += keyStr;
				tempStr += key.GetBuffer();
				tempStr.append("\r\n");
				m_out_pEdit->ReplaceSel(tempStr.c_str());
				return true;
			}
		}

	}
	catch (const std::exception& e)
	{
		return false;
	}
	return false;
}
// 梭哈主函数2
void TAB_TWO::suoha2(std::string _path)
{
	m_out_pEdit->SetWindowText("");
	FileHelp file;
	//获取当前目录
	std::string curPath = file.GetProgramDir();
	//字典目录
	curPath += "\\Directory\\";
	//curPath += _path;
	std::string LibraryPath = curPath;
	//正在读取的文件
	std::string curPathtxt;
	//密码
	std::string pw;
	std::string md5;
	long long num = 0;
	if (!fs::exists(LibraryPath) || !fs::is_directory(LibraryPath)) {
		MessageBox("目录不存在或不是有效目录");
		return;
	}
	// 获取当前时间点
	auto start = std::chrono::high_resolution_clock::now();
	for (const auto& entry : fs::directory_iterator(LibraryPath)) {
		if (fs::is_regular_file(entry) && entry.path().extension() == ".txt") {

			m_out_pEdit->ReplaceSel("当前匹配的目录：");
			m_out_pEdit->ReplaceSel(entry.path().string().c_str());
			m_out_pEdit->ReplaceSel("\r\n");
			std::ifstream File(entry.path().string());  // 使用 CT2A 转换 CString 为 std::string
			std::string line;
			while (std::getline(File, line)) {
				// 将每一行的文本插入到 CEdit 控件中
				CString lineCString(line.c_str());
				pw = line.c_str();
				int state = ((CButton*)GetDlgItem(IDC_PW_CHECK))->GetCheck();
				if (!state)
				{
					md5 = get16bitMd5(pw);
					if (suoha(md5.data()))
					{
						m_out_pEdit->ReplaceSel("Key的明文是:");
						m_out_pEdit->ReplaceSel(pw.c_str());
						goto END;
					}
				}
				else
				{
					if (suoha(pw.c_str()))
					{
						m_out_pEdit->ReplaceSel("Key的明文是:");
						m_out_pEdit->ReplaceSel(pw.c_str());
						goto END;
					}
				}
				num++;
			}
		}
	}
END:
	// 获取当前时间点
	auto end = std::chrono::high_resolution_clock::now();
	// 计算时间差
	std::chrono::duration<double> duration = end - start;
	m_out_pEdit->ReplaceSel("\r\n爆破完成");
	m_out_pEdit->ReplaceSel("\r\n共计匹配:");
	m_out_pEdit->ReplaceSel(std::to_string(num).c_str());
	m_out_pEdit->ReplaceSel("次");
	m_out_pEdit->ReplaceSel("\r\n花费时间:");
	m_out_pEdit->ReplaceSel(std::to_string(duration.count()).c_str());
	m_out_pEdit->ReplaceSel("秒");

}
// 梭哈
void TAB_TWO::OnBnClickedSuohaButton()
{
	startThreads();
}
// 消息回调
BOOL TAB_TWO::PreTranslateMessage(MSG* pMsg)
{
	if (pMsg->message == WM_KEYDOWN)
	{
		if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) && (GetAsyncKeyState(_T('A')) & 0x8000))
		{
			CString txt;
			int  start, end;
			// 获取当前焦点控件
			CWnd* pWnd = GetFocus();
			// 判断焦点是否在目标 CEdit 控件上
			CEdit* pEdit1 = (CEdit*)GetDlgItem(IDC_INPUT_EDIT);
			if (pWnd == pEdit1) // 如果焦点在 CEdit 控件上
			{
				pEdit1->GetWindowText(txt);
				pEdit1->GetSel(start, end);
				if (txt.GetLength() == end - start)   // 处于全选状态
				{
					pEdit1->SetSel(-1);          // 取消全选
				}

				else
				{
					pEdit1->SetSel(0, -1);           // 全选
				}
			}
			// 判断焦点是否在目标 CEdit 控件上
			CEdit* pEdit2 = (CEdit*)GetDlgItem(IDC_OUT_EDIT);
			if (pWnd == pEdit2) // 如果焦点在 CEdit 控件上
			{
				pEdit2->GetWindowText(txt);
				pEdit2->GetSel(start, end);
				if (txt.GetLength() == end - start)   // 处于全选状态
				{
					pEdit2->SetSel(-1);          // 取消全选
				}
				else
				{
					pEdit2->SetSel(0, -1);           // 全选
				}
			}
			return  TRUE;
		}
		if (pMsg->wParam == VK_RETURN) // 检查回车键
		{
			// 获取当前焦点控件
			CWnd* pWnd = GetFocus();

			// 判断焦点是否在目标 CEdit 控件上
			CEdit* pEdit1 = (CEdit*)GetDlgItem(IDC_INPUT_EDIT);
			if (pWnd == pEdit1) // 如果焦点在 CEdit 控件上
			{
				// 在 CEdit 中插入回车和换行符
				pEdit1->ReplaceSel(_T("\r\n"));

				return TRUE;  // 阻止默认的回车处理（即失去焦点）
			}
			CEdit* pEdit2 = (CEdit*)GetDlgItem(IDC_OUT_EDIT);
			if (pWnd == pEdit2) // 如果焦点在 CEdit 控件上
			{
				// 在 CEdit 中插入回车和换行符
				pEdit2->ReplaceSel(_T("\r\n"));

				return TRUE;  // 阻止默认的回车处理（即失去焦点）
			}
		}
	}
	return CDialogEx::PreTranslateMessage(pMsg);  // 默认处理其他消息
}
// 右键消息处理
void TAB_TWO::OnContextMenu(CWnd* pWnd, CPoint point)
{
	CWnd* m_IS_RButton = GetDlgItem(IDC_INPUT_STRING_RADIO);
	CWnd* m_IH_RButton = GetDlgItem(IDC_INPUT_HEX_RADIO);
	CWnd* m_IB_RButton = GetDlgItem(IDC_INPUT_BASE64_RADIO);
	CWnd* m_OS_RButton = GetDlgItem(IDC_OUT_STRING_RADIO);
	CWnd* m_OH_RButton = GetDlgItem(IDC_OUT_HEX_RADIO);
	CWnd* m_OB_RButton = GetDlgItem(IDC_OUT_BASE64_RADIO);

	//m_out_pEdit;
	//m_input_pEdit;
	// 判断右键点击的是哪个控件
	if (pWnd == m_IS_RButton)  // 这里m_radioButton是你的CRadioButton控件
	{
		CString Temp;
		std::string _Temp;
		m_input_pEdit->GetWindowTextA(Temp);
		_Temp = Temp.GetBuffer();
		switch (m_input_group)
		{
		case HEX:
			_Temp = hex_to_string(_Temp);
			break;
		case BASE64:
			_Temp = base64_decode(_Temp);
			break;
		default:
			break;
		}
		m_input_pEdit->SetWindowTextA(_Temp.c_str());
	}
	else if (pWnd == m_IH_RButton)
	{
		CString Temp;
		std::string _Temp;
		m_input_pEdit->GetWindowTextA(Temp);
		_Temp = Temp.GetBuffer();
		switch (m_input_group)
		{
		case STRING:
			_Temp = string_to_hex(_Temp);
			break;
		case BASE64:
			_Temp = base64_decode(_Temp);
			_Temp = string_to_hex(_Temp);
			break;
		default:
			break;
		}
		m_input_pEdit->SetWindowTextA(_Temp.c_str());
	}
	else if (pWnd == m_IB_RButton)
	{
		CString Temp;
		std::string _Temp;
		m_input_pEdit->GetWindowTextA(Temp);
		_Temp = Temp.GetBuffer();
		switch (m_input_group)
		{
		case STRING:
			_Temp = base64_encode((unsigned const char*)_Temp.c_str(), _Temp.length());
			break;
		case HEX:
			_Temp = hex_to_string(_Temp);
			_Temp = base64_encode((unsigned const char*)_Temp.c_str(), _Temp.length());
			break;
		default:
			break;
		}
		m_input_pEdit->SetWindowTextA(_Temp.c_str());
	}
	else if (pWnd == m_OS_RButton)
	{
		CString Temp;
		std::string _Temp;
		m_out_pEdit->GetWindowTextA(Temp);
		_Temp = Temp.GetBuffer();
		switch (m_out_group)
		{
		case HEX:
			_Temp = hex_to_string(_Temp);
			break;
		case BASE64:
			_Temp = base64_decode(_Temp);
			break;
		default:
			break;
		}
		m_out_pEdit->SetWindowTextA(_Temp.c_str());
	}
	else if (pWnd == m_OH_RButton)
	{
		CString Temp;
		std::string _Temp;
		m_out_pEdit->GetWindowTextA(Temp);
		_Temp = Temp.GetBuffer();
		switch (m_out_group)
		{
		case STRING:
			_Temp = string_to_hex(_Temp);
			break;
		case BASE64:
			_Temp = base64_decode(_Temp);
			_Temp = string_to_hex(_Temp);
			break;
		default:
			break;
		}
		m_out_pEdit->SetWindowTextA(_Temp.c_str());
	}
	else if (pWnd == m_OB_RButton)
	{
		CString Temp;
		std::string _Temp;
		m_out_pEdit->GetWindowTextA(Temp);
		_Temp = Temp.GetBuffer();
		switch (m_out_group)
		{
		case STRING:
			_Temp = base64_encode((unsigned const char*)_Temp.c_str(), _Temp.length());
			break;
		case HEX:
			_Temp = hex_to_string(_Temp);
			_Temp = base64_encode((unsigned const char*)_Temp.c_str(), _Temp.length());
			break;
		default:
			break;
		}
		m_out_pEdit->SetWindowTextA(_Temp.c_str());
	}
}
