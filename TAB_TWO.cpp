// TAB_TWO.cpp: 实现文件
//

#include "pch.h"
#include "ReFarm.h"
#include "afxdialogex.h"
#include "TAB_TWO.h"

enum _INPUT
{
	STRING = 0,
	HEX = 1,
	BASE64 = 2
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
	CEdit* INPUT_pEdit = (CEdit*)GetDlgItem(IDC_INPUT_EDIT);
	CEdit* OUT_pEdit = (CEdit*)GetDlgItem(IDC_OUT_EDIT);
	// 垂直滚动条自动下移
	INPUT_pEdit->LineScroll(INPUT_pEdit->GetLineCount());
	OUT_pEdit->LineScroll(OUT_pEdit->GetLineCount());
	return TRUE; 
}
#include "AES.hpp"
#include "base64.hpp"
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
void TAB_TWO::OnBnClickedEncodeButton()
{
	// 0 = ECB; 1 = CBC;2 = CFB;3 = OFB;4 = CTR;
	int Cryptomodel = this->m_CryptoModelBom->GetCurSel();
	int Ivmodel = this->m_IvModelBom->GetCurSel();
	int Keymodel = this->m_KeyModelBom->GetCurSel();
	CString key, Iv, inputbuf;
	GetDlgItemTextA(IDC_KEY_EDIT, key);
	GetDlgItemTextA(IDC_IV_EDIT, Iv);
	GetDlgItemTextA(IDC_INPUT_EDIT, inputbuf);
	switch (Ivmodel)
	{
	case STRING:
		break;
	case HEX:
		Iv = hex_to_string(Iv.GetBuffer()).c_str();
		break;
	case BASE64:
		Iv = base64_decode(Iv.GetBuffer(), Iv.GetLength());
		break;
	default:
		break;
	}
	switch (Keymodel)
	{
	case STRING:
		break;
	case HEX:
		key = hex_to_string(key.GetBuffer()).c_str();
		break;
	case BASE64:
		key = base64_decode(key.GetBuffer(), key.GetLength());
		break;
	default:
		break;
	}
	switch (m_input_group)
	{
	case STRING:
		break;
	case HEX:
		inputbuf = hex_to_string(inputbuf.GetBuffer()).c_str();
		break;
	case BASE64:
		inputbuf = base64_decode(inputbuf.GetBuffer(), inputbuf.GetLength());
		break;
	default:
		break;
	}
	try
	{
		//init crypto library
		if (Cryptomodel == ECB)
		{
			AES AESCrypto(key.GetBuffer());
			std::string RetStr = AESCrypto.encrypt(inputbuf.GetBuffer(), Cryptomodel);
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
			SetDlgItemTextA(IDC_OUT_EDIT, RetStr.c_str());
		}
		else
		{
			AES AESCrypto(key.GetBuffer(), Iv.GetBuffer());
			std::string RetStr = AESCrypto.encrypt(inputbuf.GetBuffer(), Cryptomodel);
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
			SetDlgItemTextA(IDC_OUT_EDIT, RetStr.c_str());
		}

	}
	catch (const std::exception& e)
	{
		MessageBox(e.what());
	}
}


void TAB_TWO::OnBnClickedDecodeButton()
{
	// 0 = ECB; 1 = CBC;2 = CFB;3 = OFB;4 = CTR;
	int Cryptomodel = this->m_CryptoModelBom->GetCurSel();
	int Ivmodel = this->m_IvModelBom->GetCurSel();
	int Keymodel = this->m_KeyModelBom->GetCurSel();
	CString key, Iv, inputbuf;
	GetDlgItemTextA(IDC_KEY_EDIT, key);
	GetDlgItemTextA(IDC_IV_EDIT, Iv);
	GetDlgItemTextA(IDC_INPUT_EDIT, inputbuf);
	switch (Ivmodel)
	{
	case STRING:
		break;
	case HEX:
		Iv = hex_to_string(Iv.GetBuffer()).c_str();
		break;
	case BASE64:
		Iv = base64_decode(Iv.GetBuffer(), Iv.GetLength());
		break;
	default:
		break;
	}
	switch (Keymodel)
	{
	case STRING:
		break;
	case HEX:
		key = hex_to_string(key.GetBuffer()).c_str();
		break;
	case BASE64:
		key = base64_decode(key.GetBuffer(), key.GetLength());
		break;
	default:
		break;
	}

	switch (m_input_group)
	{
	case STRING:
		break;
	case HEX:
		inputbuf = hex_to_string(inputbuf.GetBuffer()).c_str();
		break;
	case BASE64:
		inputbuf = base64_decode(inputbuf.GetBuffer(), inputbuf.GetLength());
		break;
	default:
		break;
	}

	try
	{
		//init crypto library
		if (Cryptomodel == ECB)
		{
			AES AESCrypto(key.GetBuffer());
			std::string RetStr = AESCrypto.decrypt(inputbuf.GetBuffer(), Cryptomodel);
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
			SetDlgItemTextA(IDC_OUT_EDIT, RetStr.c_str());
		}
		else
		{
			AES AESCrypto(key.GetBuffer(), Iv.GetBuffer());
			std::string RetStr = AESCrypto.decrypt(inputbuf.GetBuffer(), Cryptomodel);
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
			SetDlgItemTextA(IDC_OUT_EDIT, RetStr.c_str());
		}

	}
	catch (const std::exception& e)
	{
		MessageBox(e.what());
	}
}
