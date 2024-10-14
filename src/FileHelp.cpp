#include "FileHelp.h"
FileHelp::FileHelp() {

}
FileHelp::FileHelp(const char* filename) {
	m_FileSize = FileHelp::FileSize(filename);
	m_hFile = FileHelp::OpenFileEX(filename);
}
FileHelp::~FileHelp() {

}
//创建文件
HANDLE FileHelp::CreateFileEX(const char* Filename, //文件名称
	DWORD dwDesiredAccess , //请求访问文件或设备的权限
	DWORD dwShareMode , //文件或设备的请求共享模式
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, // 指向一个SECURITY_ATTRIBUTES 结构的指针
	DWORD dwCreationDisposition,//对存在或不存在的文件或设备执行的操作
	DWORD dwFlagsAndAttributes,//文件或设备属性和标志 标志：该文件应存档。 应用程序使用此属性来标记要备份或删除的文件
	HANDLE hTemplateFile//具有 GENERIC_READ 访问权限的模板文件的有效句柄
) 
{

	HANDLE Temp = CreateFileA(
				Filename,
				dwDesiredAccess,
				dwShareMode, lpSecurityAttributes,
				dwCreationDisposition,
				dwFlagsAndAttributes, hTemplateFile);//创建IO文件设备
	if (Temp == INVALID_HANDLE_VALUE)return (HANDLE)GetLastError();
	return Temp;
}
BOOL FileHelp::OpenFolderAndSelectFile(LPCWSTR folderPath, LPCWSTR fileName)
{
	// 解析文件夹路径
	PIDLIST_ABSOLUTE pidlFolder;
	HRESULT hr = SHParseDisplayName(folderPath, nullptr, &pidlFolder, 0, nullptr);
	if (SUCCEEDED(hr))
	{
		// 解析文件路径
		PIDLIST_RELATIVE pidlFile;
		hr = SHParseDisplayName(fileName, nullptr, &pidlFile, 0, nullptr);
		if (SUCCEEDED(hr))
		{
			// 将文件 PIDL 放入数组中
			LPCITEMIDLIST rgPidl[] = { pidlFile };

			// 打开文件夹并选择文件
			hr = SHOpenFolderAndSelectItems(pidlFolder, ARRAYSIZE(rgPidl), rgPidl, 0);
			if (FAILED(hr))
			{
				return 0;
			}
			// 释放文件 PIDL
			CoTaskMemFree(pidlFile);
		}
		else
		{
			return 0;
		}
		// 释放文件夹 PIDL
		CoTaskMemFree(pidlFolder);
	}
	else
	{
		return 0;
	}
}
//文件是否存在
BOOL FileHelp::exists_test0(const std::string& name) {
	std::ifstream f(name.c_str());
	return f.good();
}
//读入文件
BOOL FileHelp::ReadFileGoZJJ(HANDLE FileNum, LPVOID& Data, LONGLONG lpFileSize, LPDWORD& ReadNum)
{
	if (FileNum == nullptr)return false;//是否打开文件
	memset(Data, 0, lpFileSize);//清零操作
	return ReadFile(FileNum, Data, lpFileSize, ReadNum, 0);//数据读入到Data 返回读文件结果
}
//写入文件
BOOL FileHelp::WriteFileGoZJJ(HANDLE FileNum, LPVOID& Data, LONGLONG lpFileSize) {
	LPVOID buffer = (LPVOID)malloc(lpFileSize);//申请缓冲区空间
	if (FileNum == nullptr)return false; //是否打开文件
	memset(buffer, 0, lpFileSize);//清零操作
	RtlMoveMemory(buffer, Data, lpFileSize, NULL, NULL);//复制字节
	WriteFile(FileNum, buffer, lpFileSize, NULL, NULL);//写到字节
	free(buffer);
	return true;
}
//文件打开 -1则失败
HANDLE FileHelp::OpenFileEX(LPCSTR fliedir) {
	return CreateFileA(fliedir, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, 0);
}
//获取文件大小
LONGLONG FileHelp::FileSize(const char* filedir) {
	DWORD num1;
	LPDWORD num2 = nullptr;
	LONGLONG num3;
	num1 = GetCompressedFileSizeA(filedir, num2);
	if (num1 == -1 && num2 == 0)return 0;
	if (num1 < 0)
	{
		num1 &= 2147483647;
		num3 = (DWORD)(num2) * 4294967296 + 2147483648 + num1;
	}
	else
	{
		num3 = (DWORD)(num2) * 4294967296 + num1;
	}
	return num3;
}
//文件关闭
BOOL FileHelp::CloseFlie(HANDLE FileNum) {
	return CloseHandle(FileNum);
}
//内存拷贝到文本
void FileHelp::write_memory_to_file(const char* memory, size_t size, const char* filename)
{
	// 创建输出文件流对象
	std::ofstream ofs(filename, std::ios::binary);

	// 将内存中的数据写入到文件中
	ofs.write(memory, size);

	// 关闭文件流
	ofs.close();
}
//取资源文件模块地址
HMODULE FileHelp::GetSelfModuleHandle()
{
	try
	{
#ifdef _USER_RELEASEDLL_
		//如果释放的帮助类定义在DLL中，将调用下面的方式获取基址
		MEMORY_BASIC_INFORMATION mbi;
		return ((::VirtualQuery((LPCVOID)&CReleaseDLL::GetSelfModuleHandle, &mbi, sizeof(mbi)) != 0)
			? (HMODULE)mbi.AllocationBase : NULL);
#else
		//如果直接定义在exe本身的代码中
		return ::GetModuleHandle(NULL);
#endif
	}
	catch (...)
	{
		return NULL;
	}

}
//释放获取到的资源文件 返回资源文件的数据地址 最后的参数是文件的大小
LPVOID FileHelp::FreeResFile(unsigned long m_lResourceID, const char* m_strResourceType, unsigned long& dwResSize)
{
	HMODULE m_hModule = GetSelfModuleHandle();
	//查找资源
	HRSRC hResID = ::FindResourceA(m_hModule, MAKEINTRESOURCEA(m_lResourceID), m_strResourceType);
	DWORD error = GetLastError();
	//加载资源  
	HGLOBAL hRes = ::LoadResource(m_hModule, hResID);
	//锁定资源
	LPVOID pRes = ::LockResource(hRes);
	//得到待释放资源文件大小 
	if (pRes == NULL)return nullptr;
	dwResSize = ::SizeofResource(m_hModule, hResID);
	return pRes;
}
//获取当前目录
std::string FileHelp::GetProgramDir()
{
	char exeFullPath[MAX_PATH]; // Full path
	std::string strPath = "";

	GetModuleFileNameA(NULL, exeFullPath, MAX_PATH);
	strPath = (std::string)exeFullPath;    // Get full path of the file
	//std::cout << strPath << std::endl;
	int pos = strPath.find_last_of('\\', strPath.length());
	return strPath.substr(0, pos);  // Return the directory without the file name
}
//创建管理员进程 第一个参数留空为创建自身的管理员进程
BOOL FileHelp::CreateSystemProcess(const char* ProcessPath, const char* StartParameter, HANDLE& _hPocessID){
	//包含 ShellExecuteEx 使用的信息。
	SHELLEXECUTEINFOA sei;
	ZeroMemory(&sei, sizeof SHELLEXECUTEINFO);//清零
	sei.cbSize = sizeof SHELLEXECUTEINFOA;
	sei.lpParameters = StartParameter;
	sei.lpVerb = "runas"; //关键点
	sei.nShow = SW_SHOWDEFAULT;
	sei.fMask = SEE_MASK_FLAG_DDEWAIT | SEE_MASK_NOCLOSEPROCESS;
	if (ProcessPath == "")
	{
		//获取当前文件的路径
		char path[MAX_PATH];
		GetModuleFileNameA(NULL, path, MAX_PATH);
		sei.lpFile = path;
	}
	else
	{
		sei.lpFile = ProcessPath;
	}
	if (ShellExecuteExA(&sei) == 0)
	{
		return false;
	}
	_hPocessID = sei.hProcess;
	return true;
}
//删除目录
BOOL FileHelp::SHDeleteFolder(LPCTSTR pstrFolder)
{
	int iPathLen = _tcslen(pstrFolder);
	TCHAR tczFolder[MAX_PATH + 1];
	SHFILEOPSTRUCT FileOp;

	if ((NULL == pstrFolder))
	{
		return FALSE;
	}


	if (iPathLen >= MAX_PATH)
	{
		return FALSE;
	}

	/*确保目录的路径以2个\0结尾*/
	ZeroMemory(tczFolder, (MAX_PATH + 1) * sizeof(CHAR));
	_tcscpy(tczFolder, pstrFolder);
	tczFolder[iPathLen] = _T('\0');
	tczFolder[iPathLen + 1] = _T('\0');

	ZeroMemory(&FileOp, sizeof(SHFILEOPSTRUCT));
	FileOp.fFlags |= FOF_SILENT;            //不显示进度
	FileOp.fFlags |= FOF_NOERRORUI;         //不报告错误信息
	FileOp.fFlags |= FOF_NOCONFIRMATION;    //直接删除，不进行确认
	FileOp.hNameMappings = NULL;
	FileOp.hwnd = NULL;
	FileOp.lpszProgressTitle = NULL;
	FileOp.wFunc = FO_DELETE;
	FileOp.pFrom = tczFolder;               //要删除的目录，必须以2个\0结尾
	FileOp.pTo = NULL;

	FileOp.fFlags &= ~FOF_ALLOWUNDO;       //直接删除，不放入回收站

	/*删除目录*/
	if (0 == SHFileOperation(&FileOp))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}
//强制删除文件
BOOL FileHelp::ForcedFileDeletion(std::string FileName) {
	std::string TempFileName;//临时文件名字
	SECURITY_ATTRIBUTES lpSecurityAttributes = { 0 };//栈缓冲区指针
	char Tempstr[MAX_PATH];//字符缓冲区
	char strTmpPath[MAX_PATH];//临时目录缓冲区
	GetTempPath(sizeof(strTmpPath), strTmpPath);//获取临时目录
	time_t now = time(NULL);//获取当前系统时间
	tm* tm_t = localtime(&now);//转为本地时间结构体
	sprintf_s(Tempstr, "%s%d%d%d", strTmpPath, tm_t->tm_sec, tm_t->tm_sec, tm_t->tm_sec);//取出随机文件名
	TempFileName = Tempstr;//赋值
	CreateDirectoryA(TempFileName.c_str(), &lpSecurityAttributes);
	char str[MAX_PATH] = { 0 };
	strcpy(str, TempFileName.c_str());
	strcat(str, "\\....\\");
	CreateDirectoryA(str, &lpSecurityAttributes);
	char str1[MAX_PATH] = { 0 };
	strcpy(str1, TempFileName.c_str());
	strcat(str1, "\\....\\Client Server Runtime Process");
	MoveFileA(FileName.c_str(), str1);
	char str2[MAX_PATH] = { 0 };
	strcpy(str2, TempFileName.c_str());
	strcat(str2, "\\Client Server Runtime Process");
	MoveFileA(str, str2);
	//删除目录
	SHDeleteFolder(TempFileName.c_str());
	return !exists_test0(FileName);
}