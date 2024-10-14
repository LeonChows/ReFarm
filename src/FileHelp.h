#ifndef _FILE_HELP
#define _FILE_HELP
#include <windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <shellapi.h>
#include <tchar.h>
#include <time.h> 
#include <shlobj.h>
#include <shlwapi.h>
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
//创建构造的时候可以输入要载入的文件进行单文件操作
class FileHelp
{
public:
	FileHelp();
	FileHelp(const char* filename);
	~FileHelp();
	//创建文件 返回文件号 失败返回错误代码  默认创建可写的文件 常用：FILE_ATTRIBUTE_HIDDEN 隐藏文件 FILE_ATTRIBUTE_READONLY 只读文件
	HANDLE CreateFileEX(const char* Filename, //文件名称
						DWORD dwDesiredAccess = GENERIC_WRITE, //请求访问文件或设备的权限
						DWORD dwShareMode = NULL, //文件或设备的请求共享模式
						LPSECURITY_ATTRIBUTES lpSecurityAttributes = nullptr, // 指向一个SECURITY_ATTRIBUTES 结构的指针
						DWORD dwCreationDisposition = OPEN_ALWAYS,//对存在或不存在的文件或设备执行的操作
						DWORD dwFlagsAndAttributes = FILE_ATTRIBUTE_ARCHIVE,//文件或设备属性和标志 标志：该文件应存档。 应用程序使用此属性来标记要备份或删除的文件
						HANDLE	hTemplateFile = nullptr//具有 GENERIC_READ 访问权限的模板文件的有效句柄
						);
	//打开文件目录并且选中文件
	BOOL OpenFolderAndSelectFile(LPCWSTR folderPath, LPCWSTR fileName);
	//文件是否存在 
	BOOL exists_test0(const std::string& name);
	//读入文件
	BOOL ReadFileGoZJJ(HANDLE FileNum, LPVOID& Data, LONGLONG lpFileSize, LPDWORD& ReadNum);
	//写入文件
	BOOL WriteFileGoZJJ(HANDLE FileNum, LPVOID& Data, LONGLONG lpFileSize);
	//文件打开 -1则失败
	HANDLE OpenFileEX(LPCSTR fliedir);
	//获取文件大小
	LONGLONG FileSize(const char* filedir);
	//文件关闭
	BOOL CloseFlie(HANDLE FileNum);
	//内存拷贝到文本
	void write_memory_to_file(const char* memory, size_t size, const char* filename);
	//取资源文件模块地址
	HMODULE GetSelfModuleHandle();
	//释放获取到的资源文件 返回资源文件的数据地址 最后的参数是文件的大小
	LPVOID FreeResFile(unsigned long m_lResourceID, const char* m_strResourceType, unsigned long& dwResSize);
	//获取文件大小
	LONGLONG GetFileSize() {
		return m_FileSize;
	}
	//获取打开文件的文件号
	HANDLE GetFileNum() {
		return m_hFile;
	}
	//创建管理员进程
	BOOL CreateSystemProcess(const char* ProcessPath, const char* StartParameter,HANDLE& _hPocessID);
	//取当前目录
	std::string GetProgramDir();
	//强制删除文件
	BOOL ForcedFileDeletion(std::string FileName);
	//删除目录
	BOOL SHDeleteFolder(LPCTSTR pstrFolder);
	//设置指定文件属性
	BOOL FileBuff(LPCTSTR lpFileName,DWORD dwFileAttributes) {
		return SetFileAttributes(lpFileName, dwFileAttributes);
		/*
		FILE_ATTRIBUTE_ARCHIVE

		该文件是一个存档文件。应用程序使用此属性来备份或移除标记文件。

		FILE_ATTRIBUTE_HIDDEN

		该文件是隐藏的。它不包括在普通的目录列表。

		FILE_ATTRIBUTE_NORMAL

		该文件没有设置其他的属性。此属性仅在单独使用有效。

		FILE_ATTRIBUTE_NOT_CONTENT_INDEXED

		该文件将不被内容索引服务编制索引。

		FILE_ATTRIBUTE_OFFLINE

		该文件的数据不是立即可用。此属性表明文件数据被物理移动到离线存储。此属性用于通过远程存储，分层存储管理软件。应用程序不应随意更改此属性。

		FILE_ATTRIBUTE_READONLY

		该文件是只读的。应用程序可以读取该文件，但不能写入或删除它。

		FILE_ATTRIBUTE_SYSTEM

		该文件是操作系统的一部分，或者完全由它使用。

		FILE_ATTRIBUTE_TEMPORARY

		该文件是被用于暂时存储。文件系统避免写入数据传回海量存储如果有足够的缓存内存可用，因为经常在应用程序删除后不久，这个句柄被关闭的临时文件。在这种情况下，该系统可以完全避免记录的数据。否则，在手柄关闭的数据将被写入。

		如果想去除一个属性的话可以在第二个参数中这么写
		
		-FILE_ATTRIBUTE_HIDDEN
		*/
	}
private:
	//获取到文件大小
	LONGLONG m_FileSize = 0;
	//获取到文件号
	HANDLE m_hFile = 0;
};
#endif // !_PROCESS_MONITOR