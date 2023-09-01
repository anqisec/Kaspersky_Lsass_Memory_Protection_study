#include <Windows.h>
#include <winternl.h>

#define TABLE_LENGTH 1024
DWORD offset_table[TABLE_LENGTH][3] = {
    {0x32BC3,0x39E5C,0x9E36E},
    {0x1FA63,0x395DC,0x8CA6C}
};
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

inline bool _compare_dll_name(WORD len, WCHAR* dll_name) {
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
    //TO_LOWERCASE
}
int main(int argc, char* argv[]) {
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
    while (1) {
        // 获取dll名称，0x58
        DWORD64 _dll_name = _entry_addr + 0x58;
        UNICODE_STRING* dll_name = reinterpret_cast<UNICODE_STRING*>(_dll_name);
        //wprintf(L"dll name: %s\n", dll_name->Buffer);
        // 获取dllbase地址，0x30
        DWORD64 _p_dll_base = _entry_addr + 0x30;
        DWORD64 _dll_base = *(reinterpret_cast<DWORD64*>(_p_dll_base));
        //printf("base address: %p\n", reinterpret_cast<DWORD64*>(_dll_base));

        if (_compare_dll_name(dll_name->Length, dll_name->Buffer)) {

            _kernel32_base_addr = _dll_base;
            break;
        }
        // 获取flink
        _entry_addr = *(reinterpret_cast<DWORD64*>(_entry_addr));
        if (_InLoadOrderModuleList == _entry_addr)break;

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


    // 从文件中读取数组索引值，获取相关符号的偏移量
    
    // 首先要从kernel32中获取createfile和



    return 0;
}
