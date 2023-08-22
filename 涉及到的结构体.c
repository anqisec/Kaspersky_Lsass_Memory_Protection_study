/*
关于PreOperation中穿进去的两个参数
rcx_1
rdx_2


推测rdx_2为一个结构体

*/
typedef struct rdx_2 {
    DWORD dword_0h;         // 偏移量0x0，值为1
    DWORD dword_4h;         // 偏移量0x4，值为0    当我们要打开的进程是一个普通进程的时候，这个地方的值就是1，直接就跳走了，没有那么多复杂的检查要走
    QWORD dword_8h;         // 偏移量0x8，里面存的也是一个地址，EPROCESS结构体，对应我们要打开的进程
                            // 在本次研究中，对应的是lsass.exe进程
    QWORD qword_10h;        // 偏移量0x10，里面存的是一个地址，nt!PsProcessType
    ...
    QWORD qword_20h;        // 偏移量0x20，是一个地址
                            // 这个地址指向另一个结构体，我在里面看到了access mask
}

typedef struct _QWORD_20H {
    DWORD dword_0h;         // 当前实例中为0x1410，就是我们在调用OpenProcess时指定的权限
    DWORD dword_1h;         // 当前实例中为0x1410

/*
2: kd> dd /c 1  ffff8989f0ce7068
ffff8989`f0ce7068  00001410
ffff8989`f0ce706c  00001410
*/
}
