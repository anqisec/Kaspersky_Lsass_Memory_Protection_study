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



typedef struct Unknown_CCD68 {
    DWORD   _0h;  	// 8
    DWORD   _4h;  	// 3
    DWORD   _8h;  	// 0
    DWORD   _Ch;  	// 返回之后赋值，APP2_tid，当前的app2的线程id
    BYTE    _10h; 	// 0
    QWORD   _30h; 	// 出来之后给_30h字段赋了个值，App——pid，这里是在返回之后赋的值
    DWORD   _38h; 	// 0
    DWORD   _3Ch; 	// 0xB
    DWORD   _40h; 	// 4
    QWORD   _44h; 	// 3
    DWORD   _4Ch; 	// access_mask  0x1410
    DWORD   _50h; 	// 4
    QWORD   _54h; 	// 9
    DWORD   _5Ch; 	// app2_pid
    DWORD   _60h; 	// SID长度
    DWORD   _64h; 	// 7
    QWORD   _6Ch; 	// SID（这里存的是sid实际的值，并非地址，长度为_60h指示的值）
    // 下一个字段的偏移量是 0x60+poi(_60h)
    DWORD   _78h; 	// 4
    QWORD   _7Ch; 	// 0xA
    DWORD   _84h; 	// lsass_pid
    DWORD   _88h; 	// 4
    QWORD   _8Ch; 	// 0x14
    DWORD   _94h; 	// 0
    DWORD   _98h; 	// 8
    QWORD   _9Ch; 	// 0x4EE
    QWORD   _A4h; 	// rbp+var_30
    DWORD   _ACh; 	// 8
    QWORD   _B0h; 	// 0x4EC
    QWORD   _B8h; 	// rbp+var_28
    DWORD   _C0h; 	// 4
    QWORD   _C4h; 	// 0x4F3
    DWORD   _CCh; 	// lsass父进程PID
    DWORD   _D0h; 	// 4
    QWORD   _D4h; 	// 0x4F2
    DWORD   _DCh; 	// APP2的integrity level
    DWORD   _E0h; 	// 8
    QWORD   _E4h; 	// 0x1D
    QWORD   _ECh; 	// app2的authenticationID
    DWORD   _F4h; 	// 4
    QWORD   _F8h; 	// 0x41
    DWORD   _100h;	// 0
}
