文件版本获取工具：
https://github.com/wqreytuk/Kaspersky_Lsass_Memory_Protection_study/blob/main/get_file_version.zip

关于文件的版本信息，根据[微软官方文档](https://learn.microsoft.com/en-us/windows/win32/api/winver/nf-winver-getfileversioninfoa)，对于有对应mui文件的文件，其版本信息以mui文件中的为准，因此我们在获取lsasrv.dll的版本信息时，
应该指定路径为`C:\windows\system32\lsasrv.dll`

![image](https://github.com/wqreytuk/Kaspersky_Lsass_Memory_Protection_study/assets/48377190/6aebf492-350d-4aa1-8c3d-f7493b59b3f2)


如果将该文件拷贝到其他目录再进行版本获取，可能会得到不同的版本信息，因为它找不到mui文件

比如`C:\windows\system32\lsasrv.dll`的对应mui文件就位于`C:\Windows\System32\en-US\lsasrv.dll.mui`


这里的指令偏移指的是在IDA打开的lsasrv.dll中搜索函数`LsapCreateLsaLogonSession`，在该函数中搜索`LogonSessionList`从而
定位到指令
```
lea     rcx, ?LogonSessionList@@3PAU_LIST_ENTRY@@A ; _LIST_ENTRY near * LogonSessionList
```
记录下该指令地址相对于IDA中lsasrv.dll的基地址的偏移

在实际的代码中我们可以使用该指令的偏移加上lsasrv.dll在lsass.exe进程中的基地址来计算出该指令在内存中的实际地址real_ins_addr

real_ins_addr+7就是下一条指令的地址next_ins_addr，即CPU执行到该指令时RIP寄存器的值

real_ins_addr+3就是符号`LogonSessionList`相对于RIP的偏移，进行反转之后可以得到一个DWORD，与next_ins_addr相加即可得到该符号的
实际地址real_symbol_addr

### LogonSessionList

|  lsasrv.dll_file_version | instruction_offset  |
|---|---|
| 10.0.19041.1 |  0x32BC3 | 
|  10.0.19041.2913 | 0x1FA63  | 
|  6.1.7601.17514 | 0x16150  | 
|  10.0.22621.1 | 0x2D2B3  | 

### hAesKey和h3DesKey

在IDA的`LsaEncryptMemory`函数中搜索上面那俩符号

我们解密不需要初始向量，因为关键部分并不在头部，而初始向量只负责解密头部那几个字节

#### h3DesKey

|  lsasrv.dll_file_version | instruction_offset  |
|---|---|
| 10.0.19041.1 |  0x39E5C | 
|  10.0.19041.2913 | 0x395DC  | 
|  6.1.7601.17514 | 0x111DE  | 
|  10.0.22621.1 | 0x1C55C  | 

#### hAesKey

|  lsasrv.dll_file_version | instruction_offset  |
|---|---|
| 10.0.19041.1 |  0x9E36E | 
|  10.0.19041.2913 | 0x8CA6C  | 
|  6.1.7601.17514 | 0x3261B  | 
|  10.0.22621.1 | 0x4250C  | 
