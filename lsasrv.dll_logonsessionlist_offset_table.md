文件版本获取工具：
https://github.com/wqreytuk/Kaspersky_Lsass_Memory_Protection_study/blob/main/get_file_version.zip


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

|  lsasrv.dll_file_version | instruction_offset  |
|---|---|
| 10.0.19041.508 |  0x32BC3 | 
|  10.0.19041.3271 | 0x1FA63  | 
