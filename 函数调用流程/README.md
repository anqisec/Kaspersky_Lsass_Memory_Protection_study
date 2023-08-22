
首先，函数`sub_140064BD0`通过CallPreOperation被调用

之后该函数调用`sub_140064978`，该函数签名如下：
```c
DWORD sub_140064978(
  QWORD eprocess_of_lsass,
  QWORD nt!PsProcessType,
  QWORD ethread_of_app2,
  DWORD access_mask,
  QWORD &access_mask
  )
```

在函数`sub_140064978`中，先后获取了lsass的PID及其父进程的PID，和app2的PID进行比较

最后调用了函数`sub_1400C9E74`，该函数的签名如下：

```c
DWORD sub_1400C9E74(
  DWORD access_mask,
  QWORD &access_mask,
  QWORD &app2_pid,
  QWORD &lsass_pid,
  DWORD 3(hard_coded)
)
```

在该函数中，`sub_1400CCB80`被调用，其签名如下：

```c
QWORD sub_1400CCB80(
  DWORD access_mask,
  QWORD &lsass_pid,
  DWORD 3(hard_coded)
)
```

该函数中调用`sub_1400CDC28`，签名如下：

```
DWORD sub_1400CDC28(
  DWROD 0(hard_coded),
  QWORD &SID
)
```

该函数会返回APP2进程的用户SID，因此我将其重命名为`Get_APP2_User_SID_sub_1400CDC28`

紧接着，该函数又调用了`sub_1400CDBB4`，签名如下：
```c
VOID sub_1400CDBB4(
  QWORD &AuthenticationId
)
```

这个函数用于从app2的PrimaryToken中获取AuthenticationID，这个ID用于标识一个logonsession，因此我讲这个函数重命名为
```
Get_APP2_Authentication_Id_sub_1400CDBB4
```

之后，从klflt.sys中取出一个函数数组，并通过dispatch_call调用了第104号函数（从0开始）：`sub_18003E1B0`，函数签名如下：
```
VOID sub_18003E1B0(
  QWORD lsass_pid,
  QWORD &0(hard_coded)
)
```

该函数将第2个参数变成`sub_18004012C`的第3个参数，并增加了第4个参数中，所以该函数的签名为
```c
VOID sub_18004012C(
  QWORD lsass_pid,
  DWORD 0(hard_coded),
  QWORD &0(hard_coded),
  BYTE 1(hard_coded)
)
```

在该函数中`sub_18004033C`被调用，签名如下：
```
QWORD sub_18004033C(
  QWORD lsass_pid,
  QWORD 0(hard_coded),
  BYTE 1(hard_coded),
)
```

该函数对lsass_pid进行了如下操作：
```c
lsass_pid = lsass_pid & 0xFFFFFFFF;
lsass_pid = lsass_pid >> 2;
edx = lsass_pid * 0x9E370001 & xFFFFFFFF;
edx = reverse_byte(edx);
```

然后调用了函数`sub_180002200`，签名如下：
```
QWORD sub_180002200(
  QWORD rcx(value_from_memory_klflt),
  DWORD edx(lsass_pid_transformer),
  QWORD r8(OUT)
)
```

其中rcx来自`poi(klflt+0x89df8)`


后面可以考虑在这个内存位置先内存访问断点

在最终返回到klif驱动之后，会再次通过dispatch call进入到klflt驱动的函数当中，这次传进去的是app2的pid和bugcheckparam

调用的函数为`sub_18003E1A0`，之前调用的是`sub_18003E1B0`，两者的区别如下：


```asm
sub_18003E1B0 proc near
mov     r8, rdx
mov     r9b, 1
xor     edx, edx
jmp     sub_18004012C 
sub_18003E1B0 endp
```

```asm
sub_18003E1A0 proc near
mov     r8, rdx
xor     r9d, r9d
xor     edx, edx
jmp     sub_18004012C
sub_18003E1A0 endp
```


唯一的区别就是第四个参数，一个是1一个是0

在第二次调用中，调用到了第一次不曾调用过的函数`sub_18003AD30`，在执行到该函数的`call`指令时，线程
发生了切换，调用栈如下：

```asm
kd> k
 # Child-SP          RetAddr               Call Site
00 ffff9884`48a66d18 fffff802`5745a8d4     klflt!ComrUnregisterProvider+0x21723
01 ffff9884`48a66d20 fffff802`57440268     klflt!ComrUnregisterProvider+0x1de54
02 ffff9884`48a66d50 fffff802`5744086c     klflt!ComrUnregisterProvider+0x37e8
03 ffff9884`48a66d80 fffff802`5744074e     klflt!ComrUnregisterProvider+0x3dec
04 ffff9884`48a66e40 fffff802`57e34f29     klflt!ComrUnregisterProvider+0x3cce
05 ffff9884`48a66e80 fffff802`57e5945e     klgse+0x24f29
06 ffff9884`48a66ed0 fffff802`57c06cfd     klgse+0x4945e
07 ffff9884`48a66fd0 fffff802`57c06c5a     klhk+0x6cfd
08 ffff9884`48a67080 fffff802`57c06cfd     klhk+0x6c5a
09 ffff9884`48a670b0 fffff802`57c21785     klhk+0x6cfd
0a ffff9884`48a67160 fffff802`57c19840     klhk+0x21785
0b ffff9884`48a67240 fffff802`51c10906     klhk+0x19840
0c ffff9884`48a672a0 fffff802`51c101e6     nt!IopXxxControlFile+0x706
0d ffff9884`48a673e0 fffff802`51a0f8f5     nt!NtDeviceIoControlFile+0x56
0e ffff9884`48a67450 00007ffe`9432d0c4     nt!KiSystemServiceCopyEnd+0x25
0f 00000061`fef1f298 00007ffe`94227a74     ntdll!NtDeviceIoControlFile+0x14
10 00000061`fef1f2a0 00000000`00000020     0x00007ffe`94227a74
11 00000061`fef1f2a8 00000214`7c00334f     0x20
12 00000061`fef1f2b0 00000000`0000002d     0x00000214`7c00334f
13 00000061`fef1f2b8 00000000`00000000     0x2d

```

可以看到之前没有见到过的驱动`klhk.sys`和`klgse.sys`，而且调用栈中有`ntdll!NtDeviceIoControlFile`，说明此时存在r0和r3的通信

查看当前的peb信息，发现进程为`C:\WINDOWS\system32\dwm.exe`
