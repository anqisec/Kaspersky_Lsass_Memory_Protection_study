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
