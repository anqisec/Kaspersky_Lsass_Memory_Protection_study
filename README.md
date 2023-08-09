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

[参考这篇文章](https://ntopcode.wordpress.com/2018/01/16/anatomy-of-the-thread-suspension-mechanism-in-windows-windows-internals/)
