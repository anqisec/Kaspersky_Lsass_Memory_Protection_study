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


