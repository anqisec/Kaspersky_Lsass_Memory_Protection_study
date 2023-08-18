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

之后，从klflt.sys中取出一个函数数组，并通过dispatch_call调用了第104号函数（从0开始）
