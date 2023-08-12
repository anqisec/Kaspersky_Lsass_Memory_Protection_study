; 参数传入情况：
; 1p
; 	lsass.exe进程的handle
; 2p
; 	DesiredAccess    0x10     PROCESS_VM_READ
; 3p
; 	PsProcessType
; 	dt_object_type poi(nt!PsProcessType)
; 4p
; 	PreviousMode
; 5p
; 	TAG    mVmM
; 6p
; 	传出参数？
; 	(PVOID *)&ProcessObject
; 7p
; 	0
; 8p
; 	0
0: kd> uf nt!ObpReferenceObjectByHandleWithTag 
nt!ObpReferenceObjectByHandleWithTag:
fffff802`0cb38260 44884c2420      mov     byte ptr [rsp+20h],r9b
fffff802`0cb38265 4c89442418      mov     qword ptr [rsp+18h],r8
fffff802`0cb3826a 89542410        mov     dword ptr [rsp+10h],edx
fffff802`0cb3826e 53              push    rbx
fffff802`0cb3826f 56              push    rsi
fffff802`0cb38270 57              push    rdi
fffff802`0cb38271 4154            push    r12
fffff802`0cb38273 4155            push    r13
fffff802`0cb38275 4156            push    r14
fffff802`0cb38277 4883ec58        sub     rsp,58h
; App2的ETHREAD
fffff802`0cb3827b 654c8b342588010000 mov   r14,qword ptr gs:[188h]
fffff802`0cb38284 488bf1          mov     rsi,rcx
fffff802`0cb38287 4c8ba424b8000000 mov     r12,qword ptr [rsp+0B8h]
fffff802`0cb3828f 33c9            xor     ecx,ecx
; 6p    rsp+38
fffff802`0cb38291 4c8bac24c8000000 mov     r13,qword ptr [rsp+0C8h]
fffff802`0cb38299 498bd8          mov     rbx,r8
fffff802`0cb3829c 888c24b8000000  mov     byte ptr [rsp+0B8h],cl
; [r14+0B8h]是_KPROCESS的地址
fffff802`0cb382a3 498bbeb8000000  mov     rdi,qword ptr [r14+0B8h]
fffff802`0cb382aa 4889bc2490000000 mov     qword ptr [rsp+90h],rdi
fffff802`0cb382b2 49890c24        mov     qword ptr [r12],rcx
; if(6p==NULL)
fffff802`0cb382b6 4d85ed          test    r13,r13
fffff802`0cb382b9 0f85f5030000    jne     nt!ObpReferenceObjectByHandleWithTag+0x454 (fffff802`0cb386b4)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x5f:
; handle_of_lsass
fffff802`0cb382bf 488bc6          mov     rax,rsi
fffff802`0cb382c2 48896c2450      mov     qword ptr [rsp+50h],rbp
; 后面的操作应该可以和我在下面这篇文章中看到的handle寻找方式对得上
; https://imphash.medium.com/windows-process-internals-a-few-concepts-to-know-before-jumping-on-memory-forensics-part-5-a-2368187685e
; 1111111111111111111111111111111110000000000000000000000000000000
; 3210987654321098765432109876543210987654321098765432109876543210
; handle的低21bit被清空
; handle的值一般不会太大，所以这里操作完之后基本上就变成0了，所以不跳
fffff802`0cb382c7 482500000080    and     rax,0FFFFFFFF80000000h
fffff802`0cb382cd 4c897c2448      mov     qword ptr [rsp+48h],r15
fffff802`0cb382d2 483d00000080    cmp     rax,0FFFFFFFF80000000h
fffff802`0cb382d8 0f840c020000    je      nt!ObpReferenceObjectByHandleWithTag+0x28a (fffff802`0cb384ea)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x7e:
; 0: kd> dd /c 1 nt!MmVerifierData L1
; fffff802`0c96b000  00000000
; 不跳
fffff802`0cb382de f705182de3ff00010000 test dword ptr [nt!MmVerifierData (fffff802`0c96b000)],100h
fffff802`0cb382e8 0f858c6e1100    jne     nt!ObpReferenceObjectByHandleWithTag+0x116f1a (fffff802`0cc4f17a)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x8e:
; KernelApcDisable，一开始这个值是0，dec之后就变成0xFFFF了
fffff802`0cb382ee 6641ff8ee4010000 dec     word ptr [r14+1E4h]
; [r14+220h]是_KPROCESS地址，这两者是一样的
fffff802`0cb382f6 493bbe20020000  cmp     rdi,qword ptr [r14+220h]
fffff802`0cb382fd 0f8521040000    jne     nt!ObpReferenceObjectByHandleWithTag+0x4c4 (fffff802`0cb38724)  Branch

nt!ObpReferenceObjectByHandleWithTag+0xa3:
; EPROCESS的Flags字段
; https://blog.csdn.net/ma_de_hao_mei_le/article/details/132233733?spm=1001.2014.3001.5502
fffff802`0cb38303 8b8704030000    mov     eax,dword ptr [rdi+304h]
; 第26bit位为1，不跳
fffff802`0cb38309 0fbae01a        bt      eax,1Ah
fffff802`0cb3830d 0f83706f1100    jae     nt!ObpReferenceObjectByHandleWithTag+0x117023 (fffff802`0cc4f283)  Branch

nt!ObpReferenceObjectByHandleWithTag+0xb3:
; EPROCESS的ObjectTable字段，类型为_HANDLE_TABLE
; _HANDLE_TABLE中有一个字段HandleTableList，类型为LIST_ENTRY
; 可以在windbg中使用如下命令遍历HandleTableList
; !list -x "dt_HANDLE_TABLE @$extret-18" 0xfffff802`0cdf4018
; 这样我们就可以得到所有的handle_table
; _HANDLE_TABLE的字段TableCode可以帮助我们定位到handle_table_enrty，来找到当前进程掌握的所有handle
fffff802`0cb38313 4c8b8f18040000  mov     r9,qword ptr [rdi+418h]

nt!ObpReferenceObjectByHandleWithTag+0xba:
fffff802`0cb3831a 4c898c24c8000000 mov     qword ptr [rsp+0C8h],r9
fffff802`0cb38322 4d85c9          test    r9,r9
fffff802`0cb38325 0f84586f1100    je      nt!ObpReferenceObjectByHandleWithTag+0x117023 (fffff802`0cc4f283)  Branch

nt!ObpReferenceObjectByHandleWithTag+0xcb:
; 两者并不相等
fffff802`0cb3832b 4c3b0de609e3ff  cmp     r9,qword ptr [nt!ObpKernelHandleTable (fffff802`0c968d18)]
fffff802`0cb38332 0f845a040000    je      nt!ObpReferenceObjectByHandleWithTag+0x532 (fffff802`0cb38792)  Branch

nt!ObpReferenceObjectByHandleWithTag+0xd8:
; handle的合法性检测
fffff802`0cb38338 f7c6fc030000    test    esi,3FCh
fffff802`0cb3833e 0f8445040000    je      nt!ObpReferenceObjectByHandleWithTag+0x529 (fffff802`0cb38789)  Branch

nt!ObpReferenceObjectByHandleWithTag+0xe4:
fffff802`0cb38344 488bd6          mov     rdx,rsi
fffff802`0cb38347 498bc9          mov     rcx,r9
; 就传进去两个参数
; 1p
; 	OBJECT_TABLE(HANDLE_TABLE)
; 2p
; 	handle_of_lsass
; 其实我们只需要把函数nt!ExpLookupHandleTableEntry逆向掉，就可以得到从EPROCESS获取所有HANDLE的方法
fffff802`0cb3834a e801050000      call    nt!ExpLookupHandleTableEntry (fffff802`0cb38850)
; 返回值    TableCode+(handle_of_lsass>>2<<2)*4
fffff802`0cb3834f 488bf8          mov     rdi,rax
fffff802`0cb38352 4885c0          test    rax,rax
fffff802`0cb38355 0f842e040000    je      nt!ObpReferenceObjectByHandleWithTag+0x529 (fffff802`0cb38789)  Branch

nt!ObpReferenceObjectByHandleWithTag+0xfb:
; 这个指令是在操作高速缓存，并不需要太关心这个东西
fffff802`0cb3835b 0f0d08          prefetchw [rax]
fffff802`0cb3835e 488b08          mov     rcx,qword ptr [rax]
fffff802`0cb38361 488b6808        mov     rbp,qword ptr [rax+8]
fffff802`0cb38365 48896c2438      mov     qword ptr [rsp+38h],rbp
fffff802`0cb3836a 48894c2430      mov     qword ptr [rsp+30h],rcx
fffff802`0cb3836f 4c8b7c2430      mov     r15,qword ptr [rsp+30h]
fffff802`0cb38374 49f7c7feff0100  test    r15,1FFFEh
; 不跳
fffff802`0cb3837b 0f84ff010000    je      nt!ObpReferenceObjectByHandleWithTag+0x320 (fffff802`0cb38580)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x121:
; r15b是r15的最低8bit
fffff802`0cb38381 410fb6c7        movzx   eax,r15b
; 0xFF 取反 0
fffff802`0cb38385 f6d0            not     al
fffff802`0cb38387 a801            test    al,1
fffff802`0cb38389 0f8554030000    jne     nt!ObpReferenceObjectByHandleWithTag+0x483 (fffff802`0cb386e3)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x12f:
fffff802`0cb3838f 498d5ffe        lea     rbx,[r15-2]
fffff802`0cb38393 488bcd          mov     rcx,rbp
fffff802`0cb38396 498bc7          mov     rax,r15
fffff802`0cb38399 488bd5          mov     rdx,rbp
; 两者是相等的，[rdi]和rax
; rbx的值被交换到了这块内存中，就是原始值-2
fffff802`0cb3839c f0480fc70f      lock cmpxchg16b oword ptr [rdi]
fffff802`0cb383a1 4c8bf8          mov     r15,rax
fffff802`0cb383a4 4889442430      mov     qword ptr [rsp+30h],rax
fffff802`0cb383a9 488bea          mov     rbp,rdx
fffff802`0cb383ac 4889542438      mov     qword ptr [rsp+38h],rdx
; 不跳
fffff802`0cb383b1 0f855b030000    jne     nt!ObpReferenceObjectByHandleWithTag+0x4b2 (fffff802`0cb38712)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x157:
; poi(TableCode+(handle_of_lsass>>2<<2)*4)
fffff802`0cb383b7 488bc8          mov     rcx,rax
; poi(TableCode+(handle_of_lsass>>2<<2)*4)>>1
fffff802`0cb383ba 48d1e9          shr     rcx,1
fffff802`0cb383bd 6683f910        cmp     cx,10h
; 不跳
fffff802`0cb383c1 0f84e7030000    je      nt!ObpReferenceObjectByHandleWithTag+0x54e (fffff802`0cb387ae)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x167:
fffff802`0cb383c7 488bd8          mov     rbx,rax
; sar是算术位移指令，会保存操作数的标志位，如果rbx原本就是负数，那么高位补1，否则补0
; rbx的最高位是1，也就是说rbx是负数，那么就是补1
fffff802`0cb383ca 48c1fb10        sar     rbx,10h
; 算术位移完成之后，再丢掉最低的4bit
fffff802`0cb383ce 4883e3f0        and     rbx,0FFFFFFFFFFFFFFF0h

nt!ObpReferenceObjectByHandleWithTag+0x172:
; =0
fffff802`0cb383d2 833d2b8cecff00  cmp     dword ptr [nt!ObpTraceFlags (fffff802`0ca01004)],0
fffff802`0cb383d9 0f85dc6d1100    jne     nt!ObpReferenceObjectByHandleWithTag+0x116f5b (fffff802`0cc4f1bb)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x17f:
; 3p    nt!PsProcessType
fffff802`0cb383df 488b9424a0000000 mov     rdx,qword ptr [rsp+0A0h]
; 暂时不清楚这是个什么东西
fffff802`0cb383e7 4c8d0d120cadff  lea     r9,[nt!MmSetTrimWhileAgingState <PERF> (nt+0x0) (fffff802`0c609000)]
fffff802`0cb383ee 488bc3          mov     rax,rbx
fffff802`0cb383f1 48c1e808        shr     rax,8
fffff802`0cb383f5 0fb6c8          movzx   ecx,al
fffff802`0cb383f8 0fb64318        movzx   eax,byte ptr [rbx+18h]
fffff802`0cb383fc 33c8            xor     ecx,eax
fffff802`0cb383fe 0fb6053b9fecff  movzx   eax,byte ptr [nt!ObHeaderCookie (fffff802`0ca02340)]
fffff802`0cb38405 33c8            xor     ecx,eax
fffff802`0cb38407 4885d2          test    rdx,rdx
fffff802`0cb3840a 0f8434010000    je      nt!ObpReferenceObjectByHandleWithTag+0x2e4 (fffff802`0cb38544)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x1b0:
fffff802`0cb38410 0fb64228        movzx   eax,byte ptr [rdx+28h]
fffff802`0cb38414 3bc1            cmp     eax,ecx
fffff802`0cb38416 0f8528010000    jne     nt!ObpReferenceObjectByHandleWithTag+0x2e4 (fffff802`0cb38544)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x1bc:
fffff802`0cb3841c 81e5ffffff01    and     ebp,1FFFFFFh
; 4p PreviousMode    1
fffff802`0cb38422 80bc24a800000000 cmp     byte ptr [rsp+0A8h],0
fffff802`0cb3842a 744a            je      nt!ObpReferenceObjectByHandleWithTag+0x216 (fffff802`0cb38476)  Branch

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
; 从windbg中来看，ExpLookupHandleTableEntry函数的返回值是一个 nt!_andle_table_entry类型
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
; 跳
fffff802`0cb38437 0f8518030000    jne     nt!ObpReferenceObjectByHandleWithTag+0x4f5 (fffff802`0cb38755)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x1dd:
fffff802`0cb3843d 0fb6431a        movzx   eax,byte ptr [rbx+1Ah]
fffff802`0cb38441 a840            test    al,40h
fffff802`0cb38443 7431            je      nt!ObpReferenceObjectByHandleWithTag+0x216 (fffff802`0cb38476)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x1e5:
fffff802`0cb38445 0fb6c0          movzx   eax,al
fffff802`0cb38448 488bcb          mov     rcx,rbx
fffff802`0cb3844b 83e07f          and     eax,7Fh
fffff802`0cb3844e 420fb68408001a3600 movzx eax,byte ptr [rax+r9+361A00h]
fffff802`0cb38457 482bc8          sub     rcx,rax
fffff802`0cb3845a 488b01          mov     rax,qword ptr [rcx]
fffff802`0cb3845d 80781800        cmp     byte ptr [rax+18h],0
fffff802`0cb38461 7413            je      nt!ObpReferenceObjectByHandleWithTag+0x216 (fffff802`0cb38476)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x203:
fffff802`0cb38463 488b4010        mov     rax,qword ptr [rax+10h]
fffff802`0cb38467 4883f801        cmp     rax,1
fffff802`0cb3846b 0f846a6d1100    je      nt!ObpReferenceObjectByHandleWithTag+0x116f7b (fffff802`0cc4f1db)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x211:
fffff802`0cb38471 4c8b7c2430      mov     r15,qword ptr [rsp+30h]

nt!ObpReferenceObjectByHandleWithTag+0x216:
fffff802`0cb38476 488b8c24c0000000 mov     rcx,qword ptr [rsp+0C0h]
fffff802`0cb3847e 49c1ff11        sar     r15,11h
fffff802`0cb38482 4885c9          test    rcx,rcx
fffff802`0cb38485 0f859f000000    jne     nt!ObpReferenceObjectByHandleWithTag+0x2ca (fffff802`0cb3852a)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x22b:
fffff802`0cb3848b 41f6c704        test    r15b,4
fffff802`0cb3848f 0f85506d1100    jne     nt!ObpReferenceObjectByHandleWithTag+0x116f85 (fffff802`0cc4f1e5)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x235:
fffff802`0cb38495 4532d2          xor     r10b,r10b

nt!ObpReferenceObjectByHandleWithTag+0x238:
fffff802`0cb38498 4c8b9c24c8000000 mov     r11,qword ptr [rsp+0C8h]
fffff802`0cb384a0 4d85ed          test    r13,r13
fffff802`0cb384a3 0f8516020000    jne     nt!ObpReferenceObjectByHandleWithTag+0x45f (fffff802`0cb386bf)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x249:
fffff802`0cb384a9 4584d2          test    r10b,r10b
fffff802`0cb384ac 0f85476d1100    jne     nt!ObpReferenceObjectByHandleWithTag+0x116f99 (fffff802`0cc4f1f9)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x252:
fffff802`0cb384b2 4883c330        add     rbx,30h
fffff802`0cb384b6 80bc24b800000000 cmp     byte ptr [rsp+0B8h],0
fffff802`0cb384be 49891c24        mov     qword ptr [r12],rbx
fffff802`0cb384c2 0f8574020000    jne     nt!ObpReferenceObjectByHandleWithTag+0x4dc (fffff802`0cb3873c)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x268:
fffff802`0cb384c8 498bce          mov     rcx,r14
fffff802`0cb384cb e83023b9ff      call    nt!KeLeaveCriticalRegionThread (fffff802`0c6ca800)
fffff802`0cb384d0 33c0            xor     eax,eax

nt!ObpReferenceObjectByHandleWithTag+0x272:
fffff802`0cb384d2 4c8b7c2448      mov     r15,qword ptr [rsp+48h]
fffff802`0cb384d7 488b6c2450      mov     rbp,qword ptr [rsp+50h]
fffff802`0cb384dc 4883c458        add     rsp,58h
fffff802`0cb384e0 415e            pop     r14
fffff802`0cb384e2 415d            pop     r13
fffff802`0cb384e4 415c            pop     r12
fffff802`0cb384e6 5f              pop     rdi
fffff802`0cb384e7 5e              pop     rsi
fffff802`0cb384e8 5b              pop     rbx
fffff802`0cb384e9 c3              ret

nt!ObpReferenceObjectByHandleWithTag+0x28a:
fffff802`0cb384ea 4883feff        cmp     rsi,0FFFFFFFFFFFFFFFFh
fffff802`0cb384ee 0f8460010000    je      nt!ObpReferenceObjectByHandleWithTag+0x3f4 (fffff802`0cb38654)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x294:
fffff802`0cb384f4 4883fefe        cmp     rsi,0FFFFFFFFFFFFFFFEh
fffff802`0cb384f8 0f84fd000000    je      nt!ObpReferenceObjectByHandleWithTag+0x39b (fffff802`0cb385fb)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x29e:
fffff802`0cb384fe 4584c9          test    r9b,r9b
fffff802`0cb38501 0f85696c1100    jne     nt!ObpReferenceObjectByHandleWithTag+0x116f10 (fffff802`0cc4f170)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x2a7:
fffff802`0cb38507 4c8b0d0a08e3ff  mov     r9,qword ptr [nt!ObpKernelHandleTable (fffff802`0c968d18)]
fffff802`0cb3850e 4881f600000080  xor     rsi,0FFFFFFFF80000000h
fffff802`0cb38515 6641ff8ee4010000 dec     word ptr [r14+1E4h]
fffff802`0cb3851d 4c898c24c8000000 mov     qword ptr [rsp+0C8h],r9
fffff802`0cb38525 e90efeffff      jmp     nt!ObpReferenceObjectByHandleWithTag+0xd8 (fffff802`0cb38338)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x2ca:
fffff802`0cb3852a 418bc7          mov     eax,r15d
fffff802`0cb3852d 896904          mov     dword ptr [rcx+4],ebp
fffff802`0cb38530 83e007          and     eax,7
fffff802`0cb38533 8901            mov     dword ptr [rcx],eax
fffff802`0cb38535 41f6c704        test    r15b,4
fffff802`0cb38539 0f8456ffffff    je      nt!ObpReferenceObjectByHandleWithTag+0x235 (fffff802`0cb38495)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x2df:
fffff802`0cb3853f e9a16c1100      jmp     nt!ObpReferenceObjectByHandleWithTag+0x116f85 (fffff802`0cc4f1e5)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x2e4:
fffff802`0cb38544 4d8b84c920993f00 mov     r8,qword ptr [r9+rcx*8+3F9920h]
fffff802`0cb3854c 4d85c0          test    r8,r8
fffff802`0cb3854f 0f84da6c1100    je      nt!ObpReferenceObjectByHandleWithTag+0x116fcf (fffff802`0cc4f22f)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x2f5:
fffff802`0cb38555 4c3b05349cecff  cmp     r8,qword ptr [nt!MmBadPointer (fffff802`0ca02190)]
fffff802`0cb3855c 0f84cd6c1100    je      nt!ObpReferenceObjectByHandleWithTag+0x116fcf (fffff802`0cc4f22f)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x302:
fffff802`0cb38562 4885d2          test    rdx,rdx
fffff802`0cb38565 0f84b1feffff    je      nt!ObpReferenceObjectByHandleWithTag+0x1bc (fffff802`0cb3841c)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x30b:
fffff802`0cb3856b bf240000c0      mov     edi,0C0000024h
fffff802`0cb38570 e9e5010000      jmp     nt!ObpReferenceObjectByHandleWithTag+0x4fa (fffff802`0cb3875a)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x320:
fffff802`0cb38580 0f0d0f          prefetchw [rdi]
fffff802`0cb38583 4c8b07          mov     r8,qword ptr [rdi]
fffff802`0cb38586 41f6c001        test    r8b,1
fffff802`0cb3858a 0f84f0010000    je      nt!ObpReferenceObjectByHandleWithTag+0x520 (fffff802`0cb38780)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x330:
fffff802`0cb38590 498d48ff        lea     rcx,[r8-1]
fffff802`0cb38594 498bc0          mov     rax,r8
fffff802`0cb38597 f0480fb10f      lock cmpxchg qword ptr [rdi],rcx
fffff802`0cb3859c 75e2            jne     nt!ObpReferenceObjectByHandleWithTag+0x320 (fffff802`0cb38580)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x33e:
fffff802`0cb3859e 488b1f          mov     rbx,qword ptr [rdi]
fffff802`0cb385a1 488bcf          mov     rcx,rdi
fffff802`0cb385a4 0f1007          movups  xmm0,xmmword ptr [rdi]
fffff802`0cb385a7 48c1fb10        sar     rbx,10h
fffff802`0cb385ab 4883e3f0        and     rbx,0FFFFFFFFFFFFFFF0h
fffff802`0cb385af 0f11442430      movups  xmmword ptr [rsp+30h],xmm0
fffff802`0cb385b4 e87724b9ff      call    nt!ExSlowReplenishHandleTableEntry (fffff802`0c6caa30)
fffff802`0cb385b9 ffc0            inc     eax
fffff802`0cb385bb 4863c8          movsxd  rcx,eax
fffff802`0cb385be 488bc1          mov     rax,rcx
fffff802`0cb385c1 f0480fc103      lock xadd qword ptr [rbx],rax
fffff802`0cb385c6 4885c0          test    rax,rax
fffff802`0cb385c9 0f8ed16b1100    jle     nt!ObpReferenceObjectByHandleWithTag+0x116f40 (fffff802`0cc4f1a0)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x36f:
fffff802`0cb385cf b801000000      mov     eax,1
fffff802`0cb385d4 f0480fc107      lock xadd qword ptr [rdi],rax
fffff802`0cb385d9 498d4930        lea     rcx,[r9+30h]
fffff802`0cb385dd f0830c2400      lock or dword ptr [rsp],0
fffff802`0cb385e2 48833900        cmp     qword ptr [rcx],0
fffff802`0cb385e6 0f8550020000    jne     nt!ObpReferenceObjectByHandleWithTag+0x5dc (fffff802`0cb3883c)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x38c:
fffff802`0cb385ec 488b6c2438      mov     rbp,qword ptr [rsp+38h]
fffff802`0cb385f1 4c8b7c2430      mov     r15,qword ptr [rsp+30h]
fffff802`0cb385f6 e9d7fdffff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x172 (fffff802`0cb383d2)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x39b:
fffff802`0cb385fb 483b1dee9aecff  cmp     rbx,qword ptr [nt!PsThreadType (fffff802`0ca020f0)]
fffff802`0cb38602 0f8507020000    jne     nt!ObpReferenceObjectByHandleWithTag+0x5af (fffff802`0cb3880f)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x3a8:
fffff802`0cb38608 f7c20000e0ff    test    edx,0FFE00000h
fffff802`0cb3860e 0f85066b1100    jne     nt!ObpReferenceObjectByHandleWithTag+0x116eba (fffff802`0cc4f11a)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x3b4:
fffff802`0cb38614 488b8424c0000000 mov     rax,qword ptr [rsp+0C0h]
fffff802`0cb3861c 4885c0          test    rax,rax
fffff802`0cb3861f 0f85086b1100    jne     nt!ObpReferenceObjectByHandleWithTag+0x116ecd (fffff802`0cc4f12d)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x3c5:
fffff802`0cb38625 390dd989ecff    cmp     dword ptr [nt!ObpTraceFlags (fffff802`0ca01004)],ecx
fffff802`0cb3862b bb01000000      mov     ebx,1
fffff802`0cb38630 0f85056b1100    jne     nt!ObpReferenceObjectByHandleWithTag+0x116edb (fffff802`0cc4f13b)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x3d6:
fffff802`0cb38636 f0490fc15ed0    lock xadd qword ptr [r14-30h],rbx
fffff802`0cb3863c 48ffc3          inc     rbx
fffff802`0cb3863f 4883fb01        cmp     rbx,1
fffff802`0cb38643 0f8e106b1100    jle     nt!ObpReferenceObjectByHandleWithTag+0x116ef9 (fffff802`0cc4f159)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x3e9:
fffff802`0cb38649 4d893424        mov     qword ptr [r12],r14

nt!ObpReferenceObjectByHandleWithTag+0x3ed:
fffff802`0cb3864d 8bc1            mov     eax,ecx
fffff802`0cb3864f e97efeffff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x272 (fffff802`0cb384d2)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x3f4:
fffff802`0cb38654 483b1d759aecff  cmp     rbx,qword ptr [nt!PsProcessType (fffff802`0ca020d0)]
fffff802`0cb3865b 0f8538010000    jne     nt!ObpReferenceObjectByHandleWithTag+0x539 (fffff802`0cb38799)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x401:
fffff802`0cb38661 f7c20000e0ff    test    edx,0FFE00000h
fffff802`0cb38667 0f85656a1100    jne     nt!ObpReferenceObjectByHandleWithTag+0x116e72 (fffff802`0cc4f0d2)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x40d:
fffff802`0cb3866d 488b8424c0000000 mov     rax,qword ptr [rsp+0C0h]
fffff802`0cb38675 498bbeb8000000  mov     rdi,qword ptr [r14+0B8h]
fffff802`0cb3867c 4885c0          test    rax,rax
fffff802`0cb3867f 0f857c010000    jne     nt!ObpReferenceObjectByHandleWithTag+0x5a1 (fffff802`0cb38801)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x425:
fffff802`0cb38685 390d7989ecff    cmp     dword ptr [nt!ObpTraceFlags (fffff802`0ca01004)],ecx
fffff802`0cb3868b bb01000000      mov     ebx,1
fffff802`0cb38690 0f854f6a1100    jne     nt!ObpReferenceObjectByHandleWithTag+0x116e85 (fffff802`0cc4f0e5)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x436:
fffff802`0cb38696 f0480fc15fd0    lock xadd qword ptr [rdi-30h],rbx
fffff802`0cb3869c 48ffc3          inc     rbx
fffff802`0cb3869f 4883fb01        cmp     rbx,1
fffff802`0cb386a3 0f8e5a6a1100    jle     nt!ObpReferenceObjectByHandleWithTag+0x116ea3 (fffff802`0cc4f103)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x449:
fffff802`0cb386a9 49893c24        mov     qword ptr [r12],rdi

nt!ObpReferenceObjectByHandleWithTag+0x44d:
fffff802`0cb386ad 8bc1            mov     eax,ecx
fffff802`0cb386af e91efeffff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x272 (fffff802`0cb384d2)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x454:
; 将6p指向的内存的头8bytes清0
fffff802`0cb386b4 33c0            xor     eax,eax
fffff802`0cb386b6 49894500        mov     qword ptr [r13],rax
fffff802`0cb386ba e900fcffff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x5f (fffff802`0cb382bf)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x45f:
fffff802`0cb386bf 41837b0400      cmp     dword ptr [r11+4],0
fffff802`0cb386c4 0f84dffdffff    je      nt!ObpReferenceObjectByHandleWithTag+0x249 (fffff802`0cb384a9)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x46a:
fffff802`0cb386ca 488bd6          mov     rdx,rsi
fffff802`0cb386cd 498bcb          mov     rcx,r11
fffff802`0cb386d0 e83bdd2100      call    nt!ExpGetHandleExtraInfo (fffff802`0cd56410)
fffff802`0cb386d5 4885c0          test    rax,rax
fffff802`0cb386d8 0f84cbfdffff    je      nt!ObpReferenceObjectByHandleWithTag+0x249 (fffff802`0cb384a9)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x47e:
fffff802`0cb386de e90a6b1100      jmp     nt!ObpReferenceObjectByHandleWithTag+0x116f8d (fffff802`0cc4f1ed)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x483:
fffff802`0cb386e3 4d8bc7          mov     r8,r15
fffff802`0cb386e6 488bd7          mov     rdx,rdi
fffff802`0cb386e9 498bc9          mov     rcx,r9
fffff802`0cb386ec e803900100      call    nt!ExpBlockOnLockedHandleEntry (fffff802`0cb516f4)
fffff802`0cb386f1 0f0d0f          prefetchw [rdi]
fffff802`0cb386f4 488b07          mov     rax,qword ptr [rdi]
fffff802`0cb386f7 488b6f08        mov     rbp,qword ptr [rdi+8]
fffff802`0cb386fb 4c8b8c24c8000000 mov     r9,qword ptr [rsp+0C8h]
fffff802`0cb38703 4889442430      mov     qword ptr [rsp+30h],rax
fffff802`0cb38708 4c8b7c2430      mov     r15,qword ptr [rsp+30h]
fffff802`0cb3870d 48896c2438      mov     qword ptr [rsp+38h],rbp

nt!ObpReferenceObjectByHandleWithTag+0x4b2:
fffff802`0cb38712 49f7c7feff0100  test    r15,1FFFEh
fffff802`0cb38719 0f8562fcffff    jne     nt!ObpReferenceObjectByHandleWithTag+0x121 (fffff802`0cb38381)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x4bf:
fffff802`0cb3871f e95cfeffff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x320 (fffff802`0cb38580)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x4c4:
fffff802`0cb38724 488bcf          mov     rcx,rdi
fffff802`0cb38727 e85057f6ff      call    nt!ObReferenceProcessHandleTable (fffff802`0ca9de7c)
fffff802`0cb3872c 4c8bc8          mov     r9,rax
fffff802`0cb3872f c68424b800000001 mov     byte ptr [rsp+0B8h],1
fffff802`0cb38737 e9defbffff      jmp     nt!ObpReferenceObjectByHandleWithTag+0xba (fffff802`0cb3831a)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x4dc:
fffff802`0cb3873c 488b8c2490000000 mov     rcx,qword ptr [rsp+90h]
fffff802`0cb38744 4881c1f8020000  add     rcx,2F8h
fffff802`0cb3874b e8b0f2b8ff      call    nt!ExReleaseRundownProtection (fffff802`0c6c7a00)
fffff802`0cb38750 e973fdffff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x268 (fffff802`0cb384c8)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x4f5:
; 到这里就判死刑了，下面我要看一下正常的流程是怎么走的
fffff802`0cb38755 bf220000c0      mov     edi,0C0000022h

nt!ObpReferenceObjectByHandleWithTag+0x4fa:
fffff802`0cb3875a 488d4b30        lea     rcx,[rbx+30h]
fffff802`0cb3875e e8ed78b1ff      call    nt!ObDereferenceObject (fffff802`0c650050)

nt!ObpReferenceObjectByHandleWithTag+0x503:
fffff802`0cb38763 80bc24b800000000 cmp     byte ptr [rsp+0B8h],0
fffff802`0cb3876b 0f85f86a1100    jne     nt!ObpReferenceObjectByHandleWithTag+0x117009 (fffff802`0cc4f269)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x511:
fffff802`0cb38771 498bce          mov     rcx,r14
fffff802`0cb38774 e88720b9ff      call    nt!KeLeaveCriticalRegionThread (fffff802`0c6ca800)
fffff802`0cb38779 8bc7            mov     eax,edi
fffff802`0cb3877b e952fdffff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x272 (fffff802`0cb384d2)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x520:
fffff802`0cb38780 4d85c0          test    r8,r8
fffff802`0cb38783 0f859b000000    jne     nt!ObpReferenceObjectByHandleWithTag+0x5c4 (fffff802`0cb38824)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x529:
fffff802`0cb38789 4885f6          test    rsi,rsi
fffff802`0cb3878c 0f85b56a1100    jne     nt!ObpReferenceObjectByHandleWithTag+0x116fe7 (fffff802`0cc4f247)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x532:
fffff802`0cb38792 bf080000c0      mov     edi,0C0000008h
fffff802`0cb38797 ebca            jmp     nt!ObpReferenceObjectByHandleWithTag+0x503 (fffff802`0cb38763)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x539:
fffff802`0cb38799 4885db          test    rbx,rbx
fffff802`0cb3879c 0f84bffeffff    je      nt!ObpReferenceObjectByHandleWithTag+0x401 (fffff802`0cb38661)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x542:
fffff802`0cb387a2 b9240000c0      mov     ecx,0C0000024h
fffff802`0cb387a7 8bc1            mov     eax,ecx
fffff802`0cb387a9 e924fdffff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x272 (fffff802`0cb384d2)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x54e:
fffff802`0cb387ae 488d044dfeffffff lea     rax,[rcx*2-2]
fffff802`0cb387b6 baf07f0000      mov     edx,7FF0h
fffff802`0cb387bb 4933c7          xor     rax,r15
fffff802`0cb387be 25feff0100      and     eax,1FFFEh
fffff802`0cb387c3 4c33f8          xor     r15,rax
fffff802`0cb387c6 4c897c2430      mov     qword ptr [rsp+30h],r15
fffff802`0cb387cb 49c1ff10        sar     r15,10h
fffff802`0cb387cf 4983e7f0        and     r15,0FFFFFFFFFFFFFFF0h
fffff802`0cb387d3 498bcf          mov     rcx,r15
fffff802`0cb387d6 498bdf          mov     rbx,r15
fffff802`0cb387d9 e8ea20b3ff      call    nt!ObpIncrPointerCountEx (fffff802`0c66a8c8)
fffff802`0cb387de 41b8f07f0000    mov     r8d,7FF0h
fffff802`0cb387e4 488d542430      lea     rdx,[rsp+30h]
fffff802`0cb387e9 488bcf          mov     rcx,rdi
fffff802`0cb387ec e83b11beff      call    nt!ExFastReplenishHandleTableEntry (fffff802`0c71992c)
fffff802`0cb387f1 4863c8          movsxd  rcx,eax
fffff802`0cb387f4 85c0            test    eax,eax
fffff802`0cb387f6 0f84f0fdffff    je      nt!ObpReferenceObjectByHandleWithTag+0x38c (fffff802`0cb385ec)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x59c:
fffff802`0cb387fc e990691100      jmp     nt!ObpReferenceObjectByHandleWithTag+0x116f31 (fffff802`0cc4f191)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x5a1:
fffff802`0cb38801 c74004ffff1f00  mov     dword ptr [rax+4],1FFFFFh
fffff802`0cb38808 8908            mov     dword ptr [rax],ecx
fffff802`0cb3880a e976feffff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x425 (fffff802`0cb38685)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x5af:
fffff802`0cb3880f 4885db          test    rbx,rbx
fffff802`0cb38812 0f84f0fdffff    je      nt!ObpReferenceObjectByHandleWithTag+0x3a8 (fffff802`0cb38608)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x5b8:
fffff802`0cb38818 b9240000c0      mov     ecx,0C0000024h
fffff802`0cb3881d 8bc1            mov     eax,ecx
fffff802`0cb3881f e9aefcffff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x272 (fffff802`0cb384d2)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x5c4:
fffff802`0cb38824 488bd7          mov     rdx,rdi
fffff802`0cb38827 498bc9          mov     rcx,r9
fffff802`0cb3882a e8c58e0100      call    nt!ExpBlockOnLockedHandleEntry (fffff802`0cb516f4)
fffff802`0cb3882f 4c8b8c24c8000000 mov     r9,qword ptr [rsp+0C8h]
fffff802`0cb38837 e944fdffff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x320 (fffff802`0cb38580)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x5dc:
fffff802`0cb3883c 33d2            xor     edx,edx
fffff802`0cb3883e e80d02c3ff      call    nt!ExfUnblockPushLock (fffff802`0c768a50)
fffff802`0cb38843 e9a4fdffff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x38c (fffff802`0cb385ec)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116e72:
fffff802`0cc4f0d2 4584c9          test    r9b,r9b
fffff802`0cc4f0d5 0f849295eeff    je      nt!ObpReferenceObjectByHandleWithTag+0x40d (fffff802`0cb3866d)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116e7b:
fffff802`0cc4f0db b9220000c0      mov     ecx,0C0000022h
fffff802`0cc4f0e0 e9c895eeff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x44d (fffff802`0cb386ad)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116e85:
fffff802`0cc4f0e5 448b8c24b0000000 mov     r9d,dword ptr [rsp+0B0h]
fffff802`0cc4f0ed 488d4fd0        lea     rcx,[rdi-30h]
fffff802`0cc4f0f1 448bc3          mov     r8d,ebx
fffff802`0cc4f0f4 0fb6d3          movzx   edx,bl
fffff802`0cc4f0f7 e86caebeff      call    nt!ObpPushStackInfo (fffff802`0c839f68)
fffff802`0cc4f0fc 33c9            xor     ecx,ecx
fffff802`0cc4f0fe e99395eeff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x436 (fffff802`0cb38696)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116ea3:
fffff802`0cc4f103 33d2            xor     edx,edx
fffff802`0cc4f105 48895c2420      mov     qword ptr [rsp+20h],rbx
fffff802`0cc4f10a 4c8bc7          mov     r8,rdi
fffff802`0cc4f10d 8d4a18          lea     ecx,[rdx+18h]
fffff802`0cc4f110 448d4a10        lea     r9d,[rdx+10h]
fffff802`0cc4f114 e8b7d6b1ff      call    nt!KeBugCheckEx (fffff802`0c76c7d0)
fffff802`0cc4f119 cc              int     3

nt!ObpReferenceObjectByHandleWithTag+0x116eba:
fffff802`0cc4f11a 4584c9          test    r9b,r9b
fffff802`0cc4f11d 0f84f194eeff    je      nt!ObpReferenceObjectByHandleWithTag+0x3b4 (fffff802`0cb38614)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116ec3:
fffff802`0cc4f123 b9220000c0      mov     ecx,0C0000022h
fffff802`0cc4f128 e92095eeff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x3ed (fffff802`0cb3864d)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116ecd:
fffff802`0cc4f12d c74004ffff1f00  mov     dword ptr [rax+4],1FFFFFh
fffff802`0cc4f134 8908            mov     dword ptr [rax],ecx
fffff802`0cc4f136 e9ea94eeff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x3c5 (fffff802`0cb38625)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116edb:
fffff802`0cc4f13b 448b8c24b0000000 mov     r9d,dword ptr [rsp+0B0h]
fffff802`0cc4f143 498d4ed0        lea     rcx,[r14-30h]
fffff802`0cc4f147 448bc3          mov     r8d,ebx
fffff802`0cc4f14a 0fb6d3          movzx   edx,bl
fffff802`0cc4f14d e816aebeff      call    nt!ObpPushStackInfo (fffff802`0c839f68)
fffff802`0cc4f152 33c9            xor     ecx,ecx
fffff802`0cc4f154 e9dd94eeff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x3d6 (fffff802`0cb38636)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116ef9:
fffff802`0cc4f159 33d2            xor     edx,edx
fffff802`0cc4f15b 48895c2420      mov     qword ptr [rsp+20h],rbx
fffff802`0cc4f160 4d8bc6          mov     r8,r14
fffff802`0cc4f163 8d4a18          lea     ecx,[rdx+18h]
fffff802`0cc4f166 448d4a10        lea     r9d,[rdx+10h]
fffff802`0cc4f16a e861d6b1ff      call    nt!KeBugCheckEx (fffff802`0c76c7d0)
fffff802`0cc4f16f cc              int     3

nt!ObpReferenceObjectByHandleWithTag+0x116f10:
fffff802`0cc4f170 b8080000c0      mov     eax,0C0000008h
fffff802`0cc4f175 e95893eeff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x272 (fffff802`0cb384d2)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116f1a:
fffff802`0cc4f17a 4584c9          test    r9b,r9b
fffff802`0cc4f17d 0f856b91eeff    jne     nt!ObpReferenceObjectByHandleWithTag+0x8e (fffff802`0cb382ee)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116f23:
fffff802`0cc4f183 488bce          mov     rcx,rsi
fffff802`0cc4f186 e81d941600      call    nt!VfCheckUserHandle (fffff802`0cdb85a8)
fffff802`0cc4f18b 90              nop
fffff802`0cc4f18c e95d91eeff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x8e (fffff802`0cb382ee)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116f31:
fffff802`0cc4f191 f7d9            neg     ecx
fffff802`0cc4f193 4863c1          movsxd  rax,ecx
fffff802`0cc4f196 f0490fc107      lock xadd qword ptr [r15],rax
fffff802`0cc4f19b e94c94eeff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x38c (fffff802`0cb385ec)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116f40:
fffff802`0cc4f1a0 33d2            xor     edx,edx
fffff802`0cc4f1a2 4c8d4330        lea     r8,[rbx+30h]
fffff802`0cc4f1a6 4803c1          add     rax,rcx
fffff802`0cc4f1a9 4889442420      mov     qword ptr [rsp+20h],rax
fffff802`0cc4f1ae 8d4a18          lea     ecx,[rdx+18h]
fffff802`0cc4f1b1 448d4a10        lea     r9d,[rdx+10h]
fffff802`0cc4f1b5 e816d6b1ff      call    nt!KeBugCheckEx (fffff802`0c76c7d0)
fffff802`0cc4f1ba cc              int     3

nt!ObpReferenceObjectByHandleWithTag+0x116f5b:
fffff802`0cc4f1bb 448b8c24b0000000 mov     r9d,dword ptr [rsp+0B0h]
fffff802`0cc4f1c3 41b801000000    mov     r8d,1
fffff802`0cc4f1c9 410fb6d0        movzx   edx,r8b
fffff802`0cc4f1cd 488bcb          mov     rcx,rbx
fffff802`0cc4f1d0 e893adbeff      call    nt!ObpPushStackInfo (fffff802`0c839f68)
fffff802`0cc4f1d5 90              nop
fffff802`0cc4f1d6 e90492eeff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x17f (fffff802`0cb383df)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116f7b:
fffff802`0cc4f1db bf06a000c0      mov     edi,0C000A006h
fffff802`0cc4f1e0 e97595eeff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x4fa (fffff802`0cb3875a)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116f85:
fffff802`0cc4f1e5 41b201          mov     r10b,1
fffff802`0cc4f1e8 e9ab92eeff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x238 (fffff802`0cb38498)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116f8d:
fffff802`0cc4f1ed 488b00          mov     rax,qword ptr [rax]
fffff802`0cc4f1f0 49894500        mov     qword ptr [r13],rax
fffff802`0cc4f1f4 e9b092eeff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x249 (fffff802`0cb384a9)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116f99:
fffff802`0cc4f1f9 8b842498000000  mov     eax,dword ptr [rsp+98h]
fffff802`0cc4f200 85c0            test    eax,eax
fffff802`0cc4f202 0f84aa92eeff    je      nt!ObpReferenceObjectByHandleWithTag+0x252 (fffff802`0cb384b2)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116fa8:
fffff802`0cc4f208 4c8bcb          mov     r9,rbx
fffff802`0cc4f20b 89442420        mov     dword ptr [rsp+20h],eax
fffff802`0cc4f20f 4c8bc7          mov     r8,rdi
fffff802`0cc4f212 488bd6          mov     rdx,rsi
fffff802`0cc4f215 498bcb          mov     rcx,r11
fffff802`0cc4f218 e867010a00      call    nt!ObpAuditObjectAccess (fffff802`0ccef384)
fffff802`0cc4f21d 84c0            test    al,al
fffff802`0cc4f21f 0f858d92eeff    jne     nt!ObpReferenceObjectByHandleWithTag+0x252 (fffff802`0cb384b2)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116fc5:
fffff802`0cc4f225 bf080000c0      mov     edi,0C0000008h
fffff802`0cc4f22a e92b95eeff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x4fa (fffff802`0cb3875a)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x116fcf:
fffff802`0cc4f22f 33ff            xor     edi,edi
fffff802`0cc4f231 4533c9          xor     r9d,r9d
fffff802`0cc4f234 488bd3          mov     rdx,rbx
fffff802`0cc4f237 48897c2420      mov     qword ptr [rsp+20h],rdi
fffff802`0cc4f23c b989010000      mov     ecx,189h
fffff802`0cc4f241 e88ad5b1ff      call    nt!KeBugCheckEx (fffff802`0c76c7d0)
fffff802`0cc4f246 cc              int     3

nt!ObpReferenceObjectByHandleWithTag+0x116fe7:
fffff802`0cc4f247 65488b042588010000 mov   rax,qword ptr gs:[188h]
fffff802`0cc4f250 488bd6          mov     rdx,rsi
fffff802`0cc4f253 498bc9          mov     rcx,r9
fffff802`0cc4f256 440fb68032020000 movzx   r8d,byte ptr [rax+232h]
fffff802`0cc4f25e e86956c3ff      call    nt!ExHandleLogBadReference (fffff802`0c8848cc)
fffff802`0cc4f263 90              nop
fffff802`0cc4f264 e92995eeff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x532 (fffff802`0cb38792)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x117009:
fffff802`0cc4f269 488b8c2490000000 mov     rcx,qword ptr [rsp+90h]
fffff802`0cc4f271 4881c1f8020000  add     rcx,2F8h
fffff802`0cc4f278 e88387a7ff      call    nt!ExReleaseRundownProtection (fffff802`0c6c7a00)
fffff802`0cc4f27d 90              nop
fffff802`0cc4f27e e9ee94eeff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x511 (fffff802`0cb38771)  Branch

nt!ObpReferenceObjectByHandleWithTag+0x117023:
fffff802`0cc4f283 bf080000c0      mov     edi,0C0000008h
fffff802`0cc4f288 e9e494eeff      jmp     nt!ObpReferenceObjectByHandleWithTag+0x511 (fffff802`0cb38771)  Branch
