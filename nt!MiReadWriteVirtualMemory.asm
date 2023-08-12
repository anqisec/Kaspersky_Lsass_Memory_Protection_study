0: kd> uf nt!MiReadWriteVirtualMemory
nt!MiReadWriteVirtualMemory:
fffff802`0cb19510 48895c2408      mov     qword ptr [rsp+8],rbx
fffff802`0cb19515 4889742410      mov     qword ptr [rsp+10h],rsi
fffff802`0cb1951a 48897c2418      mov     qword ptr [rsp+18h],rdi
fffff802`0cb1951f 4c89642420      mov     qword ptr [rsp+20h],r12
fffff802`0cb19524 4155            push    r13
fffff802`0cb19526 4156            push    r14
fffff802`0cb19528 4157            push    r15
fffff802`0cb1952a 4883ec60        sub     rsp,60h
fffff802`0cb1952e 4d8bf9          mov     r15,r9
fffff802`0cb19531 4d8be8          mov     r13,r8
fffff802`0cb19534 4c8be2          mov     r12,rdx
fffff802`0cb19537 4c8bd1          mov     r10,rcx
fffff802`0cb1953a 654c8b342588010000 mov   r14,qword ptr gs:[188h]
fffff802`0cb19543 410fb68632020000 movzx   eax,byte ptr [r14+232h]
fffff802`0cb1954b 88442440        mov     byte ptr [rsp+40h],al
fffff802`0cb1954f 84c0            test    al,al
fffff802`0cb19551 0f84e7a11200    je      nt!MiReadWriteVirtualMemory+0x12a22e (fffff802`0cc4373e)  Branch

nt!MiReadWriteVirtualMemory+0x47:
fffff802`0cb19557 4a8d040a        lea     rax,[rdx+r9]
fffff802`0cb1955b 483bc2          cmp     rax,rdx
fffff802`0cb1955e 0f8287010000    jb      nt!MiReadWriteVirtualMemory+0x1db (fffff802`0cb196eb)  Branch

nt!MiReadWriteVirtualMemory+0x54:
fffff802`0cb19564 4d03c8          add     r9,r8
fffff802`0cb19567 4d3bc8          cmp     r9,r8
fffff802`0cb1956a 0f827b010000    jb      nt!MiReadWriteVirtualMemory+0x1db (fffff802`0cb196eb)  Branch

nt!MiReadWriteVirtualMemory+0x60:
fffff802`0cb19570 48b9fffffeffff7f0000 mov rcx,7FFFFFFEFFFFh
fffff802`0cb1957a 483bc1          cmp     rax,rcx
fffff802`0cb1957d 0f8768010000    ja      nt!MiReadWriteVirtualMemory+0x1db (fffff802`0cb196eb)  Branch

nt!MiReadWriteVirtualMemory+0x73:
fffff802`0cb19583 4c3bc9          cmp     r9,rcx
fffff802`0cb19586 0f875f010000    ja      nt!MiReadWriteVirtualMemory+0x1db (fffff802`0cb196eb)  Branch

nt!MiReadWriteVirtualMemory+0x7c:
fffff802`0cb1958c 488b9c24a0000000 mov     rbx,qword ptr [rsp+0A0h]
fffff802`0cb19594 4885db          test    rbx,rbx
fffff802`0cb19597 0f8436010000    je      nt!MiReadWriteVirtualMemory+0x1c3 (fffff802`0cb196d3)  Branch

nt!MiReadWriteVirtualMemory+0x8d:
fffff802`0cb1959d 488bcb          mov     rcx,rbx
fffff802`0cb195a0 48b80000ffffff7f0000 mov rax,7FFFFFFF0000h
fffff802`0cb195aa 483bd8          cmp     rbx,rax
fffff802`0cb195ad 7203            jb      nt!MiReadWriteVirtualMemory+0xa2 (fffff802`0cb195b2)  Branch

nt!MiReadWriteVirtualMemory+0x9f:
fffff802`0cb195af 488bc8          mov     rcx,rax

nt!MiReadWriteVirtualMemory+0xa2:
fffff802`0cb195b2 488b01          mov     rax,qword ptr [rcx]
fffff802`0cb195b5 488901          mov     qword ptr [rcx],rax
fffff802`0cb195b8 0fb6442440      movzx   eax,byte ptr [rsp+40h]
fffff802`0cb195bd eb05            jmp     nt!MiReadWriteVirtualMemory+0xb4 (fffff802`0cb195c4)  Branch

nt!MiReadWriteVirtualMemory+0xb4:
fffff802`0cb195c4 33ff            xor     edi,edi
fffff802`0cb195c6 48897c2448      mov     qword ptr [rsp+48h],rdi
fffff802`0cb195cb 8bf7            mov     esi,edi
fffff802`0cb195cd 897c2444        mov     dword ptr [rsp+44h],edi
fffff802`0cb195d1 4d85ff          test    r15,r15
fffff802`0cb195d4 0f84ca000000    je      nt!MiReadWriteVirtualMemory+0x194 (fffff802`0cb196a4)  Branch

nt!MiReadWriteVirtualMemory+0xca:
fffff802`0cb195da 4c8b05ef8aeeff  mov     r8,qword ptr [nt!PsProcessType (fffff802`0ca020d0)]
fffff802`0cb195e1 48897c2438      mov     qword ptr [rsp+38h],rdi
fffff802`0cb195e6 48897c2430      mov     qword ptr [rsp+30h],rdi
fffff802`0cb195eb 488d4c2450      lea     rcx,[rsp+50h]
fffff802`0cb195f0 48894c2428      mov     qword ptr [rsp+28h],rcx
fffff802`0cb195f5 c74424204d6d566d mov     dword ptr [rsp+20h],6D566D4Dh
fffff802`0cb195fd 440fb6c8        movzx   r9d,al
fffff802`0cb19601 8b9424a8000000  mov     edx,dword ptr [rsp+0A8h]
fffff802`0cb19608 498bca          mov     rcx,r10
fffff802`0cb1960b e850ec0100      call    nt!ObpReferenceObjectByHandleWithTag (fffff802`0cb38260)
fffff802`0cb19610 8bf0            mov     esi,eax
fffff802`0cb19612 89442444        mov     dword ptr [rsp+44h],eax
fffff802`0cb19616 85c0            test    eax,eax
fffff802`0cb19618 0f8886000000    js      nt!MiReadWriteVirtualMemory+0x194 (fffff802`0cb196a4)  Branch

nt!MiReadWriteVirtualMemory+0x10e:
fffff802`0cb1961e 4d8b96b8000000  mov     r10,qword ptr [r14+0B8h]
fffff802`0cb19625 4c89542458      mov     qword ptr [rsp+58h],r10
fffff802`0cb1962a 4c8b742450      mov     r14,qword ptr [rsp+50h]
fffff802`0cb1962f 41f686d002000001 test    byte ptr [r14+2D0h],1
fffff802`0cb19637 0f850ea11200    jne     nt!MiReadWriteVirtualMemory+0x12a23b (fffff802`0cc4374b)  Branch

nt!MiReadWriteVirtualMemory+0x12d:
fffff802`0cb1963d 488d442448      lea     rax,[rsp+48h]
fffff802`0cb19642 4889442430      mov     qword ptr [rsp+30h],rax
fffff802`0cb19647 0fb6442440      movzx   eax,byte ptr [rsp+40h]
fffff802`0cb1964c 88442428        mov     byte ptr [rsp+28h],al
fffff802`0cb19650 4c897c2420      mov     qword ptr [rsp+20h],r15
fffff802`0cb19655 83bc24a800000010 cmp     dword ptr [rsp+0A8h],10h
fffff802`0cb1965d 757e            jne     nt!MiReadWriteVirtualMemory+0x1cd (fffff802`0cb196dd)  Branch

nt!MiReadWriteVirtualMemory+0x14f:
fffff802`0cb1965f 4d8bcd          mov     r9,r13
fffff802`0cb19662 4d8bc2          mov     r8,r10
fffff802`0cb19665 498bd4          mov     rdx,r12
fffff802`0cb19668 498bce          mov     rcx,r14

nt!MiReadWriteVirtualMemory+0x15b:
fffff802`0cb1966b e890000000      call    nt!MmCopyVirtualMemory (fffff802`0cb19700)
fffff802`0cb19670 8bf0            mov     esi,eax
fffff802`0cb19672 488b7c2448      mov     rdi,qword ptr [rsp+48h]
fffff802`0cb19677 4c8b542458      mov     r10,qword ptr [rsp+58h]

nt!MiReadWriteVirtualMemory+0x16c:
fffff802`0cb1967c 89742444        mov     dword ptr [rsp+44h],esi
fffff802`0cb19680 8b9424a8000000  mov     edx,dword ptr [rsp+0A8h]
fffff802`0cb19687 498bce          mov     rcx,r14
fffff802`0cb1968a e89129baff      call    nt!PsIsProcessReadWriteVmLoggingEnabled (fffff802`0c6bc020)
fffff802`0cb1968f 85c0            test    eax,eax
fffff802`0cb19691 0f85d4a01200    jne     nt!MiReadWriteVirtualMemory+0x12a25b (fffff802`0cc4376b)  Branch

nt!MiReadWriteVirtualMemory+0x187:
fffff802`0cb19697 ba4d6d566d      mov     edx,6D566D4Dh
fffff802`0cb1969c 498bce          mov     rcx,r14
fffff802`0cb1969f e81c10bbff      call    nt!ObfDereferenceObjectWithTag (fffff802`0c6ca6c0)

nt!MiReadWriteVirtualMemory+0x194:
fffff802`0cb196a4 4885db          test    rbx,rbx
fffff802`0cb196a7 7409            je      nt!MiReadWriteVirtualMemory+0x1a2 (fffff802`0cb196b2)  Branch

nt!MiReadWriteVirtualMemory+0x199:
fffff802`0cb196a9 48893b          mov     qword ptr [rbx],rdi
fffff802`0cb196ac eb04            jmp     nt!MiReadWriteVirtualMemory+0x1a2 (fffff802`0cb196b2)  Branch

nt!MiReadWriteVirtualMemory+0x1a2:
fffff802`0cb196b2 8bc6            mov     eax,esi

nt!MiReadWriteVirtualMemory+0x1a4:
fffff802`0cb196b4 4c8d5c2460      lea     r11,[rsp+60h]
fffff802`0cb196b9 498b5b20        mov     rbx,qword ptr [r11+20h]
fffff802`0cb196bd 498b7328        mov     rsi,qword ptr [r11+28h]
fffff802`0cb196c1 498b7b30        mov     rdi,qword ptr [r11+30h]
fffff802`0cb196c5 4d8b6338        mov     r12,qword ptr [r11+38h]
fffff802`0cb196c9 498be3          mov     rsp,r11
fffff802`0cb196cc 415f            pop     r15
fffff802`0cb196ce 415e            pop     r14
fffff802`0cb196d0 415d            pop     r13
fffff802`0cb196d2 c3              ret

nt!MiReadWriteVirtualMemory+0x1c3:
fffff802`0cb196d3 0fb6442440      movzx   eax,byte ptr [rsp+40h]
fffff802`0cb196d8 e9e7feffff      jmp     nt!MiReadWriteVirtualMemory+0xb4 (fffff802`0cb195c4)  Branch

nt!MiReadWriteVirtualMemory+0x1cd:
fffff802`0cb196dd 4d8bcc          mov     r9,r12
fffff802`0cb196e0 4d8bc6          mov     r8,r14
fffff802`0cb196e3 498bd5          mov     rdx,r13
fffff802`0cb196e6 498bca          mov     rcx,r10
fffff802`0cb196e9 eb80            jmp     nt!MiReadWriteVirtualMemory+0x15b (fffff802`0cb1966b)  Branch

nt!MiReadWriteVirtualMemory+0x1db:
fffff802`0cb196eb b8050000c0      mov     eax,0C0000005h
fffff802`0cb196f0 ebc2            jmp     nt!MiReadWriteVirtualMemory+0x1a4 (fffff802`0cb196b4)  Branch

nt!MiReadWriteVirtualMemory+0x12a22e:
fffff802`0cc4373e 488b9c24a0000000 mov     rbx,qword ptr [rsp+0A0h]
fffff802`0cc43746 e9795eedff      jmp     nt!MiReadWriteVirtualMemory+0xb4 (fffff802`0cb195c4)  Branch

nt!MiReadWriteVirtualMemory+0x12a23b:
fffff802`0cc4374b 4d3bd6          cmp     r10,r14
fffff802`0cc4374e 0f84e95eedff    je      nt!MiReadWriteVirtualMemory+0x12d (fffff802`0cb1963d)  Branch

nt!MiReadWriteVirtualMemory+0x12a244:
fffff802`0cc43754 4939be20040000  cmp     qword ptr [r14+420h],rdi
fffff802`0cc4375b 0f85dc5eedff    jne     nt!MiReadWriteVirtualMemory+0x12d (fffff802`0cb1963d)  Branch

nt!MiReadWriteVirtualMemory+0x12a251:
fffff802`0cc43761 be050000c0      mov     esi,0C0000005h
fffff802`0cc43766 e9115fedff      jmp     nt!MiReadWriteVirtualMemory+0x16c (fffff802`0cb1967c)  Branch

nt!MiReadWriteVirtualMemory+0x12a25b:
fffff802`0cc4376b 48897c2428      mov     qword ptr [rsp+28h],rdi
fffff802`0cc43770 4c89642420      mov     qword ptr [rsp+20h],r12
fffff802`0cc43775 448bca          mov     r9d,edx
fffff802`0cc43778 4d8bc6          mov     r8,r14
fffff802`0cc4377b 498bd2          mov     rdx,r10
fffff802`0cc4377e 8bce            mov     ecx,esi
fffff802`0cc43780 e883751000      call    nt!EtwTiLogReadWriteVm (fffff802`0cd4ad08)
fffff802`0cc43785 90              nop
fffff802`0cc43786 e90c5fedff      jmp     nt!MiReadWriteVirtualMemory+0x187 (fffff802`0cb19697)  Branch
