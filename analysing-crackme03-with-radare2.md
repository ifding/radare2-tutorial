
# Analysing crackme.03 with radare2

In this post I am going to show how to analyse crackme with radare2 framework. The crackme is from [geslan](https://github.com/geyslan/crackmes). You can download the source code (crackme.03.asm) and create the binray file (crackme.03).
```sh
# nasm -f bin crackme.03.asm
# chmod +x crackme.03
./crackme.03 
Try to find the string of success and make me print it.
``` 

## Preliminary analysis

Before starting dynamic analysis we shall see what information we can extract from binary file using utility `rabin2`.
```sh
# rabin2 -I crackme.03
havecode true
pic      false
canary   false
nx       false
crypto   false
va       true
bintype  elf
class    ELF32
lang     c
arch     x86
bits     32
machine  Intel 80386
os       linux
minopsz  1
maxopsz  16
pcalign  0
subsys   linux
endian   little
stripped false
static   true
linenum  true
lsyms    true
relocs   true
rpath    NONE
binsz    372
```

Some basic information about binary can be obtained. It can be seen this is a ELF32 file format binary with enabled `nx` protection which hasn't been stripped, which means radare2 should be able to find main function starting address.

Let's check main function starting by
```sh
# rabin2 -MRsSz crackme.03
Warning: Cannot initialize section headers
Warning: Cannot initialize strings table
Warning: Cannot initialize dynamic strings
[Sections]
idx=00 vaddr=0x00010000 paddr=0x00000000 sz=65568 vsz=65568 perm=m-r-- name=LOAD0
idx=01 vaddr=0x00010000 paddr=0x00000000 sz=52 vsz=52 perm=m-rw- name=ehdr

2 sections
[Symbols]

0 symbols
[Relocations]

0 relocations
```

A small file, with no symbols, no strings, no sections. Looks like a hand-crafted binary!

## Dynamci analysis

Now when we have some information about binary let's say with dynamic analysis. We'll load it up in r2 using the r2 command:
```nasm
# r2 ./crackme.03
[0x00010020]> aa
[Cannot find function 'entry0' at 0x00010020 entry0 (aa)
[0x00010020]> s entry0
[0x00010020]> pdf
p: Cannot find function at 0x00010020
[0x00010020]> s 0x00010020
[0x00010020]> pd
        |   ;-- entry0:
        |   0x00010020      b32a           mov bl, 0x2a                ; '*' ; 42
        |   0x00010022      31c0           xor eax, eax
        |   0x00010024      40             inc eax
       ,==< 0x00010025      eb12           jmp 0x10039
       ||   0x00010027      003400         add byte [eax + eax], dh
       ||   0x0001002a      2000           and byte [eax], al
       ||   0x0001002c      0100           add dword [eax], eax
       ||   0x0001002e      0c14           or al, 0x14
       ||   0x00010030      90             nop
       |`=< 0x00010031      7c97           jl 0xffca
       |    0x00010033      ad             lodsd eax, dword [esi]
       |    ;-- section_end.ehdr:
       |    0x00010034      b6b6           mov dh, 0xb6                ; 182
       |    0x00010036      c6c0bf         mov al, 0xbf                ; 191
       `--> 0x00010039      29c9           sub ecx, ecx
            0x0001003b      b900000100     mov ecx, 0x10000            ; section.ehdr
            0x00010040      31d2           xor edx, edx
            0x00010042      31db           xor ebx, ebx
        .-> 0x00010044      8a19           mov bl, byte [ecx]
        |   0x00010046      01da           add edx, ebx
        |   0x00010048      41             inc ecx
        |   0x00010049      81f92e000100   cmp ecx, 0x1002e
        `=< 0x0001004f      75f3           jne 0x10044
            0x00010051      c1e202         shl edx, 2
            0x00010054      663b152e0001.  cmp dx, word [0x1002e]      ; [0x1002e:2]=0x140c
        ,=< 0x0001005b      7529           jne 0x10086
        |   0x0001005d      31ed           xor ebp, ebp
        |   0x0001005f      89d7           mov edi, edx
        |   0x00010061      45             inc ebp
        |   0x00010062      b810800000     mov eax, 0x8010
        |   0x00010067      45             inc ebp
        |   0x00010068      f7e5           mul ebp
        |   0x0001006a      96             xchg eax, esi
        |   0x0001006b      89f0           mov eax, esi
        |   0x0001006d      662b05140001.  sub ax, word [0x10014]
       ,==< 0x00010074      7510           jne 0x10086
       ||   0x00010076      29fe           sub esi, edi
       ||   0x00010078      6681f614ec     xor si, 0xec14
      ,===< 0x0001007d      7507           jne 0x10086
     ,====< 0x0001007f      eb01           jmp 0x10082
     ||||   0x00010081      d431           aam 0x31
      |||   0x00010083      c0755e29       sal byte [ebp + 0x5e], 0x29
            0x00010087      d2743854       sal byte [eax + edi + 0x54], cl
        ,=< 0x0001008b      7279           jb 0x10106
        |   0x0001008d      20746f20       and byte [edi + ebp*2 + 0x20], dh
        |   0x00010091      66696e642074   imul bp, word [esi + 0x64], 0x7420
        |   0x00010097      6865207374     push 0x74732065
       ,==< 0x0001009c      7269           jb 0x10107
       ||   0x0001009e      6e             outsb dx, byte [esi]
       ||   0x0001009f      67206f66       and byte [bx + 0x66], ch
       ||   0x000100a3      207375         and byte [ebx + 0x75], dh
       ||   0x000100a6      636365         arpl word [ebx + 0x65], sp
      ,===< 0x000100a9      7373           jae 0x1011e
      |||   0x000100ab      20616e         and byte [ecx + 0x6e], ah
      |||   0x000100ae      64206d61       and byte fs:[ebp + 0x61], ch
      |||   0x000100b2      6b65206d       imul esp, dword [ebp + 0x20], 0x6d
      |||   0x000100b6      65207072       and byte gs:[eax + 0x72], dh
      |||   0x000100ba      696e74206974.  imul ebp, dword [esi + 0x74], 0x2e746920
      |||   0x000100c1      0ab804000000   or bh, byte [eax + 4]
      |||   0x000100c7      bb01000000     mov ebx, 1
      |||   0x000100cc      b98a000100     mov ecx, 0x1008a
      |||   0x000100d1      ba38000000     mov edx, 0x38               ; '8' ; 56
      |||   0x000100d6      cd80           int 0x80
      |||   0x000100d8      b801000000     mov eax, 1
      |||   0x000100dd      bb00000000     mov ebx, 0
```

It seems that the block between 0x00010025 and 0x00010039 is not used. We can hide it with:
```nasm
[0x00010020]> s 0x00010027
[0x00010027]> Ch 0x00010039 - 0x00010027
[0x00010027]> s-
[0x00010020]> pdf
p: Cannot find function at 0x00010020
[0x00010020]> s 0x00010020
[0x00010020]> pd
            ;-- entry0:
            0x00010020      b32a           mov bl, 0x2a                ; '*' ; 42
            0x00010022      31c0           xor eax, eax
            0x00010024      40             inc eax
        ,=< 0x00010025      eb12           jmp 0x10039
        |   0x00010027 (18 bytes hidden)
        `-> 0x00010039      29c9           sub ecx, ecx
            0x0001003b      b900000100     mov ecx, 0x10000            ; section.ehdr
            0x00010040      31d2           xor edx, edx
            0x00010042      31db           xor ebx, ebx
        .-> 0x00010044      8a19           mov bl, byte [ecx]
        |   0x00010046      01da           add edx, ebx
        |   0x00010048      41             inc ecx
        |   0x00010049      81f92e000100   cmp ecx, 0x1002e
        `=< 0x0001004f      75f3           jne 0x10044
            0x00010051      c1e202         shl edx, 2
            0x00010054      663b152e0001.  cmp dx, word [0x1002e]      ; [0x1002e:2]=0x140c
        ,=< 0x0001005b      7529           jne 0x10086
        |   0x0001005d      31ed           xor ebp, ebp
        |   0x0001005f      89d7           mov edi, edx
        |   0x00010061      45             inc ebp
        |   0x00010062      b810800000     mov eax, 0x8010
        |   0x00010067      45             inc ebp
        |   0x00010068      f7e5           mul ebp
        |   0x0001006a      96             xchg eax, esi
        |   0x0001006b      89f0           mov eax, esi
        |   0x0001006d      662b05140001.  sub ax, word [0x10014]
       ,==< 0x00010074      7510           jne 0x10086
       ||   0x00010076      29fe           sub esi, edi
       ||   0x00010078      6681f614ec     xor si, 0xec14
      ,===< 0x0001007d      7507           jne 0x10086
     ,====< 0x0001007f      eb01           jmp 0x10082
     ||||   0x00010081      d431           aam 0x31
      |||   0x00010083      c0755e29       sal byte [ebp + 0x5e], 0x29
            0x00010087      d2743854       sal byte [eax + edi + 0x54], cl
        ,=< 0x0001008b      7279           jb 0x10106
        |   0x0001008d      20746f20       and byte [edi + ebp*2 + 0x20], dh
        |   0x00010091      66696e642074   imul bp, word [esi + 0x64], 0x7420
        |   0x00010097      6865207374     push 0x74732065
       ,==< 0x0001009c      7269           jb 0x10107
       ||   0x0001009e      6e             outsb dx, byte [esi]
       ||   0x0001009f      67206f66       and byte [bx + 0x66], ch
       ||   0x000100a3      207375         and byte [ebx + 0x75], dh
       ||   0x000100a6      636365         arpl word [ebx + 0x65], sp
      ,===< 0x000100a9      7373           jae 0x1011e
      |||   0x000100ab      20616e         and byte [ecx + 0x6e], ah
      |||   0x000100ae      64206d61       and byte fs:[ebp + 0x61], ch
      |||   0x000100b2      6b65206d       imul esp, dword [ebp + 0x20], 0x6d
      |||   0x000100b6      65207072       and byte gs:[eax + 0x72], dh
      |||   0x000100ba      696e74206974.  imul ebp, dword [esi + 0x74], 0x2e746920
      |||   0x000100c1      0ab804000000   or bh, byte [eax + 4]
      |||   0x000100c7      bb01000000     mov ebx, 1
      |||   0x000100cc      b98a000100     mov ecx, 0x1008a
      |||   0x000100d1      ba38000000     mov edx, 0x38               ; '8' ; 56
      |||   0x000100d6      cd80           int 0x80
      |||   0x000100d8      b801000000     mov eax, 1
      |||   0x000100dd      bb00000000     mov ebx, 0
      |||   0x000100e2      cd80           int 0x80
      |||   0x000100e4      31d2           xor edx, edx
      |||   0x000100e6      6839000100     push 0x10039
      |||   0x000100eb      66832c240b     sub word [esp], 0xb
      |||   0x000100f0      5e             pop esi
      |||   0x000100f1      8d7601         lea esi, dword [esi + 1]    ; 0x1
      |||   0x000100f4      29c9           sub ecx, ecx
      |||   0x000100f6      75ec           jne 0x100e4
```

### First checksum

We can seee a short loop starting 0x00010044, that loads 0x10000. Since the headers are screwed to prevent loading in GNU Tools, this is likely a checksum to prevent modifications. Further, they are 3 jumps to 0x10086. This may be a badboy.
```nasm
[0x00010020]> pd @0x10086
            0x00010086      29d2           sub edx, edx
        ,=< 0x00010088      7438           je 0x100c2
```

Classic trick to fool automatic analyzers. Of cource `edx - edx` is always to zero, the jumb is taken. If arrows are annoying you, feel free to turn them off with e asm.lines = false.

### Badboy
```nasm
[0x00010020]> pd @0x100c2
        |   0x000100c2      b804000000     mov eax, 4
        |   0x000100c7      bb01000000     mov ebx, 1
        |   0x000100cc      b98a000100     mov ecx, 0x1008a
        |   0x000100d1      ba38000000     mov edx, 0x38               ; '8' ; 56
        |   0x000100d6      cd80           int 0x80
       .--> 0x000100d8      b801000000     mov eax, 1
       ||   0x000100dd      bb00000000     mov ebx, 0
       ||   0x000100e2      cd80           int 0x80
```

Time to take a look at [the syscall reference](http://syscalls.kernelgrok.com/), you can also check your local syscall.h. Looks like the first one is a write, and the second one is an exit. Just to be sure, let's check what is printed sys_write takes:

- Like every syscall, the call number in eax (4)
- The file descriptor in ebx (1, aka stdout)
- The buffer to print in ecx (0x1008a), this is an address, and the lenth in edx (0x38).

What is at 0x1008a?
```nasm
[0x00010020]> ps 0x38 @0x1008a
Try to find the string of success and make me print it.

[0x00010020]> 
```

We should add a comment at 0x1008a:
```sh
[0x00010020]> Cca 0x1008a BADBOY
```

We should focus on avoid jumps to this location.

### Reversing the checksum

Since no input/output operations occurs until this jump, you can bet that all this part was a checksum. Let's reverse the checksum, first go back to 0x1003b.
```nasm
[0x00010020]> pd @0x1003b
            0x0001003b      b900000100     mov ecx, 0x10000            ; section.ehdr
            0x00010040      31d2           xor edx, edx
            0x00010042      31db           xor ebx, ebx
        .-> 0x00010044      8a19           mov bl, byte [ecx]
        |   0x00010046      01da           add edx, ebx
        |   0x00010048      41             inc ecx
        |   0x00010049      81f92e000100   cmp ecx, 0x1002e
        `=< 0x0001004f      75f3           jne 0x10044
            0x00010051      c1e202         shl edx, 2
            0x00010054      663b152e0001.  cmp dx, word [0x1002e]      ; [0x1002e:2]=0x140c
        ,=< 0x0001005b      7529           jne 0x10086
```

This code will load the address 0x10000 (Pointing to the first of the binary) in ecx, ebx and ebx are set to zero, and the loop starts:
```
1. bl = *ecx
2. edx = edx + ebx
3. ecx++
4. goto 1. if ecx != 0x1002e
5. edx = edx * 2
6. goto 0x10086 (badboy) if edx != [0x1002e]
```

Did you notice that the loop is increasing ecx, and not the value 'pointed' by ecx? This loop will add every bytes between 0x10000 and 0x1002e, and the sum must be equal to the value at 0x1002e.
```nasm
[0x00010020]> pfw @0x1002e
0x0001002e = 0x140c
```

This is indeed a checksum to check the integrity of the header.
```nasm
        ,=< 0x0001005b      7529           jne 0x10086
        |   0x0001005d      31ed           xor ebp, ebp
        |   0x0001005f      89d7           mov edi, edx
        |   0x00010061      45             inc ebp
        |   0x00010062      b810800000     mov eax, 0x8010
        |   0x00010067      45             inc ebp
        |   0x00010068      f7e5           mul ebp
        |   0x0001006a      96             xchg eax, esi
        |   0x0001006b      89f0           mov eax, esi
        |   0x0001006d      662b05140001.  sub ax, word [0x10014]
       ,==< 0x00010074      7510           jne 0x10086
       ||   0x00010076      29fe           sub esi, edi
       ||   0x00010078      6681f614ec     xor si, 0xec14
      ,===< 0x0001007d      7507           jne 0x10086
     ,====< 0x0001007f      eb01           jmp 0x10082
```

1. ebp = 0
2. ebp = ebp + 1 + 1
3. eax = 0x8010
4. eax = ebp*eax
5. eax = eax - [0x10014] = eax - 0x140C
6. goto badboy if eax != 0

Note: `mul ebp` is equivalent to `mul eax, ebp`.

1. esi = eax = 0x8010 * 2
2. esi = esi - edx = esi - 0x140C
3. si = si^0xec14
4. goto badboy if si != 0

```nasm
[0x00010020]> pd @0x10082
            0x00010082      31c0           xor eax, eax
        ,=< 0x00010084      755e           jne 0x100e4
        |   0x00010086      29d2           sub edx, edx
```

The jump is never taken, and we'll end up in badboy. It seems that we should patch here. To load the file within radare2 in write mode, you can use the `-w` option. If the jump was taken, we'll land right after the badboy block.

### Decryption

Let's go to 0x100e4:
```nasm
[0x00010320]> pd @0x100e4
      .---> 0x000100e4      31d2           xor edx, edx
      |||   0x000100e6      6839000100     push 0x10039
      |||   0x000100eb      66832c240b     sub word [esp], 0xb
      |||   0x000100f0      5e             pop esi
      |||   0x000100f1      8d7601         lea esi, dword [esi + 1]    ; 0x1
      |||   0x000100f4      29c9           sub ecx, ecx
      `===< 0x000100f6      75ec           jne 0x100e4
      .---> 0x000100f8      46             inc esi
     ,====< 0x000100f9      eb01           jmp 0x100fc
     ||||   0x000100fb      c3             ret
     `----> 0x000100fc      8a16           mov dl, byte [esi]
      |||   0x000100fe      88140c         mov byte [esp + ecx], dl
      |||   0x00010101      41             inc ecx
      |||   0x00010102      83f909         cmp ecx, 9
      `===< 0x00010105      75f1           jne 0x100f8
```

Fancy push/pop trick at 0x000100e6:
1. 0x10039 is pushed on the stack
2. 0xb is substracted from [esp], which is indeed 0x10039
3. The top of the stack (0x10039 - 0xb) is popped into esi.

The routine looks roughly like:
1. esi = 0x10039
2. esi = esi - 0xb + 1 + 1 = 0x10030

It seems that 9 bytes are also pushed on the stack "manually", at 0x000100fe, in a small loop.
```nasm
       ||   0x00010107      29d2           sub edx, edx
       ||   0x00010109      31c9           xor ecx, ecx
       ||   0x0001010b      41             inc ecx
       ||   0x0001010c      8a140c         mov dl, byte [esp + ecx]
       ||   0x0001010f      80ea09         sub dl, 9
       ||   0x00010112      80f2ac         xor dl, 0xac
      ,===< 0x00010115      eb02           jmp 0x10119
      |||   0x00010117      e84132540c     call 0xc55335d
       ||   0x0001011c      ff88140c83f9   dec dword [eax - 0x67cf3ec]
       ||   0x00010122      0875e6         or byte [ebp - 0x1a], dh
       ||   0x00010125      41             inc ecx
       ||   0x00010126      c6040c0a       mov byte [esp + ecx], 0xa
       ||   0x0001012a      49             dec ecx
       ||   0x0001012b      87d1           xchg ecx, edx
       ||   0x0001012d      42             inc edx
       ||   0x0001012e      44             inc esp
      ,===< 0x0001012f      eb01           jmp 0x10132
```

```nasm
[0x00010320]> pd @0x10119
      |||   0x00010119      32540cff       xor dl, byte [esp + ecx - 1]
      |||   0x0001011d      88140c         mov byte [esp + ecx], dl
      |||   0x00010120      83f908         cmp ecx, 8
      `===< 0x00010123      75e6           jne 0x1010b
       ||   0x00010125      41             inc ecx
       ||   0x00010126      c6040c0a       mov byte [esp + ecx], 0xa
       ||   0x0001012a      49             dec ecx
       ||   0x0001012b      87d1           xchg ecx, edx
       ||   0x0001012d      42             inc edx
       ||   0x0001012e      44             inc esp
      ,===< 0x0001012f      eb01           jmp 0x10132
```

This looks like a decryption one. Nothing complicated.
1. edx = 0
2. ecx = 0
3. ecx = ecx + 1
4. dl = esp + ecx
5. dl = dl - 9
6. dl = dl^0xac
7. dl = dl^(esp+ecx=1)
8. goto 3. if ecx != 8

Because the crypted string is: `0x90,0x7c,0x97,0xad,0xb6,0xb6,0xc6,0xc0,0xbf`. We can use python to do the decryption process:
```py
>>> array = [ 0x90, 0x7C, 0x97, 0xAD, 0xB6, 0xB6, 0xC6, 0xC0, 0xBF ]
>>> for i in range(0,8):
...     array[i+1] = (array[i+1] - 9) ^ 0xac ^ array[i]
>>> print ''.join([chr(i) for i in array])
�Omedetou
```

This prints `�Omedetou`, a Japanese word meaning Congratulations. The weird char on the front will likely be skip later. Looks like we're on the right track.

### Another checksum

Let's go the 0x10132:
```nasm
[0x00010320]> pd @0x10132
       ||   0x00010132      b804000000     mov eax, 4
       ||   0x00010137      bb01000000     mov ebx, 1
       ||   0x0001013c      89e1           mov ecx, esp
       ||   0x0001013e      60             pushal
       ||   0x0001013f      31c9           xor ecx, ecx
       ||   0x00010141      51             push ecx
       ||   0x00010142      b900000100     mov ecx, 0x10000            ; section.ehdr
       ||   0x00010147      5a             pop edx
       ||   0x00010148      89d3           mov ebx, edx
      .---> 0x0001014a      8a19           mov bl, byte [ecx]
      |||   0x0001014c      01da           add edx, ebx
      |||   0x0001014e      41             inc ecx
      |||   0x0001014f      81f972010100   cmp ecx, 0x10172
      `===< 0x00010155      75f3           jne 0x1014a
      ,===< 0x00010157      eb01           jmp 0x1015a
      |||   0x00010159      cd66           int 0x66                    ; 'f'
       ||   0x0001015b      3b1572010100   cmp edx, dword [0x10172]    ; [0x10172:4]=0xffff7f6d
       |`=< 0x00010161      0f851fffffff   jne 0x10086
       |    0x00010167      61             popal
       |,=< 0x00010168      eb01           jmp 0x1016b
       ||   0x0001016a      c9             leave
       |`-> 0x0001016b      cd80           int 0x80
       `==< 0x0001016d      e966ffffff     jmp 0x100d8
            0x00010172      6d             insd dword es:[edi], dx
        ,=< 0x00010173      7fff           jg 0x10174
[0x00010320]> pd @0x100d8
       .--> 0x000100d8      b801000000     mov eax, 1
       ||   0x000100dd      bb00000000     mov ebx, 0
       ||   0x000100e2      cd80           int 0x80
[0x00010320]> pfw @0x10172
0x00010172 = 0x7f6d
[0x00010320]> ?d pushad
push all general-purpose registers
```

Once again, a pushad. Since the pushad opcode might not be obvious for everyone. This will push on the stack the following registers:
```
1. eax = 0x4
2. ebx = 0x1
3. ecx = the previously deciphered text + 1
4. edx = 0x8
```

After the checksum, registers are poped back, and a syscall (0x80) occurs. It's likely a call to sys_write; Then a jump to the sys_exit of badboy.

### Patching

To sum up, we need to invert the jump at 0x10084, bypass the final chechsum at 0x10161 (Since it will detect the modification at 0x10084).

First patch:

```nasm
[0x00010320]> s 0x10084
[0x00010084]> pd 1
        ,=< 0x00010084      755e           jne 0x100e4
[0x00010084]> oo+
File ./crackme.03 reopened in read-write mode
Warning: Cannot initialize section headers
Warning: Cannot initialize strings table
Warning: Cannot initialize dynamic strings
[0x00010084]> wx 74
[0x00010084]> pd 1
        ,=< 0x00010084      745e           je 0x100e4
[0x00010084]> oo
File ./crackme.03 reopened in read-only mode
Warning: Cannot initialize section headers
Warning: Cannot initialize strings table
Warning: Cannot initialize dynamic strings
```

If you open your intel manual, you'll see that the opcode for jnz is 75, and the one for jz is 74. But you may not know every correspondences. Fortunately, radare2 provides more convenients way.

Second patch:

```nasm
[0x00010020]> s 0x10161
[0x00010161]> pd 1
        `=< 0x00010161      0f851fffffff   jne 0x10086
[0x00010161]> oo+
File ./crackme.03 reopened in read-write mode
Warning: Cannot initialize section headers
Warning: Cannot initialize strings table
Warning: Cannot initialize dynamic strings
[0x00010161]> wa je 0x10086
Written 6 bytes (je 0x10086) = wx 0f841fffffff
[0x00010161]> pd 1
        `=< 0x00010161      0f841fffffff   je 0x10086
[0x00010161]> oo
File ./crackme.03 reopened in read-only mode
Warning: Cannot initialize section headers
Warning: Cannot initialize strings table
Warning: Cannot initialize dynamic strings
```

Let's check that everything is working:
```sh
# ./crackme.03 
Omedetou
```

## Reference

- [Defeating crackme03 with radare2](https://dustri.org/b/defeating-crackme03-with-radare2.html)




