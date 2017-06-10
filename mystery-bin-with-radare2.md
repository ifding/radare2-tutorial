
# Mystery bin with Radare2

Radare is an open source reversing framework. It comes with a ton of options, functionality, and a somewhat daunting learning curve. It's a powerful tool, and so [superkojiman](https://github.com/superkojiman) have come up with this guide to give people a kick start to the path of reversing with Radare2.

The best way to learn is to just dive in, so get the `mystery.bin` from the [source code](mystery.c) follow along. I'll be using a lot of commands within Radare2, and if you need more information on a particular command, just add a `?` at the end of it for a description. For example, `p?` will tell you what the p series of commands do.

## File information

Let's run the binary and see what we're up against:
```sh
$ ./mystery.bin
Enter password: foobar
Got [foobar]
Fail!
```

It prompts us for a password, and if we get it wrong, it print out "Fail!". We'll load it up in Radare2 using the r2 command:
```sh
$ r2 mystery.bin
[0x100000e50]>
```

The address in the prompt is the current location the cursor is on. We can get some information on the file using the `iI` command:
```sh
[0x100000e50]> iI
arch     x86
binsz    8716
bintype  mach0
bits     64
canary   true
class    MACH064
crypto   false
endian   little
havecode true
intrp    /usr/lib/dyld
lang     c
linenum  false
lsyms    false
machine  x86 64 all
maxopsz  16
minopsz  1
nx       false
os       osx
pcalign  0
pic      true
relocs   false
static   false
stripped false
subsys   darwin
va       true
```

Lots of information here. `pic true`, `canary true` and `nx false` tell us that it has PIE, stack canary, but has NX disenabled. It also tells us that it's Mach-O 64-bit executable x86_64 binary.

To find the binary's entry point, as well as main's address, we can use the `ie` and `iM` commands respectively:
```sh
[0x100000e50]> ie
[Entrypoints]
vaddr=0x100000e50 paddr=0x00000e50 baddr=0x100000000 laddr=0x00000000 haddr=0x00000508 type=program

1 entrypoints

[0x100000e50]> iM
[Main]
vaddr=0x100000e50 paddr=0x100000e50
```

*vaddr* is the address of the entry point and of the main. The next thing we might be interested in are symbols in the binary. This can be examined with the `is` command:
```sh
[0x100000e50]> is
[Symbols]
vaddr=0x100000000 paddr=0x00000000 ord=000 fwd=NONE sz=0 bind=GLOBAL type=FUNC name=__mh_execute_header
vaddr=0x100000e10 paddr=0x00000e10 ord=001 fwd=NONE sz=0 bind=GLOBAL type=FUNC name=_check_pass_len
vaddr=0x100000ce0 paddr=0x00000ce0 ord=002 fwd=NONE sz=0 bind=GLOBAL type=FUNC name=_check_password
vaddr=0x100000e50 paddr=0x00000e50 ord=003 fwd=NONE sz=0 bind=GLOBAL type=FUNC name=_main
vaddr=0x100000f2a paddr=0x00000f2a ord=004 fwd=NONE sz=0 bind=LOCAL type=FUNC name=imp.__stack_chk_fail
vaddr=0x100000f30 paddr=0x00000f30 ord=005 fwd=NONE sz=0 bind=LOCAL type=FUNC name=imp.printf
vaddr=0x100000f36 paddr=0x00000f36 ord=006 fwd=NONE sz=0 bind=LOCAL type=FUNC name=imp.scanf
vaddr=0x100000ce0 paddr=0x00000ce0 ord=007 fwd=NONE sz=0 bind=LOCAL type=FUNC name=func.100000ce0
vaddr=0x100000e10 paddr=0x00000e10 ord=008 fwd=NONE sz=0 bind=LOCAL type=FUNC name=func.100000e10
vaddr=0x100000e50 paddr=0x00000e50 ord=009 fwd=NONE sz=0 bind=LOCAL type=FUNC name=func.100000e50

10 symbols
```

Here we see references to printf and scanf.

We know the binary prints out "Fails!" when the incorrect password is provided. What other strings could it have? To check, we can use the `iz` command:
```sh
[0x100000e50]> iz
vaddr=0x100000f6a paddr=0x00000f6a ordinal=000 sz=17 len=16 section=3.__TEXT.__cstring type=ascii string=Enter password: 
vaddr=0x100000f7e paddr=0x00000f7e ordinal=001 sz=10 len=9 section=3.__TEXT.__cstring type=ascii string=Got [%s]\n
vaddr=0x100000f88 paddr=0x00000f88 ordinal=002 sz=6 len=5 section=3.__TEXT.__cstring type=ascii string=Win!\n
vaddr=0x100000f8e paddr=0x00000f8e ordinal=003 sz=7 len=6 section=3.__TEXT.__cstring type=ascii string=Fail!\n
```

We can also use the `/` operator to look for specific strings, or bytes:
```sh
[0x100000e50]> / Win
Searching 3 bytes from 0x100000ce0 to 0x100001030: 57 69 6e 
Searching 3 bytes in [0x100000ce0-0x100001030]
hits: 1
0x100000f88 hit0_0 .: %sGot [%s]Win!Fail!.
```

Obviously we want to see the "%sGot [%s]Win!Fail!." message get printed, and that's the whole point of this reversing exercise. To find out where it's being referenced from, we need to analyze all the functions first using the `aaa` command. Once that's done, we can use the `axt` command:
```
[0x100000e50]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[ ] [*] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan))
[0x100000e50]> axt 0x100000f88
data 0x100000ee1 lea rdi, str.Win__n in entry0
```

Here we see that it's being used in main. Aside from variables, `axt` can be also used to find references to a function. For example, to find functions that call printf:
```sh
[0x100000e50]> axt sym.imp.printf
call 0x100000e87 call sym.imp.printf in entry0
call 0x100000eb1 call sym.imp.printf in entry0
call 0x100000f00 call sym.imp.printf in entry0
call 0x100000eea call sym.imp.printf in entry0
```

So far so good. We've identified a `%sGot [%s]Win!Fail!.` message we want to end up in, and we know which function is referencing it.

## Working with functions

The next step is to have a look at what functions are available in the binary. As before, we need to analyze all the functions first using `aaa`. Then we can use the `afl` command to list all analyzed functions:
```sh
[0x100000e50]> aaa
[0x100000e50]> afl
0x100000ce0   24 302          sym._check_password
0x100000e10    4 60           sym._check_pass_len
0x100000e50    7 217          entry0
0x100000f2a    1 6            sym.imp.__stack_chk_fail
0x100000f30    1 6            sym.imp.printf
0x100000f36    1 6            sym.imp.scanf
```

Several functions have been analyzed, and we can disassemble them using the `pdf` command. Let's start by analyzing `entry0` since it references the `%sGot [%s]Win!Fail!.` string we're interested in. 

We can seek to entry0's location first, and then run `pdf` without having to provide `@entry0`. Radare2's prompt shows the address of where the cursor is currently located. Seeking allows us to change the current location, so the commands will apply to the current location. Otherwise, we would need to use the `@address` syntax. Seeking is done with the `s` command:
```sh
[0x00000000]> s entry0
[0x100000e50]> pdf
            ;-- _main:
            ;-- func.100000e50:
/ (fcn) entry0 217
|   entry0 ();
|           ; var int local_40h @ rbp-0x40
|           ; var int local_3ch @ rbp-0x3c
|           ; var int local_38h @ rbp-0x38
|           ; var int local_34h @ rbp-0x34
|           ; var int local_30h @ rbp-0x30
|           ; var int local_2ch @ rbp-0x2c
|           ; var int local_28h @ rbp-0x28
|           ; var int local_1ch @ rbp-0x1c
|           ; var int local_18h @ rbp-0x18
|           ; var int local_12h @ rbp-0x12
|           ; var int local_8h @ rbp-0x8
|           0x100000e50      55             push rbp
|           0x100000e51      4889e5         mov rbp, rsp
|           0x100000e54      4883ec40       sub rsp, 0x40              ; '@'
|           0x100000e58      488d050b0100.  lea rax, str.Enter_password: ; section.3.__TEXT.__cstring ; 0x100000f6a ; "Enter password: "
|           0x100000e5f      488b0daa0100.  mov rcx, qword [reloc.__stack_chk_guard_16] ; [0x100001010:8]=0
|           0x100000e66      488b09         mov rcx, qword [rcx]
|           0x100000e69      48894df8       mov qword [local_8h], rcx
|           0x100000e6d      c745e8000000.  mov dword [local_18h], 0
|           0x100000e74      897de4         mov dword [local_1ch], edi
|           0x100000e77      488975d8       mov qword [local_28h], rsi
|           0x100000e7b      c745d4000000.  mov dword [local_2ch], 0
|           0x100000e82      4889c7         mov rdi, rax
|           0x100000e85      b000           mov al, 0
|           0x100000e87      e8a4000000     call sym.imp.printf        ; int printf(const char *format)
|           0x100000e8c      488d3de80000.  lea rdi, 0x100000f7b       ; "%s"
|           0x100000e93      488d75ee       lea rsi, [local_12h]
|           0x100000e97      8945d0         mov dword [local_30h], eax
|           0x100000e9a      b000           mov al, 0
|           0x100000e9c      e895000000     call sym.imp.scanf         ; int scanf(const char *format)
|           0x100000ea1      488d3dd60000.  lea rdi, str.Got___s__n    ; 0x100000f7e ; "Got [%s]\n"
|           0x100000ea8      488d75ee       lea rsi, [local_12h]
|           0x100000eac      8945cc         mov dword [local_34h], eax
|           0x100000eaf      b000           mov al, 0
|           0x100000eb1      e87a000000     call sym.imp.printf        ; int printf(const char *format)
|           0x100000eb6      488d7dee       lea rdi, [local_12h]
|           0x100000eba      8945c8         mov dword [local_38h], eax
|           0x100000ebd      e84effffff     call sym._check_pass_len
|           0x100000ec2      3d0a000000     cmp eax, 0xa
|       ,=< 0x100000ec7      0f852a000000   jne 0x100000ef7
|       |   0x100000ecd      488d7dee       lea rdi, [local_12h]
|       |   0x100000ed1      e80afeffff     call sym._check_password
|       |   0x100000ed6      3d00000000     cmp eax, 0
|      ,==< 0x100000edb      0f8516000000   jne 0x100000ef7
|      ||   0x100000ee1      488d3da00000.  lea rdi, str.Win__n        ; hit0_0 ; 0x100000f88 ; "Win!\n"
|      ||   0x100000ee8      b000           mov al, 0
|      ||   0x100000eea      e841000000     call sym.imp.printf        ; int printf(const char *format)
|      ||   0x100000eef      8945c4         mov dword [local_3ch], eax
|     ,===< 0x100000ef2      e911000000     jmp 0x100000f08
|     |||      ; JMP XREF from 0x100000ec7 (entry0)
|     |||      ; JMP XREF from 0x100000edb (entry0)
|     |``-> 0x100000ef7      488d3d900000.  lea rdi, str.Fail__n       ; 0x100000f8e ; "Fail!\n"
|     |     0x100000efe      b000           mov al, 0
|     |     0x100000f00      e82b000000     call sym.imp.printf        ; int printf(const char *format)
|     |     0x100000f05      8945c0         mov dword [local_40h], eax
|     |        ; JMP XREF from 0x100000ef2 (entry0)
|     `---> 0x100000f08      488b05010100.  mov rax, qword [reloc.__stack_chk_guard_16] ; [0x100001010:8]=0
|           0x100000f0f      488b00         mov rax, qword [rax]
|           0x100000f12      483b45f8       cmp rax, qword [local_8h]
|       ,=< 0x100000f16      0f8508000000   jne 0x100000f24
|       |   0x100000f1c      31c0           xor eax, eax
|       |   0x100000f1e      4883c440       add rsp, 0x40              ; '@'
|       |   0x100000f22      5d             pop rbp
|       |   0x100000f23      c3             ret
|       |      ; JMP XREF from 0x100000f16 (entry0)
\       `-> 0x100000f24      e801000000     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
```

The first column shows the address of each instruction, the second column shows the opcodes of the instruction, and the third column shows the instruction itself. A fourth column exists to display any available comments. It's also possible to display the first 10 lines of `entry0`, you could do `pd 10`. The arrows on the left of the addresses depict where execution branches off to when a jump instruction is encountered.

At `0x100000ed1`, entry0 calls a function sym._check_password. We can see that a value is moved to `rdi` before the function is called. This implies that it takes an argument; and in this case, it's the password that we enter. Let's examine this function.
```sh
[0x100000ce0]> s sym._check_pass_len
[0x100000e10]> pdf
            ;-- func.100000e10:
/ (fcn) sym._check_pass_len 60
|   sym._check_pass_len ();
|           ; var int local_ch @ rbp-0xc
|           ; var int local_8h @ rbp-0x8
|              ; CALL XREF from 0x100000ebd (entry0)
|           0x100000e10      55             push rbp
|           0x100000e11      4889e5         mov rbp, rsp
|           0x100000e14      48897df8       mov qword [local_8h], rdi
|           0x100000e18      c745f4000000.  mov dword [local_ch], 0
|              ; JMP XREF from 0x100000e42 (sym._check_pass_len)
|       .-> 0x100000e1f      486345f4       movsxd rax, dword [local_ch]
|       |   0x100000e23      488b4df8       mov rcx, qword [local_8h]
|       |   0x100000e27      0fbe1401       movsx edx, byte [rcx + rax]
|       |   0x100000e2b      81fa00000000   cmp edx, 0
|      ,==< 0x100000e31      0f8410000000   je 0x100000e47
|      ||   0x100000e37      8b45f4         mov eax, dword [local_ch]
|      ||   0x100000e3a      0501000000     add eax, 1
|      ||   0x100000e3f      8945f4         mov dword [local_ch], eax
|      |`=< 0x100000e42      e9d8ffffff     jmp 0x100000e1f
|      |       ; JMP XREF from 0x100000e31 (sym._check_pass_len)
|      `--> 0x100000e47      8b45f4         mov eax, dword [local_ch]
|           0x100000e4a      5d             pop rbp
\           0x100000e4b      c3             ret
```

So at first glance, we can see that
- Radare2 identified two local variables, local_ch, and local_8h.
- There are two branching conditions in the function.

Let's see if we can figure out what these local variables are. The first reference to local_8h occurs at `0x100000e14`:
```nasm
mov qword [local_8h], rdi
```

We know rdi contains the password we input, so it would seem that local_8h is a copy of that password. Right after that, we see that local_ch is set to 0:
```nasm
mov dword [local_ch], 0
```

After initializing it to 0, it performs several instructions which basically checks to see it the first character in the password is a null byte. If it isn't, local_ch is then incremented by 1:
```nasm
mov eax, dword [local_ch]
add eax, 1
mov dword [local_ch], eax
```

At this point, execution jumps to `0x100000e1f`. It then takes the second character in the password and repeats over again until it eventually finds a null byte, at which point it returns the value in local_ch to the calling function. So it'safe to assume that local_ch must be a loop counter, and this function's purpose is simply check the length of the entered password.

Radare2 allows us to rename functions and variables to things that make sense to us.
```sh
[0x100000ce0]> afn check_pass_len
[0x100000ce0]> afvn local_ch counter
[0x100000ce0]> afvn local_8h password 
```

## Graphs

Now that we have a better understanding of what check_password_len does, let's move on to the next function: sym._check_password.
```sh
[0x100000e50]> s sym._check_password
[0x100000ce0]> pdf
            ;-- section.0.__TEXT.__text:
            ;-- func.100000ce0:
/ (fcn) sym._check_password 302
|   sym._check_password ();
|           ; var int local_14h @ rbp-0x14
|           ; var int local_10h @ rbp-0x10
|           ; var int local_4h @ rbp-0x4
|              ; CALL XREF from 0x100000ed1 (entry0)
|           0x100000ce0      55             push rbp                   ; section 0 va=0x100000ce0 pa=0x00000ce0 sz=585 vsz=585 rwx=m-r-x 0.__TEXT.__text
|           0x100000ce1      4889e5         mov rbp, rsp
|           0x100000ce4      48897df0       mov qword [local_10h], rdi
|           0x100000ce8      c745ec000000.  mov dword [local_14h], 0
|           0x100000cef      488b7df0       mov rdi, qword [local_10h]
|           0x100000cf3      0fbe07         movsx eax, byte [rdi]
|           0x100000cf6      3d68000000     cmp eax, 0x68              ; 'h' ; 'h'
|       ,=< 0x100000cfb      0f856b000000   jne 0x100000d6c
|       |   0x100000d01      488b45f0       mov rax, qword [local_10h]
|       |   0x100000d05      0fbe4801       movsx ecx, byte [rax + 1]  ; [0x1:1]=250
|       |   0x100000d09      81f965000000   cmp ecx, 0x65              ; 'e' ; 'e'
|      ,==< 0x100000d0f      0f8552000000   jne 0x100000d67
|      ||   0x100000d15      488b45f0       mov rax, qword [local_10h]
|      ||   0x100000d19      0fbe4802       movsx ecx, byte [rax + 2]  ; [0x2:1]=237
|      ||   0x100000d1d      81f96c000000   cmp ecx, 0x6c              ; 'l' ; 'l' ; "(."
|     ,===< 0x100000d23      0f8539000000   jne 0x100000d62
|     |||   0x100000d29      488b45f0       mov rax, qword [local_10h]
|     |||   0x100000d2d      0fbe4803       movsx ecx, byte [rax + 3]  ; [0x3:1]=254
|     |||   0x100000d31      81f96c000000   cmp ecx, 0x6c              ; 'l' ; 'l' ; "(."
|    ,====< 0x100000d37      0f8520000000   jne 0x100000d5d
|    ||||   0x100000d3d      488b45f0       mov rax, qword [local_10h]
|    ||||   0x100000d41      0fbe4804       movsx ecx, byte [rax + 4]  ; [0x4:1]=7
|    ||||   0x100000d45      81f96f000000   cmp ecx, 0x6f              ; 'o' ; 'o'
|   ,=====< 0x100000d4b      0f8507000000   jne 0x100000d58
|   |||||   0x100000d51      c745ec010000.  mov dword [local_14h], 1
|   |||||      ; JMP XREF from 0x100000d4b (sym._check_password)
|  ,`-----> 0x100000d58      e900000000     jmp 0x100000d5d
|  | ||||      ; JMP XREF from 0x100000d58 (sym._check_password)
|  | ||||      ; JMP XREF from 0x100000d37 (sym._check_password)
|  `,`----> 0x100000d5d      e900000000     jmp 0x100000d62
|   | |||      ; JMP XREF from 0x100000d5d (sym._check_password)
|   | |||      ; JMP XREF from 0x100000d23 (sym._check_password)
|   `,`---> 0x100000d62      e900000000     jmp 0x100000d67
|    | ||      ; JMP XREF from 0x100000d62 (sym._check_password)
|    | ||      ; JMP XREF from 0x100000d0f (sym._check_password)
|    `,`--> 0x100000d67      e900000000     jmp 0x100000d6c
|     | |      ; JMP XREF from 0x100000d67 (sym._check_password)
|     | |      ; JMP XREF from 0x100000cfb (sym._check_password)
|     `-`-> 0x100000d6c      817dec000000.  cmp dword [local_14h], 0
|       ,=< 0x100000d73      0f8489000000   je 0x100000e02
|       |   0x100000d79      488b45f0       mov rax, qword [local_10h]
|       |   0x100000d7d      0fbe4805       movsx ecx, byte [rax + 5]  ; [0x5:1]=0
|       |   0x100000d81      81f977000000   cmp ecx, 0x77              ; 'w' ; 'w'
|      ,==< 0x100000d87      0f8570000000   jne 0x100000dfd
|      ||   0x100000d8d      488b45f0       mov rax, qword [local_10h]
|      ||   0x100000d91      0fbe4806       movsx ecx, byte [rax + 6]  ; [0x6:1]=0
|      ||   0x100000d95      81f96f000000   cmp ecx, 0x6f              ; 'o' ; 'o'
|     ,===< 0x100000d9b      0f8557000000   jne 0x100000df8
|     |||   0x100000da1      488b45f0       mov rax, qword [local_10h]
|     |||   0x100000da5      0fbe4807       movsx ecx, byte [rax + 7]  ; [0x7:1]=1
|     |||   0x100000da9      81f972000000   cmp ecx, 0x72              ; 'r' ; 'r' ; "TEXT"
|    ,====< 0x100000daf      0f853e000000   jne 0x100000df3
|    ||||   0x100000db5      488b45f0       mov rax, qword [local_10h]
|    ||||   0x100000db9      0fbe4808       movsx ecx, byte [rax + 8]  ; [0x8:1]=3
|    ||||   0x100000dbd      81f96c000000   cmp ecx, 0x6c              ; 'l' ; 'l' ; "(."
|   ,=====< 0x100000dc3      0f8525000000   jne 0x100000dee
|   |||||   0x100000dc9      488b45f0       mov rax, qword [local_10h]
|   |||||   0x100000dcd      0fbe4809       movsx ecx, byte [rax + 9]  ; [0x9:1]=0
|   |||||   0x100000dd1      81f964000000   cmp ecx, 0x64              ; 'd' ; 'd'
|  ,======< 0x100000dd7      0f850c000000   jne 0x100000de9
|  ||||||   0x100000ddd      c745fc000000.  mov dword [local_4h], 0
| ,=======< 0x100000de4      e920000000     jmp 0x100000e09
| |||||||      ; JMP XREF from 0x100000dd7 (sym._check_password)
| =`------> 0x100000de9      e900000000     jmp 0x100000dee
| | |||||      ; JMP XREF from 0x100000de9 (sym._check_password)
| | |||||      ; JMP XREF from 0x100000dc3 (sym._check_password)
| -,`-----> 0x100000dee      e900000000     jmp 0x100000df3
| || ||||      ; JMP XREF from 0x100000dee (sym._check_password)
| || ||||      ; JMP XREF from 0x100000daf (sym._check_password)
| |`,`----> 0x100000df3      e900000000     jmp 0x100000df8
| | | |||      ; JMP XREF from 0x100000df3 (sym._check_password)
| | | |||      ; JMP XREF from 0x100000d9b (sym._check_password)
| | `,`---> 0x100000df8      e900000000     jmp 0x100000dfd
| |  | ||      ; JMP XREF from 0x100000df8 (sym._check_password)
| |  | ||      ; JMP XREF from 0x100000d87 (sym._check_password)
| |  `,`--> 0x100000dfd      e907000000     jmp 0x100000e09
| |   | |      ; JMP XREF from 0x100000d73 (sym._check_password)
| |   | `-> 0x100000e02      c745fcffffff.  mov dword [local_4h], 0xffffffff
| |   |        ; JMP XREF from 0x100000dfd (sym._check_password)
| |   |        ; JMP XREF from 0x100000de4 (sym._check_password)
| `---`---> 0x100000e09      8b45fc         mov eax, dword [local_4h]
|           0x100000e0c      5d             pop rbp
\           0x100000e0d      c3             ret
```

Look at all those arrows! There's a lot of branching goin on, so let's switch to Radare's visual mode to see a graph of what's happening. Use the `VV` command to enter visual mode.
```sh
[0x100000ce0]> VV @ sym._check_password (nodes 24 edges 34 zoom 100%) BB-NORM mouse:canvas-y movements-speed:5           


          .----------------------------------------------------------------------------------------.
          |  0x100000ce0 ;[gb]                                                                     |
          |      ; section 0 va=0x100000ce0 pa=0x00000ce0 sz=585 vsz=585 rwx=m-r-x 0.__TEXT.__text |
          |   ;-- section.0.__TEXT.__text:                                                         |
          |   ;-- func.100000ce0:                                                                  |
          | (fcn) sym._check_password 302                                                          |
          |   sym._check_password ();                                                              |
          | ; var int local_14h @ rbp-0x14                                                         |
          | ; var int local_10h @ rbp-0x10                                                         |
          | ; var int local_4h @ rbp-0x4                                                           |
          |    ; CALL XREF from 0x100000ed1 (entry0)                                               |
          | push rbp                                                                               |
          | mov rbp, rsp                                                                           |
          | mov qword [local_10h], rdi                                                             |
          | mov dword [local_14h], 0                                                               |
          | mov rdi, qword [local_10h]                                                             |
          | movsx eax, byte [rdi]                                                                  |
          |    ; 'h'                                                                               |
          |    ; 'h'                                                                               |
          | cmp eax, 0x68                                                                          |
          | jne 0x100000d6c;[ga]                                                                   |
          `----------------------------------------------------------------------------------------'
                  f t
                  '-------------------.---------------------------.
                                      |                           |
                                      |                           |
                              .----------------------------.      |
                              | [0x100000d01] ;[gd]        |      |
                              | mov rax, qword [local_10h] |      |
                              |    ; [0x1:1]=250           |      |
                              | movsx ecx, byte [rax + 1]  |      |
                              |    ; 'e'                   |      |
                              |    ; 'e'                   |      |
                              | cmp ecx, 0x65              |      |

```

Radare2 displays an ASCII graph of the function being analyzed. Now we can clearly see where the branching is taking place. Notice that Radare2 also puts a "t" and "f" under each condition to signify "true" and "false" respectively. Visual mode has its own set of commands, such as:
- hjkl      scroll canvas
- HJKL      move node
- tab/TAB   select next/previous node
- t/f       follow true/false edges
- .         center the graph
- p         press repeatedly to change graph view

If we press p several times, we eventually get a mini-graph view. Using tab, we can move to the next node and Radare2 will display the instructions in that node on the top left corner. The graph depicts a series of nested if conditions where it checks to see it each character in the password we provided, matches a certain character. So basically, this function returns 0 if our input matches the expected password.

## Adding comments

We can add a comment, which can make it easier to understand. For example, we add a comment for sym._check_password:
```sh
[0x100000ce0]> CC Returns 0 when password is 'helloworld'
[0x100000ce0]> pd 10
            ;-- section.0.__TEXT.__text:
            ;-- func.100000ce0:
/ (fcn) sym._check_password 302
|   sym._check_password ();
|           ; var int local_14h @ rbp-0x14
|           ; var int local_10h @ rbp-0x10
|           ; var int local_4h @ rbp-0x4
|              ; CALL XREF from 0x100000ed1 (entry0)
|           0x100000ce0      55             push rbp                   ; section 0 va=0x100000ce0 pa=0x00000ce0 sz=585 vsz=585 rwx=m-r-x 0.__TEXT.__text Returns 0 when password is 'helloworld'
|           0x100000ce1      4889e5         mov rbp, rsp
|           0x100000ce4      48897df0       mov qword [local_10h], rdi
|           0x100000ce8      c745ec000000.  mov dword [local_14h], 0
|           0x100000cef      488b7df0       mov rdi, qword [local_10h]
|           0x100000cf3      0fbe07         movsx eax, byte [rdi]
|           0x100000cf6      3d68000000     cmp eax, 0x68              ; 'h' ; 'h'
|       ,=< 0x100000cfb      0f856b000000   jne 0x100000d6c
|       |   0x100000d01      488b45f0       mov rax, qword [local_10h]
|       |   0x100000d05      0fbe4801       movsx ecx, byte [rax + 1]  ; [0x1:1]=250
```

We've solved this easy binary challenge. Let's see it in action:
```sh
$ ./mystery.bin
Enter password: helloworld
Got [helloworld]
Win!
```

## Conclusion

Hopefully this this guide has given you a taste of Radare’s potential. Other things it can do include debugging the binary, looking for ROP gadgets, importing signatures, and so on. Radare also offers a help system, just type ? to get a list of commands. If you’ve found Radare interesting so far, I encourage you to play around with it some more. [Download](https://github.com/ctfs) some binary challenges and take Radare to town.

## Reference

- [Radare 2 in 0x1E minutes](https://blog.techorganic.com/2016/03/08/radare-2-in-0x1e-minutes/)

