
# Reverse Engineering With Radare2

In [the last article](introduction_to_radare2.md), we explore the basics of radare2. We are going to write a simple program, and then disassemble it, to see what is really doing in the processor.

Not all architectures have the same set of instructions, the most important difference is between Reduced Instruction Set Computing (embedded systems, PMDs ...) and Complex Instruction Set Computing (clusters, desktop computing ...). An example of RISC could be ARM and CISC could be x86.

Radare2 is an open source set of tools for reverse engineering and analysis of binary files (among other things, for example debugging). In this article we will cover two: rasm2 and r2.

## rasm2

It is used to assemble or disassemble files or hexpair strings. You can see the help screen:
```sh
$ rasm2 -h
Usage: rasm2 [-ACdDehLBvw] [-a arch] [-b bits] [-o addr] [-s syntax]
             [-f file] [-F fil:ter] [-i skip] [-l len] 'code'|hex|-
 -a [arch]    Set architecture to assemble/disassemble (see -L)
 -A           Show Analysis information from given hexpairs
 -b [bits]    Set cpu register size (8, 16, 32, 64) (RASM2_BITS)
 -c [cpu]     Select specific CPU (depends on arch)
 -C           Output in C format
 -d, -D       Disassemble from hexpair bytes (-D show hexpairs)
 -e           Use big endian instead of little endian
 -E           Display ESIL expression (same input as in -d)
 -f [file]    Read data from file
 -F [in:out]  Specify input and/or output filters (att2intel, x86.pseudo, ...)
 -h, -hh      Show this help, -hh for long
 -i [len]     ignore/skip N bytes of the input buffer
 -k [kernel]  Select operating system (linux, windows, darwin, ..)
 -l [len]     Input/Output length
 -L           List Asm plugins: (a=asm, d=disasm, A=analyze, e=ESIL)
 -o [offset]  Set start address for code (default 0)
 -O [file]    Output file name (rasm2 -Bf a.asm -O a)
 -p           Run SPP over input for assembly
 -s [syntax]  Select syntax (intel, att)
 -B           Binary input/output (-l is mandatory for binary input)
 -v           Show version information
 -w           What's this instruction for? describe opcode
 -q           quiet mode
 If '-l' value is greater than output length, output is padded with nops
 If the last argument is '-' reads from stdin
Environment:
 RASM2_NOPLUGINS  do not load shared plugins (speedup loading)
 R_DEBUG          if defined, show error messages and crash signal
```

The option `-d`, disassemble from hexpair bytes. For example, 90 corresponds to a nop operation. To disassemble hexadecimal code, type:
```sh
$ rasm2 -d <hexadecimal>
$ rasm2 -d 90
```

If you want to get the hexadecimal code of an instruction:
```sh
$ rasm2 "<instruction>"
$ rasm2 "nop"
```

## r2

let's write a simple code that adds two variables.
```sh
$ cat test.c
#include <stdio.h>

int main()
{
	int a = 10;
	int b = 20;
	int c = a+b;
	return 0;
}

$ gcc -o test test.c
```

Once we have the binary file, let's disassemble it.
```sh
$ r2 -vv
radare2 1.5.0 0 @ darwin-x86-64 git.1.5.0
$ r2 test
```

At this point, analyze the whole code: `aa` (analyze all).

Let's see the main function: `pdf @ main` (print disassemble function)
```nasm
            ;-- main:
            ;-- section.0.__TEXT.__text:
            ;-- func.100000f70:
/ (fcn) entry0 38
|   entry0 ();
|           ; var int local_10h @ rbp-0x10
|           ; var int local_ch @ rbp-0xc
|           ; var int local_8h @ rbp-0x8
|           ; var int local_4h @ rbp-0x4
|           0x100000f70      55             push rbp                   ; section 0 va=0x100000f70 pa=0x00000f70 sz=38 vsz=38 rwx=m-r-x 0.__TEXT.__text
|           0x100000f71      4889e5         mov rbp, rsp
|           0x100000f74      31c0           xor eax, eax
|           0x100000f76      c745fc000000.  mov dword [local_4h], 0
|           0x100000f7d      c745f80a0000.  mov dword [local_8h], 0xa
|           0x100000f84      c745f4140000.  mov dword [local_ch], 0x14
|           0x100000f8b      8b4df8         mov ecx, dword [local_8h]
|           0x100000f8e      034df4         add ecx, dword [local_ch]
|           0x100000f91      894df0         mov dword [local_10h], ecx
|           0x100000f94      5d             pop rbp
\           0x100000f95      c3             ret
```

### Exampling assembly instructions

The first two instructions are called prologue:

- `push rbp`     save the old base pointer in the stack to restore it later
- `mov rbp, rsp` copy the stack pointer to the base pointer

Now the base pointer points to the main frame.

- `mov dword [local_4h], 0`     load 0 into rbp-4
- `mov dword [local_8h], 0xa`   load 10 into rbp-8
- `mov dword [local_ch], 0x14`  load 20 into rpb-12

The size of an integer in C is 4 bytes (32 bits), that's the reason why the pointer decrements in 4 (the stack grows downward). The first instruction simply say: laod value 0 below the base pointer, the second instruction says: load value 10 (0xa) below the previous value, the third instruction says: laod value 0x14(20) below the previous value. We have pushed the variable values into the stack.

- `mov ecx, dword [local_8h]`   load value 10 into ecx
- `add ecx, dword [local_ch]`   add ecx, rbp-12 and store result in ecx
- `mov dword [local_10h], ecx`  load the result into rbp-16.

We load the values into general purpose registers, to perform the ALU operation (add). Finally we store the sum result below rbp-12.

The last two instructions are called epilogue. We pop the old base pointer off the stack and store it in rbp, then we jump to the return address (which is also in the stack).
```nasm
pop rbp
ret
```

A final note: The assembly code generated is different depending on the compiler and system.

## Reference

- [Reverse Engineering with Radare2 (A Quick Introduction)](https://null-byte.wonderhowto.com/how-to/reverse-engineering-with-radare2-a-quick-introduction-0165996/)
