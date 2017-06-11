
# Defeating ioli with radare2 

This post is from [here](https://dustri.org/b/defeating-ioli-with-radare2.html)

Enjoy a completely rewritten reverse-engeenering tutorial proudly powered by radare2 !

Grab [radare2](http://www.radare.org/y/), an [asm cheat sheet](http://www.jegerlehner.ch/intel/),
the IOLI crackme bin file (linux, win32 and pocketPC) [download from here](IOLI-crackme.zip), and geat ready.

## Gathering information

In this case it is not really needed, but in general, you will want to gather as much information about the target as you want. You may also want to run it on a VM and actually take a snapshot before you start. Specially if you do dynamic analysis and you do not know what the sample does (backdoor, worm, virus, ...)

Some tools you may want to use:
- file patchme
- sttrings patchme
- xxd patchme | less
- readelf -h ./patchme |grep Entry
- ogjdump -Mintel -D ./patchme | grep "main>:" -A 8

In this case, we already know everything for this program. After all, we wrote it ourselves, so let's go straight into the reverse stuff.

## crackme 0x00

This is the first crackme, the easiest one.

    $ ./crackme0x00
    OLI Crackme Level 0x00
    Password: 1234
    Invalid Password!

Maybe the password is in plain text inside it.
No need to disassemble here, we'll just use _rabin2_, the
"binary program info extractor" from radare2.

The rabin2's option to show strings contained in a binary is _-z_ (_man rabin2_)

    $ rabin2 -z ./crackme0x00
    [strings]
    addr=0x08048568 off=0x00000568 ordinal=000 sz=24 section=.rodata string=IOLICrackmeLevel0x00
    addr=0x08048581 off=0x00000581 ordinal=001 sz=11 section=.rodata string=Password
    addr=0x0804858f off=0x0000058f ordinal=002 sz=7 section=.rodata string=250382
    addr=0x08048596 off=0x00000596 ordinal=003 sz=18 section=.rodata string=InvalidPassword!
    addr=0x080485a9 off=0x000005a9 ordinal=004 sz=15 section=.rodata string=PasswordOK

    5 strings

What is 250382 ?

    $ ./crackme0x00
    IOLI Crackme Level 0x00
    Password: 250382
    Password OK :)

## crackme0x01
This time, no luck with _rabin2 -z_.
Let's check with _radare2_.

    $ r2 ./crackme0x01
    [0x08048330]> aa
    [0x08048330]> pdf@sym.main
    / function: sym.main (113)
    |       0x080483e4  sym.main:
    |       0x080483e4     55               push ebp
    |       0x080483e5     89e5             mov ebp, esp
    |       0x080483e7     83ec18           sub esp, 0x18
    |       0x080483ea     83e4f0           and esp, 0xfffffff0
    |       0x080483ed     b800000000       mov eax, 0x0
    |       0x080483f2     83c00f           add eax, 0xf
    |       0x080483f5     83c00f           add eax, 0xf
    |       0x080483f8     c1e804           shr eax, 0x4
    |       0x080483fb     c1e004           shl eax, 0x4
    |       0x080483fe     29c4             sub esp, eax
    |       0x08048400     c7042428850408   mov dword [esp], str.IOLICrackmeLevel0x01
    |       0x08048407     e810ffffff       call dword imp.printf
    |          ; imp.printf()
    |       0x0804840c     c7042441850408   mov dword [esp], str.Password
    |       0x08048413     e804ffffff       call dword imp.printf
    |          ; imp.printf()
    |       0x08048418     8d45fc           lea eax, [ebp-0x4]
    |       0x0804841b     89442404         mov [esp+0x4], eax
    |       0x0804841f     c704244c850408   mov dword [esp], 0x804854c
    |       0x08048426     e8e1feffff       call dword imp.scanf
    |          ; imp.scanf()
    |       0x0804842b     817dfc9a140000   cmp dword [ebp-0x4], 0x149a
    |   ,=< 0x08048432     740e             jz loc.08048442
    |   |   0x08048434     c704244f850408   mov dword [esp], str.InvalidPassword!
    |   |   0x0804843b     e8dcfeffff       call dword imp.printf
    |   |      ; imp.printf()
    |  ,==< 0x08048440     eb0c             jmp loc.0804844e
    |  ||   ; CODE (JMP) XREF 0x08048432 (sym.main)
    / loc: loc.08048442 (19)
    |  ||   0x08048442  loc.08048442:
    |  |`-> 0x08048442     c7042462850408   mov dword [esp], str.PasswordOK
    |  |    0x08048449     e8cefeffff       call dword imp.printf
    |  |       ; imp.printf()
    |  |    ; CODE (JMP) XREF 0x08048440 (sym.main)
    / loc: loc.0804844e (7)
    |  |    0x0804844e  loc.0804844e:
    |  `--> 0x0804844e     b800000000       mov eax, 0x0
    |       0x08048453     c9               leave
    \       0x08048454     c3               ret

The "aa" commands tells r2 to analyse the whole binary. This will get you nice symbols names and fancy stuffs.
"pdf" stands for

- print
- disassemble
- function

So, this will print the disassembly of sym.main function, aka the main() that every one knows.
Back to the listing, you can see several stuffs: weird names, arrows, ...

- imp. stands for imports. Those are _imported_ symbols, like printf()
- str. stands for strings. Those are strings (no shit !).

If you look carefully, you'll see a _cmp_ instruction, with a constant: 0x149a.
The "0x" in front of it indicates that it's in base 16. You can use radare2's to get it
in another base:

    [0x08048330]> ? 0x149a
    5274 0x149a 012232 10011010 0.000000

Ok, 0x149a is 5274.

    $ ./crackme0x01
    IOLI Crackme Level 0x01
    Password: 5274
    Password OK :)

## crackme0x03

    aa
    pdf@sym.main
    / function: sym.main (128)
    |     0x08048498  sym.main:
    |     0x08048498     55               push ebp
    |     0x08048499     89e5             mov ebp, esp
    |     0x0804849b     83ec18           sub esp, 0x18
    |     0x0804849e     83e4f0           and esp, 0xfffffff0
    |     0x080484a1     b800000000       mov eax, 0x0
    |     0x080484a6     83c00f           add eax, 0xf
    |     0x080484a9     83c00f           add eax, 0xf
    |     0x080484ac     c1e804           shr eax, 0x4
    |     0x080484af     c1e004           shl eax, 0x4
    |     0x080484b2     29c4             sub esp, eax
    |     0x080484b4     c7042410860408   mov dword [esp], str.IOLICrackmeLevel0x03
    |     0x080484bb     e890feffff       call dword imp.printf
    |        ; imp.printf()
    |     0x080484c0     c7042429860408   mov dword [esp], str.Password
    |     0x080484c7     e884feffff       call dword imp.printf
    |        ; imp.printf()
    |     0x080484cc     8d45fc           lea eax, [ebp-0x4]
    |     0x080484cf     89442404         mov [esp+0x4], eax
    |     0x080484d3     c7042434860408   mov dword [esp], 0x8048634
    |     0x080484da     e851feffff       call dword imp.scanf
    |        ; imp.scanf()
    |     0x080484df     c745f85a000000   mov dword [ebp-0x8], 0x5a
    |     0x080484e6     c745f4ec010000   mov dword [ebp-0xc], 0x1ec
    |     0x080484ed     8b55f4           mov edx, [ebp-0xc]            ; edx = 0x1ec
    |     0x080484f0     8d45f8           lea eax, [ebp-0x8]            ; eax -> ebp-0x8
    |     0x080484f3     0110             add [eax], edx                ; ebp-0x8 = (0x5a + 0x1ec)
    |     0x080484f5     8b45f8           mov eax, [ebp-0x8]            ; eax = 0x5a + 0x1ec = 0x246
    |     0x080484f8     0faf45f8         imul eax, [ebp-0x8]           ; eax = 0x246 * 0x246 = 0x52b24
    |     0x080484fc     8945f4           mov [ebp-0xc], eax            ; ebp-0xc = 0x52b24
    |     0x080484ff     8b45f4           mov eax, [ebp-0xc]            ; eax = 0x52b24
    |     0x08048502     89442404         mov [esp+0x4], eax            ; esp+0x4 = eax
    |     0x08048506     8b45fc           mov eax, [ebp-0x4]
    |     0x08048509     890424           mov [esp], eax
    |     0x0804850c     e85dffffff       call dword sym.test
    |        ; sym.test()
    |     0x08048511     b800000000       mov eax, 0x0
    |     0x08048516     c9               leave
    \     0x08048517     c3               ret
        ; ------------

Ho, a call to a interesting function: sym.test, called with two parameters:
Likely our password, and 0x52b24 (or 338724 if you prefer).

    pdf@sym.test
            ; CODE (CALL) XREF 0x0804850c (sym.main)
    / function: sym.test (42)
    |       0x0804846e  sym.test:
    |       0x0804846e     55               push ebp
    |       0x0804846f     89e5             mov ebp, esp
    |       0x08048471     83ec08           sub esp, 0x8
    |       0x08048474     8b4508           mov eax, [ebp+0x8]
    |       0x08048477     3b450c           cmp eax, [ebp+0xc]
    |   ,=< 0x0804847a     740e             jz loc.0804848a
    |   |   0x0804847c     c70424ec850408   mov dword [esp], str.LqydolgSdvvzrug$
    |   |   0x08048483     e88cffffff       call dword sym.shift
    |   |      ; sym.shift(unk)
    |  ,==< 0x08048488     eb0c             jmp loc.08048496
    |  ||   ; CODE (JMP) XREF 0x0804847a (sym.test)
    / loc: loc.0804848a (14)
    |  ||   0x0804848a  loc.0804848a:
    |  |`-> 0x0804848a     c70424fe850408   mov dword [esp], str.SdvvzrugRN$$$=,
    |  |    0x08048491     e87effffff       call dword sym.shift
    |  |       ; sym.shift()
    |  |    ; CODE (JMP) XREF 0x08048488 (sym.test)
    / loc: loc.08048496 (2)
    |  |    0x08048496  loc.08048496:
    |  `--> 0x08048496     c9               leave
    \       0x08048497     c3               ret

And now, you <del>should</del> must be lazy. There is a cmp, and two _path_,
with mangled strings. This seems to be a goodboy/badboy.

    $ ./crackme0x03
    IOLI Crackme Level 0x03
    Password: 338724
    Password OK!!! :)

You can also reverse the sym.shift function:

    [0x08048360]> pdf@sym.shift
            ; CODE (CALL) XREF 0x08048491 (sym.test)
            ; CODE (CALL) XREF 0x08048483 (sym.test)
    / function: sym.shift (90)
    |       0x08048414  sym.shift:
    |       0x08048414     55               push ebp
    |       0x08048415     89e5             mov ebp, esp
    |       0x08048417     81ec98000000     sub esp, 0x98
    |       0x0804841d     c7458400000000   mov dword [ebp-0x7c], 0x0  ; this seems to be a counter
    |  .    ; CODE (JMP) XREF 0x0804844e (sym.shift)
    / loc: loc.08048424 (74)
    |  .    0x08048424  loc.08048424:
    |  .--> 0x08048424     8b4508           mov eax, [ebp+0x8] ; ebp+0x8 = strlen(chain)
    |  |    0x08048427     890424           mov [esp], eax
    |  |    0x0804842a     e811ffffff       call dword imp.strlen
    |  |       ; imp.strlen()
    |  |    0x0804842f     394584           cmp [ebp-0x7c], eax
    |  |,=< 0x08048432     731c             jae loc.08048450
    |  ||   0x08048434     8d4588           lea eax, [ebp-0x78]
    |  ||   0x08048437     89c2             mov edx, eax
    |  ||   0x08048439     035584           add edx, [ebp-0x7c]
    |  ||   0x0804843c     8b4584           mov eax, [ebp-0x7c]
    |  ||   0x0804843f     034508           add eax, [ebp+0x8]
    |  ||   0x08048442     0fb600           movzx eax, byte [eax]
    |  ||   0x08048445     2c03             sub al, 0x3
    |  ||   0x08048447     8802             mov [edx], al
    |  ||   0x08048449     8d4584           lea eax, [ebp-0x7c]
    |  ||   0x0804844c     ff00             inc dword [eax]
    |  `==< 0x0804844e     ebd4             jmp loc.08048424
    |   |   ; CODE (JMP) XREF 0x08048432 (sym.shift)
    / loc: loc.08048450 (30)
    |   |   0x08048450  loc.08048450:
    |   `-> 0x08048450     8d4588           lea eax, [ebp-0x78]
    |       0x08048453     034584           add eax, [ebp-0x7c]
    |       0x08048456     c60000           mov byte [eax], 0x0
    |       0x08048459     8d4588           lea eax, [ebp-0x78]
    |       0x0804845c     89442404         mov [esp+0x4], eax
    |       0x08048460     c70424e8850408   mov dword [esp], 0x80485e8
    |       0x08048467     e8e4feffff       call dword imp.printf
    |          ; imp.printf()
    |       0x0804846c     c9               leave
    \       0x0804846d     c3               ret
            ; ------------

A strlen, a comparison to a counter, ... This looks like a (simple) decryption loop !
And the only operation done is actually a ""dec 0x3". Since this function is named _shift_,
this seems plausible. Let's check with some Python:

    :::python
    print ''.join([chr(ord(i)-0x3) for i in 'SdvvzrugRN$$$'])
        PasswordOK!!!
    print ''.join([chr(ord(i)-0x3) for i in 'LqydolgSdvvzrug$'])
        InvalidPassword!

Woohoo, we where right.


## crackme0x04

    [0x080483d0]> aa
    [0x080483d0]> pdf@sym.main
    / function: sym.main (92)
    |     0x08048509  sym.main:
    |     0x08048509     55               push ebp
    |     0x0804850a     89e5             mov ebp, esp
    |     0x0804850c     81ec88000000     sub esp, 0x88
    |     0x08048512     83e4f0           and esp, 0xfffffff0
    |     0x08048515     b800000000       mov eax, 0x0
    |     0x0804851a     83c00f           add eax, 0xf
    |     0x0804851d     83c00f           add eax, 0xf
    |     0x08048520     c1e804           shr eax, 0x4
    |     0x08048523     c1e004           shl eax, 0x4
    |     0x08048526     29c4             sub esp, eax
    |     0x08048528     c704245e860408   mov dword [esp], str.IOLICrackmeLevel0x04
    |     0x0804852f     e860feffff       call dword imp.printf
    |        ; imp.printf()
    |     0x08048534     c7042477860408   mov dword [esp], str.Password
    |     0x0804853b     e854feffff       call dword imp.printf
    |        ; imp.printf()
    |     0x08048540     8d4588           lea eax, [ebp-0x78]
    |     0x08048543     89442404         mov [esp+0x4], eax
    |     0x08048547     c7042482860408   mov dword [esp], 0x8048682
    |     0x0804854e     e821feffff       call dword imp.scanf
    |        ; imp.scanf()
    |     0x08048553     8d4588           lea eax, [ebp-0x78]
    |     0x08048556     890424           mov [esp], eax
    |     0x08048559     e826ffffff       call dword sym.check
    |        ; sym.check()
    |     0x0804855e     b800000000       mov eax, 0x0
    |     0x08048563     c9               leave
    \     0x08048564     c3               ret
        ; ------------

Nothing funky nor new.

    [0x080483d0]> pdf@sym.check
            ; CODE (CALL) XREF 0x08048559 (sym.main)
    / function: sym.check (133)
    |        0x08048484  sym.check:
    |        0x08048484     55               push ebp
    |        0x08048485     89e5             mov ebp, esp
    |        0x08048487     83ec28           sub esp, 0x28
    |        0x0804848a     c745f800000000   mov dword [ebp-0x8], 0x0  ; smells like those lines
    |        0x08048491     c745f400000000   mov dword [ebp-0xc], 0x0  ; are counters !
    |  .     ; CODE (JMP) XREF 0x080484f9 (sym.check)
    / loc: loc.08048498 (113)
    |  .     0x08048498  loc.08048498:
    |  .---> 0x08048498     8b4508           mov eax, [ebp+0x8]
    |  |     0x0804849b     890424           mov [esp], eax
    |  |     0x0804849e     e8e1feffff       call dword imp.strlen
    |  |        ; imp.strlen()
    |  |     0x080484a3     3945f4           cmp [ebp-0xc], eax            ; counter > strlen ?
    |  | ,=< 0x080484a6     7353             jae loc.080484fb              ; if yes, jumps to badboy
    |  | |   0x080484a8     8b45f4           mov eax, [ebp-0xc]
    |  | |   0x080484ab     034508           add eax, [ebp+0x8]
    |  | |   0x080484ae     0fb600           movzx eax, byte [eax]
    |  | |   0x080484b1     8845f3           mov [ebp-0xd], al
    |  | |   0x080484b4     8d45fc           lea eax, [ebp-0x4]
    |  | |   0x080484b7     89442408         mov [esp+0x8], eax
    |  | |   0x080484bb     c744240438860408 mov dword [esp+0x4], 0x8048638 ; what is that ?
    |  | |   0x080484c3     8d45f3           lea eax, [ebp-0xd]
    |  | |   0x080484c6     890424           mov [esp], eax
    |  | |   0x080484c9     e8d6feffff       call dword imp.sscanf
    |  | |      ; imp.sscanf()
    |  | |   0x080484ce     8b55fc           mov edx, [ebp-0x4]            ; edx = scanf()'s result
    |  | |   0x080484d1     8d45f8           lea eax, [ebp-0x8]
    |  | |   0x080484d4     0110             add [eax], edx                ; ebp-0x8 is incremented
    |  | |   0x080484d6     837df80f         cmp dword [ebp-0x8], 0xf      ; and compared to 0xf
    |  |,==< 0x080484da     7518             jnz loc.080484f4              ; if not equals, jump !
    |  |||   0x080484dc     c704243b860408   mov dword [esp], str.PasswordOK!
    |  |||   0x080484e3     e8acfeffff       call dword imp.printf
    |  |||      ; imp.printf()
    |  |||   0x080484e8     c7042400000000   mov dword [esp], 0x0
    |  |||   0x080484ef     e8c0feffff       call dword imp.exit
    |  |||      ; imp.exit()
    |  ||    ; CODE (JMP) XREF 0x080484da (sym.check)
    / loc: loc.080484f4 (21)
    |  ||    0x080484f4  loc.080484f4:
    |  |`--> 0x080484f4     8d45f4           lea eax, [ebp-0xc]
    |  | |   0x080484f7     ff00             inc dword [eax]
    |  `===< 0x080484f9     eb9d             jmp loc.08048498
    |    |   ; CODE (JMP) XREF 0x080484a6 (sym.check)
    / loc: loc.080484fb (14)
    |    |   0x080484fb  loc.080484fb:
    |    `-> 0x080484fb     c7042449860408   mov dword [esp], str.PasswordIncorrect!
    |        0x08048502     e88dfeffff       call dword imp.printf
    |           ; imp.printf()
    |        0x08048507     c9               leave
    \        0x08048508     c3               ret
            ; ------------

Strlen again, a loop, scanf, ...

What is send to scanf ?

    [0x080483d0]> s 0x8048638
    [0x08048638]> ps
    %d
    [0x08048638]>

This seems to be some kind of atoi(), but with scanf().
So, our password's sum must be equals to 0xf (aka 15) at some point.

    $ ./crackme0x04
    IOLI Crackme Level 0x04
    Password: 96
    Password OK!

## crackme0x05

    [0x080483d0]> aa
    [0x080483d0]> pdf@sym.main
    / function: sym.main (92)
    |     0x08048540  sym.main:
    |     0x08048540     55               push ebp
    |     0x08048541     89e5             mov ebp, esp
    |     0x08048543     81ec88000000     sub esp, 0x88
    |     0x08048549     83e4f0           and esp, 0xfffffff0
    |     0x0804854c     b800000000       mov eax, 0x0
    |     0x08048551     83c00f           add eax, 0xf
    |     0x08048554     83c00f           add eax, 0xf
    |     0x08048557     c1e804           shr eax, 0x4
    |     0x0804855a     c1e004           shl eax, 0x4
    |     0x0804855d     29c4             sub esp, eax
    |     0x0804855f     c704248e860408   mov dword [esp], str.IOLICrackmeLevel0x05
    |     0x08048566     e829feffff       call dword imp.printf
    |        ; imp.printf()
    |     0x0804856b     c70424a7860408   mov dword [esp], str.Password
    |     0x08048572     e81dfeffff       call dword imp.printf
    |        ; imp.printf()
    |     0x08048577     8d4588           lea eax, [ebp-0x78]
    |     0x0804857a     89442404         mov [esp+0x4], eax
    |     0x0804857e     c70424b2860408   mov dword [esp], 0x80486b2
    |     0x08048585     e8eafdffff       call dword imp.scanf
    |        ; imp.scanf()
    |     0x0804858a     8d4588           lea eax, [ebp-0x78]
    |     0x0804858d     890424           mov [esp], eax
    |     0x08048590     e833ffffff       call dword sym.check
    |        ; sym.check()
    |     0x08048595     b800000000       mov eax, 0x0
    |     0x0804859a     c9               leave
    \     0x0804859b     c3               ret
        ; ------------

Boring.

    [0x080483d0]> pdf@sym.check
            ; CODE (CALL) XREF 0x08048590 (sym.main)
    / function: sym.check (120)
    |        0x080484c8  sym.check:
    |        0x080484c8     55               push ebp
    |        0x080484c9     89e5             mov ebp, esp
    |        0x080484cb     83ec28           sub esp, 0x28
    |        0x080484ce     c745f800000000   mov dword [ebp-0x8], 0x0
    |        0x080484d5     c745f400000000   mov dword [ebp-0xc], 0x0
    |  .     ; CODE (JMP) XREF 0x08048530 (sym.check)
    / loc: loc.080484dc (100)
    |  .     0x080484dc  loc.080484dc:
    |  .---> 0x080484dc     8b4508           mov eax, [ebp+0x8]
    |  |     0x080484df     890424           mov [esp], eax
    |  |     0x080484e2     e89dfeffff       call dword imp.strlen
    |  |        ; imp.strlen()
    |  |     0x080484e7     3945f4           cmp [ebp-0xc], eax
    |  | ,=< 0x080484ea     7346             jae loc.08048532
    |  | |   0x080484ec     8b45f4           mov eax, [ebp-0xc]
    |  | |   0x080484ef     034508           add eax, [ebp+0x8]
    |  | |   0x080484f2     0fb600           movzx eax, byte [eax]
    |  | |   0x080484f5     8845f3           mov [ebp-0xd], al
    |  | |   0x080484f8     8d45fc           lea eax, [ebp-0x4]
    |  | |   0x080484fb     89442408         mov [esp+0x8], eax
    |  | |   0x080484ff     c744240468860408 mov dword [esp+0x4], 0x8048668
    |  | |   0x08048507     8d45f3           lea eax, [ebp-0xd]
    |  | |   0x0804850a     890424           mov [esp], eax
    |  | |   0x0804850d     e892feffff       call dword imp.sscanf
    |  | |      ; imp.sscanf()
    |  | |   0x08048512     8b55fc           mov edx, [ebp-0x4]
    |  | |   0x08048515     8d45f8           lea eax, [ebp-0x8]
    |  | |   0x08048518     0110             add [eax], edx
    |  | |   0x0804851a     837df810         cmp dword [ebp-0x8], 0x10
    |  |,==< 0x0804851e     750b             jnz loc.0804852b
    |  |||   0x08048520     8b4508           mov eax, [ebp+0x8]
    |  |||   0x08048523     890424           mov [esp], eax
    |  |||   0x08048526     e859ffffff       call dword sym.parell
    |  |||      ; sym.parell()
    |  ||    ; CODE (JMP) XREF 0x0804851e (sym.check)
    / loc: loc.0804852b (21)
    |  ||    0x0804852b  loc.0804852b:
    |  |`--> 0x0804852b     8d45f4           lea eax, [ebp-0xc]
    |  | |   0x0804852e     ff00             inc dword [eax]
    |  `===< 0x08048530     ebaa             jmp loc.080484dc
    |    |   ; CODE (JMP) XREF 0x080484ea (sym.check)
    / loc: loc.08048532 (14)
    |    |   0x08048532  loc.08048532:
    |    `-> 0x08048532     c7042479860408   mov dword [esp], str.PasswordIncorrect!
    |        0x08048539     e856feffff       call dword imp.printf
    |           ; imp.printf()
    |        0x0804853e     c9               leave
    \        0x0804853f     c3               ret
            ; ------------

Same function as the previous crackme, but this time, it's not compared to 15, but to 16.
And instead of a printf("Password OK!"), there is a call to sym.pharell

    [0x080483d0]> pdf@sym.parell
        ; CODE (CALL) XREF 0x08048526 (sym.check)
    / function: sym.parell (68)
    |      0x08048484  sym.parell:
    |      0x08048484     55               push ebp
    |      0x08048485     89e5             mov ebp, esp
    |      0x08048487     83ec18           sub esp, 0x18
    |      0x0804848a     8d45fc           lea eax, [ebp-0x4]
    |      0x0804848d     89442408         mov [esp+0x8], eax
    |      0x08048491     c744240468860408 mov dword [esp+0x4], 0x8048668
    |      0x08048499     8b4508           mov eax, [ebp+0x8]
    |      0x0804849c     890424           mov [esp], eax
    |      0x0804849f     e800ffffff       call dword imp.sscanf
    |         ; imp.sscanf()
    |      0x080484a4     8b45fc           mov eax, [ebp-0x4]
    |      0x080484a7     83e001           and eax, 0x1
    |      0x080484aa     85c0             test eax, eax
    |  ,=< 0x080484ac     7518             jnz loc.080484c6
    |  |   0x080484ae     c704246b860408   mov dword [esp], str.PasswordOK!
    |  |   0x080484b5     e8dafeffff       call dword imp.printf
    |  |      ; imp.printf()
    |  |   0x080484ba     c7042400000000   mov dword [esp], 0x0
    |  |   0x080484c1     e8eefeffff       call dword imp.exit
    |  |      ; imp.exit()
    |  |   ; CODE (JMP) XREF 0x080484ac (sym.parell)
    / loc: loc.080484c6 (2)
    |  |   0x080484c6  loc.080484c6:
    |  `-> 0x080484c6     c9               leave
    \      0x080484c7     c3               ret
        ; ------------

Another scanf(), used as an atoi(). It's return value is and'ed with 1,
and if the result is 0, goodboy ! As everyone knows, and'ing with 1 is the
same as testing is the number is odd.

    $ ./crackme0x05
    IOLI Crackme Level 0x05
    Password: 664
    Password OK!

## crackme0x06

    pdf@sym.main
    / function: sym.main (99)
    |     0x08048607  sym.main:
    |     0x08048607     55               push ebp
    |     0x08048608     89e5             mov ebp, esp
    |     0x0804860a     81ec88000000     sub esp, 0x88
    |     0x08048610     83e4f0           and esp, 0xfffffff0
    |     0x08048613     b800000000       mov eax, 0x0
    |     0x08048618     83c00f           add eax, 0xf
    |     0x0804861b     83c00f           add eax, 0xf
    |     0x0804861e     c1e804           shr eax, 0x4
    |     0x08048621     c1e004           shl eax, 0x4
    |     0x08048624     29c4             sub esp, eax
    |     0x08048626     c7042463870408   mov dword [esp], str.IOLICrackmeLevel0x06
    |     0x0804862d     e886fdffff       call dword imp.printf
    |        ; imp.printf()
    |     0x08048632     c704247c870408   mov dword [esp], str.Password
    |     0x08048639     e87afdffff       call dword imp.printf
    |        ; imp.printf()
    |     0x0804863e     8d4588           lea eax, [ebp-0x78]
    |     0x08048641     89442404         mov [esp+0x4], eax
    |     0x08048645     c7042487870408   mov dword [esp], 0x8048787
    |     0x0804864c     e847fdffff       call dword imp.scanf
    |        ; imp.scanf()
    |     0x08048651     8b4510           mov eax, [ebp+0x10]
    |     0x08048654     89442404         mov [esp+0x4], eax
    |     0x08048658     8d4588           lea eax, [ebp-0x78]
    |     0x0804865b     890424           mov [esp], eax
    |     0x0804865e     e825ffffff       call dword sym.check
    |        ; sym.check()
    |     0x08048663     b800000000       mov eax, 0x0
    |     0x08048668     c9               leave
    \     0x08048669     c3               ret
          ; ------------

Blablabla, same stuff than previously, blablabla.
Or is it ?
Check again.

You can see that this time, the _sym.check_ function takes 2 parameters.

1. The result of scanf(), ([ebp-0x78]) in esp
2. [ebp+10] in [esp+0x4]

Since main() is a function, and this code is compiled with GCC,
you can expect a stack like this:

    [esp + 0x10] - envp
    [esp + 0x0c] - argv
    [esp + 0x08] - argc
    [esp + 0x04] - return address

So, our sym.check call looks like:

    check(int password, char* argv[]);

Except this, the code is the same that the previous binary (except that envp is passed as an argument) for sym.main, sym.check, sym.parell, ...
Or it is ?
Check once again ;)
The code is different in sym.parell.
You can notice a call to sym.dummy.

    [0x08048400]> pdf@sym.dummy
             ; CODE (CALL) XREF 0x08048547 (sym.parell)
    / function: sym.dummy (102)
    |        0x080484b4  sym.dummy:
    |        0x080484b4     55               push ebp
    |        0x080484b5     89e5             mov ebp, esp
    |        0x080484b7     83ec18           sub esp, 0x18
    |        0x080484ba     c745fc00000000   mov dword [ebp-0x4], 0x0
    |   .    ; CODE (JMP) XREF 0x08048503 (sym.dummy)
    / loc: loc.080484c1 (89)
    |   .    0x080484c1  loc.080484c1:
    |   .--> 0x080484c1     8b45fc           mov eax, [ebp-0x4]
    |   |    0x080484c4     8d148500000000   lea edx, [eax*4+0x0]
    |   |    0x080484cb     8b450c           mov eax, [ebp+0xc]
    |   |    0x080484ce     833c0200         cmp dword [edx+eax], 0x0
    |   |,=< 0x080484d2     743a             jz loc.0804850e
    |   ||   0x080484d4     8b45fc           mov eax, [ebp-0x4]
    |   ||   0x080484d7     8d0c8500000000   lea ecx, [eax*4+0x0]
    |   ||   0x080484de     8b550c           mov edx, [ebp+0xc]
    |   ||   0x080484e1     8d45fc           lea eax, [ebp-0x4]
    |   ||   0x080484e4     ff00             inc dword [eax]
    |   ||   0x080484e6     c744240803000000 mov dword [esp+0x8], 0x3
    |   ||   0x080484ee     c744240438870408 mov dword [esp+0x4], str.LOLO
    |   ||   0x080484f6     8b0411           mov eax, [ecx+edx]
    |   ||   0x080484f9     890424           mov [esp], eax
    |   ||   0x080484fc     e8d7feffff       call dword imp.strncmp
    |   ||      ; imp.strncmp()
    |   ||   0x08048501     85c0             test eax, eax
    |   `==< 0x08048503     75bc             jnz loc.080484c1
    |    |   0x08048505     c745f801000000   mov dword [ebp-0x8], 0x1
    |  ,===< 0x0804850c     eb07             jmp loc.08048515
    |  | |   ; CODE (JMP) XREF 0x080484d2 (sym.dummy)
    / loc: loc.0804850e (12)
    |  | |   0x0804850e  loc.0804850e:
    |  | `-> 0x0804850e     c745f800000000   mov dword [ebp-0x8], 0x0
    |  |     ; CODE (JMP) XREF 0x0804850c (sym.dummy)
    / loc: loc.08048515 (5)
    |  |     0x08048515  loc.08048515:
    |  `---> 0x08048515     8b45f8           mov eax, [ebp-0x8]
    |        0x08048518     c9               leave
    \        0x08048519     c3               ret
             ; ------------

Let's be <del>clever</del> lazy once again:

1. str.LOLO
2. strncmp()
3. no new input/output compared to the previous binary
4. the environnement pointer is passed form sym.main to sym.check to sym.parell ...

Looks like the binary wants the same things that the previous one, _plus_ an environnement variable named "LOLO".

    $ LOLO= ./crackme0x06
    IOLI Crackme Level 0x06
    Password: 556
    Password OK!

Maybe you asked yourself "How the hell am I supposed to recognize that this is GDB's output ?!".
By experience.
But, there is another way:

    $ rabin2 -S ./crackme0x06
    [Sections]
    idx=00 addr=0x08048000 off=0x00000000 sz=0 vsz=0 perm=---- name=
    idx=01 addr=0x08048154 off=0x00000154 sz=19 vsz=19 perm=-r-- name=.interp
    idx=02 addr=0x08048168 off=0x00000168 sz=32 vsz=32 perm=-r-- name=.note.ABItag
    idx=03 addr=0x08048188 off=0x00000188 sz=60 vsz=60 perm=-r-- name=.hash
    idx=04 addr=0x080481c4 off=0x000001c4 sz=32 vsz=32 perm=-r-- name=.gnu.hash
    idx=05 addr=0x080481e4 off=0x000001e4 sz=160 vsz=160 perm=-r-- name=.dynsym
    idx=06 addr=0x08048284 off=0x00000284 sz=103 vsz=103 perm=-r-- name=.dynstr
    idx=07 addr=0x080482ec off=0x000002ec sz=20 vsz=20 perm=-r-- name=.gnu.version
    idx=08 addr=0x08048300 off=0x00000300 sz=32 vsz=32 perm=-r-- name=.gnu.version_r
    idx=09 addr=0x08048320 off=0x00000320 sz=8 vsz=8 perm=-r-- name=.rel.dyn
    idx=10 addr=0x08048328 off=0x00000328 sz=56 vsz=56 perm=-r-- name=.rel.plt
    idx=11 addr=0x08048360 off=0x00000360 sz=23 vsz=23 perm=-r-x name=.init
    idx=12 addr=0x08048378 off=0x00000378 sz=128 vsz=128 perm=-r-x name=.plt
    idx=13 addr=0x08048400 off=0x00000400 sz=788 vsz=788 perm=-r-x name=.text
    idx=14 addr=0x08048714 off=0x00000714 sz=26 vsz=26 perm=-r-x name=.fini
    idx=15 addr=0x08048730 off=0x00000730 sz=90 vsz=90 perm=-r-- name=.rodata
    idx=16 addr=0x0804878c off=0x0000078c sz=4 vsz=4 perm=-r-- name=.eh_frame
    idx=17 addr=0x08049f0c off=0x00000f0c sz=8 vsz=8 perm=-rw- name=.ctors
    idx=18 addr=0x08049f14 off=0x00000f14 sz=8 vsz=8 perm=-rw- name=.dtors
    idx=19 addr=0x08049f1c off=0x00000f1c sz=4 vsz=4 perm=-rw- name=.jcr
    idx=20 addr=0x08049f20 off=0x00000f20 sz=208 vsz=208 perm=-rw- name=.dynamic
    idx=21 addr=0x08049ff0 off=0x00000ff0 sz=4 vsz=4 perm=-rw- name=.got
    idx=22 addr=0x08049ff4 off=0x00000ff4 sz=40 vsz=40 perm=-rw- name=.got.plt
    idx=23 addr=0x0804a01c off=0x0000101c sz=12 vsz=12 perm=-rw- name=.data
    idx=24 addr=0x0804a028 off=0x00001028 sz=4 vsz=4 perm=-rw- name=.bss
    idx=25 addr=0x08049028 off=0x00001028 sz=441 vsz=441 perm=---- name=.comment
    idx=26 addr=0x080491e1 off=0x000011e1 sz=219 vsz=219 perm=---- name=.shstrtab
    idx=27 addr=0x08049744 off=0x00001744 sz=1152 vsz=1152 perm=---- name=.symtab
    idx=28 addr=0x08049bc4 off=0x00001bc4 sz=609 vsz=609 perm=---- name=.strtab

    29 sections

Since this binary is not stripped (_man strip_), you can notice a ".comment" section.
    $ r2 ./crackme0x06
    [0x08048400]> s section..comment
    [0x08049028]> ps 128
    \x00GCC: (GNU) 3.4.6 (Gentoo 3.4.6-r2, ssp-3.4.6-1.0, pie-8.7.10)\x00\x00GCC: (GNU) 3.4.6 (Gentoo 3.4.6-r2, ssp-3.4.6-1.0, pie-8.7.10)\x00\x00G

Yay, GCC 3.4.6 on a Gentoo 3.4.6-r2 !


## crackme0x07


    [0x08048400]> aa
    [0x08048400]> pdf
    / function: section..text (34)
    |     0x08048400  section..text:
    |     0x08048400     31ed             xor ebp, ebp               ; [13] va=0x08048400 pa=0x00000400 sz=900 vsz=900 rwx=-r-x .text
    |     0x08048402     5e               pop esi
    |     0x08048403     89e1             mov ecx, esp
    |     0x08048405     83e4f0           and esp, 0xfffffff0
    |     0x08048408     50               push eax
    |     0x08048409     54               push esp
    |     0x0804840a     52               push edx
    |     0x0804840b     6850870408       push dword 0x8048750
    |     0x08048410     68e0860408       push dword 0x80486e0
    |     0x08048415     51               push ecx
    |     0x08048416     56               push esi
    |     0x08048417     687d860408       push dword 0x804867d
    |     0x0804841c     e867ffffff       call dword imp.__libc_start_main
    |        ; imp.__libc_start_main()
    \     0x08048421     f4               hlt
          ; ------------

wat.
What happened to symbols ?!

    $ rabin2 -I ./crackme0x07
    [File info]
    File=/home/jvoisin/dev/reverse/crackme/done/IOLI-crackme/bin-linux/./crackme0x07
    Type=EXEC (Executable file)
    HasVA=true
    RootClass=elf
    Class=ELF32
    Arch=x86 32
    Machine=Intel 80386
    OS=linux
    Subsystem=linux
    Big endian=false
    Stripped=true
    Static=false
    Line_nums=false
    Local_syms=false
    Relocs=false
    RPath=NONE

This binary is stripped : no more symbols.

Since this is GCC-produced code, the main is likely at 0x804867d (the last push before _imp.__libc_start_main_)

    $ r2 ./crackme0x07
    [0x08048400]> aa
    [0x08048400]> pdf
    / function: section..text (34)
    |     0x08048400  section..text:
    |     0x08048400     31ed             xor ebp, ebp               ; [13] va=0x08048400 pa=0x00000400 sz=900 vsz=900 rwx=-r-x .text
    |     0x08048402     5e               pop esi
    |     0x08048403     89e1             mov ecx, esp
    |     0x08048405     83e4f0           and esp, 0xfffffff0
    |     0x08048408     50               push eax
    |     0x08048409     54               push esp
    |     0x0804840a     52               push edx
    |     0x0804840b     6850870408       push dword 0x8048750
    |     0x08048410     68e0860408       push dword 0x80486e0
    |     0x08048415     51               push ecx
    |     0x08048416     56               push esi
    |     0x08048417     687d860408       push dword 0x804867d
    |     0x0804841c     e867ffffff       call dword imp.__libc_start_main
    |        ; imp.__libc_start_main()
    \     0x08048421     f4               hlt
          ; ------------

By the way, this is the _start_ function.

    [0x08048400]> pdf@0x804867d
    / function: main (99)
    |     0x0804867d  main:
    |     0x0804867d     55               push ebp
    |     0x0804867e     89e5             mov ebp, esp
    |     0x08048680     81ec88000000     sub esp, 0x88
    |     0x08048686     83e4f0           and esp, 0xfffffff0
    |     0x08048689     b800000000       mov eax, 0x0
    |     0x0804868e     83c00f           add eax, 0xf
    |     0x08048691     83c00f           add eax, 0xf
    |     0x08048694     c1e804           shr eax, 0x4
    |     0x08048697     c1e004           shl eax, 0x4
    |     0x0804869a     29c4             sub esp, eax
    |     0x0804869c     c70424d9870408   mov dword [esp], str.IOLICrackmeLevel0x07
    |     0x080486a3     e810fdffff       call dword imp.printf
    |        ; imp.printf()
    |     0x080486a8     c70424f2870408   mov dword [esp], str.Password
    |     0x080486af     e804fdffff       call dword imp.printf
    |        ; imp.printf()
    |     0x080486b4     8d4588           lea eax, [ebp-0x78]
    |     0x080486b7     89442404         mov [esp+0x4], eax
    |     0x080486bb     c70424fd870408   mov dword [esp], 0x80487fd
    |     0x080486c2     e8d1fcffff       call dword imp.scanf
    |        ; imp.scanf()
    |     0x080486c7     8b4510           mov eax, [ebp+0x10]
    |     0x080486ca     89442404         mov [esp+0x4], eax
    |     0x080486ce     8d4588           lea eax, [ebp-0x78]
    |     0x080486d1     890424           mov [esp], eax
    |     0x080486d4     e8e0feffff       call dword fcn.080485b9
    |        ; fcn.080485b9()
    |     0x080486d9     b800000000       mov eax, 0x0
    |     0x080486de     c9               leave
    \     0x080486df     c3               ret
          ; ------------

Our main().

    [0x08048400]> pdf@fcn.080485b9
                ; CODE (CALL) XREF 0x080486d4 (main)
    / function: fcn.080485b9 (196)
    |           0x080485b9  fcn.080485b9:
    |           0x080485b9     55               push ebp
    |           0x080485ba     89e5             mov ebp, esp
    |           0x080485bc     83ec28           sub esp, 0x28
    |           0x080485bf     c745f800000000   mov dword [ebp-0x8], 0x0
    |           0x080485c6     c745f400000000   mov dword [ebp-0xc], 0x0
    |     .     ; CODE (JMP) XREF 0x08048628 (fcn.080485b9)
    / loc: loc.080485cd (176)
    |     .     0x080485cd  loc.080485cd:
    |     .---> 0x080485cd     8b4508           mov eax, [ebp+0x8]
    |     |     0x080485d0     890424           mov [esp], eax
    |     |     0x080485d3     e8d0fdffff       call dword imp.strlen
    |     |        ; imp.strlen()
    |     |     0x080485d8     3945f4           cmp [ebp-0xc], eax
    |     | ,=< 0x080485db     734d             jae loc.0804862a
    |     | |   0x080485dd     8b45f4           mov eax, [ebp-0xc]
    |     | |   0x080485e0     034508           add eax, [ebp+0x8]
    |     | |   0x080485e3     0fb600           movzx eax, byte [eax]
    |     | |   0x080485e6     8845f3           mov [ebp-0xd], al
    |     | |   0x080485e9     8d45fc           lea eax, [ebp-0x4]
    |     | |   0x080485ec     89442408         mov [esp+0x8], eax
    |     | |   0x080485f0     c7442404c2870408 mov dword [esp+0x4], 0x80487c2
    |     | |   0x080485f8     8d45f3           lea eax, [ebp-0xd]
    |     | |   0x080485fb     890424           mov [esp], eax
    |     | |   0x080485fe     e8c5fdffff       call dword imp.sscanf
    |     | |      ; imp.sscanf()
    |     | |   0x08048603     8b55fc           mov edx, [ebp-0x4]
    |     | |   0x08048606     8d45f8           lea eax, [ebp-0x8]
    |     | |   0x08048609     0110             add [eax], edx
    |     | |   0x0804860b     837df810         cmp dword [ebp-0x8], 0x10
    |     |,==< 0x0804860f     7512             jnz loc.08048623
    |     |||   0x08048611     8b450c           mov eax, [ebp+0xc]
    |     |||   0x08048614     89442404         mov [esp+0x4], eax
    |     |||   0x08048618     8b4508           mov eax, [ebp+0x8]
    |     |||   0x0804861b     890424           mov [esp], eax
    |     |||   0x0804861e     e81fffffff       call dword fcn.08048542
    |     |||      ; fcn.08048542()
    |     ||    ; CODE (JMP) XREF 0x0804860f (fcn.080485b9)
    / loc: loc.08048623 (90)
    |     ||    0x08048623  loc.08048623:
    |     |`--> 0x08048623     8d45f4           lea eax, [ebp-0xc]
    |     | |   0x08048626     ff00             inc dword [eax]
    |     `===< 0x08048628     eba3             jmp loc.080485cd
    |       |   ; CODE (JMP) XREF 0x080485db (fcn.080485b9)
    / loc: loc.0804862a (83)
    |       |   0x0804862a  loc.0804862a:
    |       `-> 0x0804862a     e8f5feffff       call dword fcn.08048524
    |       |      ; fcn.08048524()
    |           0x0804862f     8b450c           mov eax, [ebp+0xc]
    |           0x08048632     89442404         mov [esp+0x4], eax
    |           0x08048636     8b45fc           mov eax, [ebp-0x4]
    |           0x08048639     890424           mov [esp], eax
    |           0x0804863c     e873feffff       call dword fcn.080484b4
    |              ; fcn.080484b4()
    |           0x08048641     85c0             test eax, eax
    |    ,====< 0x08048643     7436             jz loc.0804867b
    |    |      0x08048645     c745f400000000   mov dword [ebp-0xc], 0x0
    |    |      ; CODE (JMP) XREF 0x08048679 (fcn.080485b9)
    / loc: loc.0804864c (49)
    |    |      0x0804864c  loc.0804864c:
    |    |      0x0804864c     837df409         cmp dword [ebp-0xc], 0x9
    |   ,=====< 0x08048650     7f29             jg loc.0804867b
    |   ||      0x08048652     8b45fc           mov eax, [ebp-0x4]
    |   ||      0x08048655     83e001           and eax, 0x1
    |   ||      0x08048658     85c0             test eax, eax
    |  ,======< 0x0804865a     7518             jnz loc.08048674
    |  |||      0x0804865c     c70424d3870408   mov dword [esp], str.wtf?
    |  |||      0x08048663     e850fdffff       call dword imp.printf
    |  |||         ; imp.printf()
    |  |||      0x08048668     c7042400000000   mov dword [esp], 0x0
    |  |||      0x0804866f     e874fdffff       call dword imp.exit
    |  |||         ; imp.exit()
    |  |        ; CODE (JMP) XREF 0x0804865a (fcn.080485b9)
    / loc: loc.08048674 (9)
    |  |        0x08048674  loc.08048674:
    |  `------> 0x08048674     8d45f4           lea eax, [ebp-0xc]
    |   ||      0x08048677     ff00             inc dword [eax]
    |   ||      0x08048679     ebd1             jmp loc.0804864c
    |   ||      ; CODE (JMP) XREF 0x08048643 (fcn.080485b9)
    |   ||      ; CODE (JMP) XREF 0x08048650 (fcn.080485b9)
    / loc: loc.0804867b (2)
    |   ||      0x0804867b  loc.0804867b:
    |   ``----> 0x0804867b     c9               leave
    \           0x0804867c     c3               ret
                ; ------------

This part looks like our previously seen sym.check function.
But bigger.

Don't be scared.
You can recognize the key verification routine of the previous crackme:

    :::python
    s = 0
    for i in password:
        s += i
        if s == 0x10:
            sym.parell()
    print "BADBOY"

As you may have guessed, _parell_ is 08048542

    pdf@08048542
              ; CODE (CALL) XREF 0x0804861e (fcn.080485b9)
    / function: fcn.08048542 (119)
    |         0x08048542  fcn.08048542:
    |         0x08048542     55               push ebp
    |         0x08048543     89e5             mov ebp, esp
    |         0x08048545     83ec18           sub esp, 0x18
    |         0x08048548     8d45fc           lea eax, [ebp-0x4]
    |         0x0804854b     89442408         mov [esp+0x8], eax
    |         0x0804854f     c7442404c2870408 mov dword [esp+0x4], 0x80487c2
    |         0x08048557     8b4508           mov eax, [ebp+0x8]
    |         0x0804855a     890424           mov [esp], eax
    |         0x0804855d     e866feffff       call dword imp.sscanf
    |            ; imp.sscanf()
    |         0x08048562     8b450c           mov eax, [ebp+0xc]
    |         0x08048565     89442404         mov [esp+0x4], eax
    |         0x08048569     8b45fc           mov eax, [ebp-0x4]
    |         0x0804856c     890424           mov [esp], eax
    |         0x0804856f     e840ffffff       call dword fcn.080484b4
    |            ; fcn.080484b4()
    |         0x08048574     85c0             test eax, eax
    |     ,=< 0x08048576     743f             jz loc.080485b7
    |     |   0x08048578     c745f800000000   mov dword [ebp-0x8], 0x0
    |     |   ; CODE (JMP) XREF 0x080485b5 (fcn.08048524)
    / loc: loc.0804857f (58)
    |     |   0x0804857f  loc.0804857f:
    |     |   0x0804857f     837df809         cmp dword [ebp-0x8], 0x9
    |    ,==< 0x08048583     7f32             jg loc.080485b7               ; If greater than 0x9, jumps over GOODBOY
    |    ||   0x08048585     8b45fc           mov eax, [ebp-0x4]
    |    ||   0x08048588     83e001           and eax, 0x1
    |    ||   0x0804858b     85c0             test eax, eax
    |   ,===< 0x0804858d     7521             jnz loc.080485b0
    |   |||   0x0804858f     833d2ca0040801   cmp dword [0x804a02c], 0x1
    |  ,====< 0x08048596     750c             jnz loc.080485a4
    |  ||||   0x08048598     c70424c5870408   mov dword [esp], str.PasswordOK!
    |  ||||   0x0804859f     e814feffff       call dword imp.printf
    |  ||||      ; imp.printf()
    |  |      ; CODE (JMP) XREF 0x08048596 (fcn.08048524)
    / loc: loc.080485a4 (21)
    |  |      0x080485a4  loc.080485a4:
    |  `----> 0x080485a4     c7042400000000   mov dword [esp], 0x0
    |   |||   0x080485ab     e838feffff       call dword imp.exit
    |   |||      ; imp.exit()
    |   |     ; CODE (JMP) XREF 0x0804858d (fcn.08048524)
    / loc: loc.080485b0 (9)
    |   |     0x080485b0  loc.080485b0:
    |   `---> 0x080485b0     8d45f8           lea eax, [ebp-0x8]
    |    ||   0x080485b3     ff00             inc dword [eax]
    |    ||   0x080485b5     ebc8             jmp loc.0804857f
    |    ||   ; CODE (JMP) XREF 0x08048576 (fcn.08048524)
    |    ||   ; CODE (JMP) XREF 0x08048583 (fcn.08048524)
    / loc: loc.080485b7 (2)
    |    ||   0x080485b7  loc.080485b7:
    |    ``-> 0x080485b7     c9               leave
    \         0x080485b8     c3               ret
              ; ------------

Looks roughly like the previous parell function.
Did you noticed the _cmp 0x9_ instruction within a loop ?
Which loop ?
There are no upward arrows !
You should read the code, instead of looking for arrows.

What about:

        0x080485b5     ebc8             jmp loc.0804857f

This is indeed part of a loop.
No other input/ouput than the previous one.
What must be inferior to 0x9 ?
Maybe our password.

    $ LOLO= ./crackme0x07
    IOLI Crackme Level 0x07
    Password: 111111118
    Password OK!

    $ LOLO= ./crackme0x07
    IOLI Crackme Level 0x07
    Password: 1111111117
    Password Incorrect!

:)

## crackme0x08
Let's be <del>lazy</del> clever : our binary rouglhy share the same structure.
It would be nice if we could _diff_ them, and focus on the differences, instead of
having to reverse them from the start, to remember every routine, ...

You can do that with radare2, using radiff2 (see the manpage).

    radiff2 -C crackme0x07 crackme0x08
                    main  0x804867d |   MATCH  (1.000000) | 0x804867d  sym.main
            fcn.080485b9  0x80485b9 |   MATCH  (1.000000) | 0x80485b9  sym.check
            fcn.08048524  0x8048524 |   MATCH  (1.000000) | 0x8048524  sym.che
            fcn.080484b4  0x80484b4 |   MATCH  (1.000000) | 0x80484b4  sym.dummy
            fcn.08048542  0x8048542 |   MATCH  (1.000000) | 0x8048542  sym.parell
           section..text  0x8048400 |   MATCH  (1.000000) | 0x8048400  section..text
    sym.__do_global_dtors_aux  0x8048450 |     NEW  (0.000000)
         sym.frame_dummy  0x8048480 |     NEW  (0.000000)
            fcn.00000000  0x0 |     NEW  (0.000000)
    sym.__do_global_ctors_aux  0x8048760 |     NEW  (0.000000)
     sym.__libc_csu_fini  0x8048750 |     NEW  (0.000000)
           section..fini  0x8048784 |     NEW  (0.000000)
            fcn.0804878d  0x804878d |     NEW  (0.000000)
     sym.__libc_csu_init  0x80486e0 |     NEW  (0.000000)
    sym.__i686.get_pc_thunk.bx  0x8048755 |     NEW  (0.000000)
           section..init  0x8048360 |     NEW  (0.000000)
            fcn.08048424  0x8048424 |     NEW  (0.000000)
            fcn.0804842d  0x804842d |     NEW  (0.000000)

Surprise ! crackme0x08 is the same than crackme0x07.
But there are new functions !
Indeed, but look where they are located: dtors, ctors, init, fini.
crackme0x07 seems to be the stripped version of crackme0x08.

## crackme0x09

The last crackme is left as an exercise to the reader.

## Conclusion

Now go break some [crackmes](http://crackmes.de) with radare2 !
