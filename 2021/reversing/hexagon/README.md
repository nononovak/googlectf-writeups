# HEXAGON

> *slaps DSP*
> This baby can fit so many instructions in its execution slots!

[Attachment](https://github.com/google/google-ctf/blob/master/2021/quals/rev-hexagon/src/challenge)

## Analysis

I didn't solve this challenge during the CTF, but after reading a little bit more afterwards, I decided to give it another try. The challege consists of a single `challenge` binary written for the "QUALCOMM DSP6 Processor". I hadn't had any experience before the CTF with these instruction sets so its all new to me.

## Disassembly

Finding a good disassembler for this "Hexagon" architecture proved to be a little challenge. I completed this challenge completely from static analysis, but it turns out I could've tried using `qemu-hexagon` or possibly [binja-hexagon](https://github.com/google/binja-hexagon). I went through no less than three different disassemblers, none of which were perfect. To start off, I'd recommend reading [the following introduction](https://github.com/programa-stic/hexag00n/blob/master/docs/intro_to_hexagon.rst). After reading this intro, I found the following disassemblers to be helpful:

* [qc\_modem\_tools]](https://github.com/bkerler/qc_modem_tools/blob/master/hexagon_disasm.py) -- This is a good first pass (and written in a single python file) so seems easy enough. It does error out on several instructions and then produces a couple others which are simply "Error". On the positive side, it does display syntax for "packet" instructions which execute in parallel `{}`.
* [radare2](https://rada.re/n/) - I've used radare2 before and its not my favorite, but it does work well here. For positives - it fixes up symbols in the disassembly and labels function names. It also has control flow ASCII art which is helpful to read jump instructions at a glance. On the minus side, it doesn't have the "packet" instructions and didn't disassemble some memory read (`memd`) instructions correctly.
* [hexag00n](https://github.com/programa-stic/hexag00n) - This disassembly got the most instructions "correct", however it doesn't have the nice symbol names of `radare2`. Helpfully, it does decode two instructions later which were important into figuring out how to understand the control flow.

At a 10k-foot view, the binary calls `welcome` which prints "Hi", calls `read_flag` which reads 8 bytes into the `flag` address at 0x3050d, calls the `check_flag` which does a lot of processing, and finally calls `print_status` which presumably prints success or failure. I tackled each of these out of order then returned to the beginning

## check_flag

This seemed like the most interesting and likely to be closest to the answer, so I started here. The function does a bunch of arithmetic operations (add, sub, xor) and has various constants and calls six different `hex1`, `hex2`, ... functions. In turn, each of those functions has additional arithmetic operations. A sample of the `radare2` output looks like:

```
        0x000202dc      805cf606       immext(#0x6f672000)
        0x000202e0      40c50078       R0 = 1869029418            0x6f67202a
        0x000202e4      02302030       R0 = R2 ; R2 = R0
        0x000202e8      21c00078       R1 = 1
        0x000202ec      52c0005a       call loc.hex1
        0x000202f0      02c062f1       R2 = xor (R2, R0)
        0x000202f4      9d715606       immext(#0x656c6740)
        0x000202f8      e0c50078       R0 = 1701603183
        0x000202fc      03303030       R0 = R3 ; R3 = R0
        0x00020300      c1c00078       R1 = 6
        0x00020304      64c0005a       call loc.hex2
```

And the hex functions all have a single "tstbit/if" instruction for conditional branching. They do have some _other_ branching, but that all looks constant. The functions look like

```
        ;-- hex1:
        0x00020390      00460185       P0 = tstbit (R1, 0x6)
    ,=< 0x00020394      10d8005c       if (P0.new) jump:t 0x203b4
    |   0x00020398      bc74a500       immext(#0xa5d2f00)
    |   0x0002039c      85c60078       R5 = 173879092
    |   0x000203a0      00c500f3       R0 = add (R0, R5)
   ,==< 0x000203a4      02c00058       jump 0x203a8
   `--> 0x000203a8      e0ff6076       R0 = sub (-1, R0)
   ,==< 0x000203ac      0ec00058       jump 0x203c8
   ||   0x000203b0      0849a007       immext(#0x7a024200)
   |`-> 0x000203b4      85c00078       R5 = 2046968324
   |    0x000203b8      00c500f3       R0 = add (R0, R5)
   |,=< 0x000203bc      02c00058       jump 0x203c0
   |`-> 0x000203c0      e0ff6076       R0 = sub (-1, R0)
   |,=< 0x000203c4      02c00058       jump 0x203c8
   ``-> 0x000203c8      00c09f52       jumpr R31
```

When disassembling this function, there are two hiccups here. First, the function starts and ends with two similar looking `memd` functions. `radare2` incorrectly disassembles these as:

```
        0x000202d4      144c0000       immext(#0x30500)
        0x000202d8      a2c1c049       R3:R2 = memd (gp + 0x68)

        0x0002037c      144c0000       immext(#0x30500)
        0x00020380      a4c2c049       R5:R4 = memd (gp + 0xa8)
        0x00020384      00c284d2       P0 = cmp.eq (R5:R4, R3:R2)
```

These instructions are very puzzling and don't really make a lot of sense. The `gp` variable or "global pointer" isn't set elsewhere in the program and the offsets 0x68 and 0xa8 don't seem to align with anything else.

Trying the `qc_modem_tools` decompiler gives different looking instructions (below).

```
	0x202d4	{	144c0000		immext (#0x30500)	[Constant extender]
	0x202d8		a2c1c049		R3:2=memd(gp+#0x30528)		}

	0x2037c	{	144c0000		immext (#0x30500)	[Constant extender]
	0x20380		a4c2c049		R5:4=memd(gp+#0x30528)		}
        0x20384 {       00c284d2                P0=cmp.eq(R5:4,R3:2)            }
```

However, these instructions don't quite make sense either because the 0x30528 address doesn't seem to point to something at a named symbol. Also, having the same address doesn't really make sense for the control flow -- read a value, do a bunch of computations on it, then read and compare the result to it again.

Looking at the `hexag00n` compiler, we get something that finally makes sense - the addresses here correspond to `flag` and `target`.

```
[000202d4] { immext
[000202d8]   r3:r2 = memd (gp + #3050d) }

[0002037c] { immext
[00020380]   r5:r4 = memd (gp + #30515) }
[00020384] { p0 = cmp.eq (r5:r4, r3:r2) }
```

A secondary hiccup with disassembly here came with the parallel "packet" instructions. Radare gives the following in a couple locations

```
        0x00020320      02406370       R2 = R3
        0x00020324      03c062f1       R3 = xor (R2, R0)
```

However, these should be part of one packet (so executed at the same time). If you do them in order, then the arithmetic doesn't quite work correctly. The correct disassembly is made by the other two disassemblers:

```
[00020320] { r2 = r3
[00020324]   r3 = xor (r2, r0) }
```

Once I worked through all of these issues and the arithmetic, I re-implemented the logic in Python (see the `solve.py` file).

## print_status and start

This function is simple but gives a hint that there is something else that's missing. On success it prints the "good" string otherwise it prints the "bad" string:

```
            ;-- print_status:
            0x00020298      e0df0076       R0 = and (R0, 255)
        ,=< 0x0002029c      0c58205c       if !P0.new jump:t 0x202b4
        |   0x000202a0      e0df0075       P0 = cmp.eq (R0, 255)
        |   0x000202a4      144c0000       immext(#0x30500)
        |   0x000202a8      a1c30078       R1 = loc.good
        |   0x000202ac      a2c70078       R2 = 61
       ,==< 0x000202b0      08c00058       jump 0x202c0
       |`-> 0x000202b4      154c0000       immext(#0x30540)
       |    0x000202b8      41c30078       R1 = loc.bad
       |    0x000202bc      62c10078       R2 = 11
       `--> 0x000202c0      06c80078       R6 = 64
            0x000202c4      20c00078       R0 = 1
            0x000202c8      04c00054       trap0 (0x1)
            0x000202cc      00c09f52       jumpr R31
```

However, the strings at those locations (0x51d and 0x55a in the `challenge` binary), these don't quite correspond to strings or anything sensical.

```
00000500: 02c0 0058 00c0 9f52 4869 210a 0000 0000  ...X...RHi!.....
00000510: 0000 0000 00bf 96aa 4611 236b b273 5e5c  ........F.#k.s^\
00000520: 5446 5442 4254 584e 5253 534d 1e60 072e  TFTBBTXNRSSM.`..
00000530: 2223 652f 3468 6e09 1f0a 3616 1708 2c75  "#e/4hn...6...,u
00000540: 7323 3d33 253d 7902 0304 7d37 2c40 180d  s#=3%=y...}7,@..
00000550: 1616 450f 0918 1c1e 4566 391c 1650 1015  ..E.....Ef9..P..
00000560: 121d 1b57 7d25 0000 0004 001f 0000 0004  ...W}%..........
```

Looking elsewhere in the binary, we can see that `target` (at 0x515) is referenced in the `entry` function. There appears to be a loop here which XORs each byte with a counter value and stores the result in memory and would explain some string de-obfuscation that we would expect here.

```
            ;-- start:
            ;-- pc:
            0x00020200      00c09da0       allocframe (0x0)            ; [02] -r-x section size 776 named .text
            0x00020204      24c0005a       call loc.welcome
            0x00020208      e0e60978       R0 = 4919
            0x0002020c      144c0000       immext(#0x30500)
            0x00020210      a1c20078       R1 = loc.target
            0x00020214      88c00269       loop0 (0x4, 0x50)
            0x00020218      02c00191       R2 = memb (R1 + 0)
            0x0002021c      028260f1       R2 = xor (R0, R2)
            0x00020220      204000b0       R0 = add (R0, 1)
            0x00020224      08c4a1ab       memb (R1 ++ 1) = R4
```

Coding this in python I get

```
with open('challenge','rb') as fhandle:
  fhandle.seek(0x515)
  data = fhandle.read(0x50)
  fhandle.close()

data = list(data)
R0 = 0x1337 # you'd think this was right ...
for i in range(0x50):
  data[i] = (data[i] ^ (R0+i)) & 0xff
print(bytes(data))
```

But the output still doesn't make sense:

```
$ solve.py
b'\x88\xae\x93|*\x1fV\x8cL\x1e\x1d\x16\x05\x10\x07\x04\x13\x10\x07\x18\x18\x1f\x00P/W\x7fpp1zb?6PEQjKIWL\x14\x11@YVCZ\x11kio\x11ZB/h|de1z\x7fodg?\x1dEah/\x90\x94\x90\x9e\x9f\xd2\xfb'
```

Going through, and checking other values, I found that an initial value of 0x28 will give you some valid strings and a de-obfuscated `target` value.

```
$ solve.py
b"\x97\xbf\x80m=\x0eE\x9dCongratulations! Flag is 'CTF{XXX}' where XXX is your input.\nTry again!\n"
good: b"Congratulations! Flag is 'CTF{XXX}' where XXX is your input.\n"
bad: b'Try again!\n'
target: b'97bf806d3d0e459d'
```

## welcome

It took quite a while to figure out how the 0x28 value (in the last section) was initialized, but my best guess was that there was some funny business with the `welcome` function. After printing the "Hi!" string, it has some other instructions before returning from the function:

```
            0x0002026c      00c067f1       R0 = xor (R7, R0)
            0x00020270      08480000       immext(#entry0)
            0x00020274      1028806a       R0 = main ; memw (Sp + 0x4) = R0
            0x00020278      1ec01e96       dealloc_return
```

As best I can figure out, the address of main (0x20228) which ends with 0x28 is somehow loaded into R0 and stored. I don't know enough about the architecture to tell what R7 or Sp is used for, but this seems to be doing some weird modifications of registers or the stack. I'm going to guess this was intentional by the designers, but it's a bit weird :shrug:

## Solution

Getting to a solution from here is a simple matter if inverting the arithmetic. Each of the operations is invertible, so working backwards from the deobfuscated `target` value will give the input string `IDigVLIW` and a flag of `CTF{IDigVLIW}` (based on the "good" string). Some python code which reduces the extra instructions and then inverts the arithmetic is found in the attached `solve.py` file.

