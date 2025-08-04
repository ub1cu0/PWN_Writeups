# two-sum

El ejercicio nos da el código en C de un programa:

```c
#include <stdio.h>
#include <stdlib.h>

static int addIntOvf(int result, int a, int b) {
    result = a + b;
    if(a > 0 && b > 0 && result < 0)
        return -1;
    if(a < 0 && b < 0 && result > 0)
        return -1;
    return 0;
}

int main() {
    int num1, num2, sum;
    FILE *flag;
    char c;

    printf("n1 > n1 + n2 OR n2 > n1 + n2 \n");
    fflush(stdout);
    printf("What two positive numbers can make this possible: \n");
    fflush(stdout);
    
    if (scanf("%d", &num1) && scanf("%d", &num2)) {
        printf("You entered %d and %d\n", num1, num2);
        fflush(stdout);
        sum = num1 + num2;
        if (addIntOvf(sum, num1, num2) == 0) {
            printf("No overflow\n");
            fflush(stdout);
            exit(0);
        } else if (addIntOvf(sum, num1, num2) == -1) {
            printf("You have an integer overflow\n");
            fflush(stdout);
        }

        if (num1 > 0 || num2 > 0) {
            flag = fopen("flag.txt","r");
            if(flag == NULL){
                printf("flag not found: please run this on the server\n");
                fflush(stdout);
                exit(0);
            }
            char buf[60];
            fgets(buf, 59, flag);
            printf("YOUR FLAG IS: %s\n", buf);
            fflush(stdout);
            exit(0);
        }
    }
    return 0;
}
```

Este código, en resumen, lo que hace es pedir dos números al usuario. Luego, se comprueba si hay un overflow de enteros, y si lo hay, se verifica si los dos números introducidos son positivos. Si ambas condiciones se cumplen, se imprime la flag.

Para llegar a la parte de la función que imprime la flag, hay que cumplir dos condiciones:

* Causar un integer overflow.
* Que los dos números que introduzcamos sean positivos.

Si intentamos causar un overflow introduciendo números muy grandes, no se producirá uno necesariamente. Así que hay que encontrar otra forma.

Observando la función `addIntOvf`:

```c
static int addIntOvf(int result, int a, int b) {
    result = a + b;
    if(a > 0 && b > 0 && result < 0)
        return -1;
    if(a < 0 && b < 0 && result > 0)
        return -1;
    return 0;
}
```

Hay una comprobación sobre cada uno de los inputs, pero no sobre el resultado como tal. Los parámetros `a`, `b` y `result` son de tipo `int`.

El tipo de dato `int` tiene como valor máximo `2,147,483,647`. Entonces, si la suma de los dos números excede ese límite y cada uno por separado no lo supera (para no ser atrapados por las condiciones), lograremos llegar a la parte donde se imprime la flag.

Probamos con:

* Primer número: `2,147,483,647`
* Segundo número: `1`

```bash
nc saturn.picoctf.net 53064
n1 > n1 + n2 OR n2 > n1 + n2
What two positive numbers can make this possible:
2147483647
1
You entered 2147483647 and 1
You have an integer overflow
YOUR FLAG IS: picoCTF{SECRETO}
```

¡Flag obtenida!
