# RSP

El ejercicio nos ofrece el código de un binario. Al observarlo, podemos ver que es un juego de piedra, papel o tijeras.

Indagando en el programa podemos encontrar lo siguiente:

```c
if (strstr(player_turn, loses[computer_turn])) {
    puts("You win! Play again?");
    return true;
  } else {
    puts("Seems like you didn't win this time. Play again?");
    return false;
  }
```

`strstr` comprueba si la cadena del segundo argumento está contenida en la del primero. Por lo tanto, verifica si el movimiento que hace perder a la máquina está presente en el input del jugador.

Esto tiene lógica, pero en realidad no se está haciendo una comprobación estricta del tipo "input == rock", sino que simplemente se busca la cadena "rock" dentro del input. Esto significa que si introducimos "rock\_", también lo detectaría como válido.

Gracias a esto, si usamos el siguiente payload, ganaremos siempre, ya que contiene todas las cadenas que hacen perder a la máquina:

```
rockpaperscissors
```

Ejemplo de ejecución:

```c
Welcome challenger to the game of Rock, Paper, Scissors
For anyone that beats me 5 times in a row, I will offer up a flag I found
Are you ready?
Type '1' to play a game
Type '2' to exit the program
1
1

Please make your selection (rock/paper/scissors):
rockpaperscissors
rockpaperscissors
You played: rockpaperscissors
The computer played: rock // busca "paper" en nuestra cadena (rockPAPERscissors)
You win! Play again?
```

Si ganamos 5 veces seguidas, el programa nos devolverá la flag.
