# Picker IV

En este ejercicio nos dan un binario junto con su código en C.

Si ejecutamos el binario, podemos ver que nos pide una dirección en hexadecimal a la que saltar:

```c
./picker-IV         
Enter the address in hex to jump to, excluding '0x': 0x0000000000
You input 0x0
Segfault triggered! Exiting.
```

Vamos a asumir que ASLR está desactivado en la máquina víctima y también vamos a desactivarlo en nuestra máquina.

Como ahora las direcciones deberían ser las mismas todo el tiempo, y dado que PIE no está activado, podemos simplemente ver si hay alguna función interesante a la que podamos saltar.

Al revisar el código fuente, observamos la siguiente función:

```c
int win() {
  FILE *fptr;
  char c;

  printf("You won!\n");
  // Open file
  fptr = fopen("flag.txt", "r");
  if (fptr == NULL)
  {
      printf("Cannot open file.\n");
      exit(0);
  }

  // Read contents from file
  c = fgetc(fptr);
  while (c != EOF)
  {
      printf ("%c", c);
      c = fgetc(fptr);
  }

  printf("\n");
  fclose(fptr);
}
```

Esta es la clásica función `win` que imprime la flag, así que vamos a intentar descubrir cuál es su dirección:

```c
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x00000000004010e0  putchar@plt
0x00000000004010f0  puts@plt
0x0000000000401100  fclose@plt
0x0000000000401110  printf@plt
0x0000000000401120  fgetc@plt
0x0000000000401130  signal@plt
0x0000000000401140  setvbuf@plt
0x0000000000401150  fopen@plt
0x0000000000401160  __isoc99_scanf@plt
0x0000000000401170  exit@plt
0x0000000000401180  sleep@plt
0x0000000000401190  _start
0x00000000004011c0  _dl_relocate_static_pie
0x00000000004011d0  deregister_tm_clones
0x0000000000401200  register_tm_clones
0x0000000000401240  __do_global_dtors_aux
0x0000000000401270  frame_dummy
0x0000000000401276  print_segf_message
0x000000000040129e  win // Aquí
0x0000000000401334  main
0x00000000004013d0  __libc_csu_init
0x0000000000401440  __libc_csu_fini
0x0000000000401448  _fini
```

Ahora que sabemos la dirección, vamos a enviársela al programa para ver si salta correctamente a `win`:

```c
Enter the address in hex to jump to, excluding '0x': 0x000000000040129e
You input 0x40129e
You won!
picoCTF{SECRETO}
```

¡Listo!
