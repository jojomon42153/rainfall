## 1: Analyse

### A: C'est quoi mon binaire?
  ```shell
  # On se connecte
  $ ssh level0@127.0.0.1 -p 4242
        _____       _       ______    _ _
      |  __ \     (_)     |  ____|  | | |
      | |__) |__ _ _ _ __ | |__ __ _| | |
      |  _  /  _` | | '_ \|  __/ _` | | |
      | | \ \ (_| | | | | | | | (_| | | |
      |_|  \_\__,_|_|_| |_|_|  \__,_|_|_|

                    Good luck & Have fun

      To start, ssh with level0/level0 on 10.0.2.15:4242

  # On rentre le password
  level0@127.0.0.1's password: <level0>
      GCC stack protector support:            Enabled
      Strict user copy checks:                Disabled
      Restrict /dev/mem access:               Enabled
      Restrict /dev/kmem access:              Enabled
      grsecurity / PaX: No GRKERNSEC
      Kernel Heap Hardening: No KERNHEAP
    System-wide ASLR (kernel.randomize_va_space): Off (Setting: 0)
    RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
    No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   /home/user/level0/level0
  
  # On regarde ce qu'on a
  level0@RainFall:~$ ls -la
    total 737
    dr-xr-x---+ 1 level0 level0     60 Mar  6  2016 .
    dr-x--x--x  1 root   root      340 Sep 23  2015 ..
    -rw-r--r--  1 level0 level0    220 Apr  3  2012 .bash_logout
    -rw-r--r--  1 level0 level0   3530 Sep 23  2015 .bashrc
    -rwsr-x---+ 1 level1 users  747441 Mar  6  2016 level0
    -rw-r--r--  1 level0 level0    675 Apr  3  2012 .profile

  # On teste les arguments
  level0@RainFall:~$ ./level0
    Segmentation fault (core dumped)

  level0@RainFall:~$ ./level0 input
    No !

  level0@RainFall:~$ ./level0 input input
    No !

  level0@RainFall:~$ ./level0 input input input
    No !
  ```
  * On a un binaire appartenant a level1 dans le home avec les droits SUID...
  * ... qui segfault sans arguments ...
  * ... qui print "No !" avec des arguments

### B: On l'ouvre avec gdb
  * On va dans tmp pour lancer avec peda qu'on a copié avec le setup.sh
  ```shell
    level0@RainFall:~$ cd /tmp
  ```

  * On lance gdb avec notre binaire
  ```shell
    level0@RainFall:/tmp$ gdb ~/level0
      [...]
      Reading symbols from /home/user/level0/level0...(no debugging symbols found)...done.
  ```

  * Qu'est-ce qu'on a comme fonctions?
  ```shell
    gdb-peda$ info function
      [...] Output trop long à lire [...]
  ```

  * Commandes lancées pendant l'analyse du binaire ci-dessous
  ```shell
    gdb-peda$ x/s 0x80c5348     # On imprime la valeur passée en argument en format char
      0x80c5348:  "/bin/sh"
    gdb-peda$ x/s 0x80c5348     # Idem
      0x80ee170 <stderr>:	 "\240\347\016\b@\350\016\b\340\350\016\b"
    gdb-peda$ x/s 0x80c5350     # Idem
      0x80c5350:  "No !\n"
  ```

  * On disassemble main pour regarder le code
  ```shell
    gdb-peda$ pdisas main
      Dump of assembler code for function main:
      # Initialisation de la mémoire
      0x08048ec0 <+0>:	  push   ebp            # On stocke le begin pointer
      0x08048ec1 <+1>:	  mov    ebp,esp        # On rebouge ebp au debut de la zone buffer
      0x08048ec3 <+3>:	  and    esp,0xfffffff0 # On applique un masque sur esp pour aligner la mémoire
      0x08048ec6 <+6>:	  sub    esp,0x20       # On laise 32 octets d'espace

      # On lance atoi avec argv[1]
      0x08048ec9 <+9>:	  mov    eax,DWORD PTR [ebp+0xc]  # On fait pointer eax sur argv[0]
      0x08048ecc <+12>:	  add    eax,0x4                  # On avance de 4. eax pointe maintenant sur argv[1]
      0x08048ecf <+15>:	  mov    eax,DWORD PTR [eax]      # On déréférence pour accéder à la valeur
      0x08048ed1 <+17>:	  mov    DWORD PTR [esp],eax      # On push la valeur sur la stack.
      0x08048ed4 <+20>:	  call   0x8049710 <atoi>         # On lance atoi avec l'argument sur la stack. Le retour est stocké dans eax.
    
      # Si atoi(argv[1]) != 423, on saute à la ligne main+152
      0x08048ed9 <+25>:	  cmp    eax,0x1a7            # On compare la valeur du retour d'atoi avec 0x1a7 (423)
      0x08048ede <+30>:	  jne    0x8048f58 <main+152> # Si c'est pas égal (jne == jump not equal), on jump a la ligne main+152

      # On strdup "/bin/sh"
      0x08048ee0 <+32>:	  mov    DWORD PTR [esp],0x80c5348  # On push le pointeur 0x80c5348 sur la stack (voir premiere commande) => c'est la string "/bin/sh"
      0x08048ee7 <+39>:	  call   0x8050bf0 <strdup>         # On la passe dans strdup qui nous renvoie l'adresse du malloc
      0x08048eec <+44>:	  mov    DWORD PTR [esp+0x10],eax   # On stocke l'addresse du malloc dans notre stack à esp+16
      0x08048ef0 <+48>:	  mov    DWORD PTR [esp+0x14],0x0   # On met une value NULL (fin de tableau) a esp + 20 (== ebp - 12)

      # On vérifie le gid et le uid de l'utilisateur
      0x08048ef8 <+56>:	  call   0x8054680 <getegid>      # On call getegid qui va nous retourner le group id
      0x08048efd <+61>:	  mov    DWORD PTR [esp+0x1c],eax # On stocke a esp + 28 (== ebp - 4)
      0x08048f01 <+65>:	  call   0x8054670 <geteuid>      # On call geteuid qui va nous retourner le user id
      0x08048f06 <+70>:	  mov    DWORD PTR [esp+0x18],eax # On stocke a esp + 24 (== ebp - 8)

      # On call setresgid(getegid(), getegid(), getegid())
      0x08048f0a <+74>:	  mov    eax,DWORD PTR [esp+0x1c] # On fait pointer eax sur le retour de getegid
      0x08048f0e <+78>:	  mov    DWORD PTR [esp+0x8],eax  # On le stocke a esp + 8 (== ebp - 24)
      0x08048f12 <+82>:	  mov    eax,DWORD PTR [esp+0x1c] # On fait pointer eax sur le retour de getegid
      0x08048f16 <+86>:	  mov    DWORD PTR [esp+0x4],eax  # On le stocke a esp + 4 (== ebp - 28)
      0x08048f1a <+90>:	  mov    eax,DWORD PTR [esp+0x1c] # On fait pointer eax sur le retour de getegid
      0x08048f1e <+94>:	  mov    DWORD PTR [esp],eax      # On le stocke a esp (== ebp - 32)
      0x08048f21 <+97>:	  call   0x8054700 <setresgid>    # On call setresgid avec nos parametres précédement setup

      # On call setresuid(geteuid(), geteuid(), geteuid())
      0x08048f26 <+102>:	mov    eax,DWORD PTR [esp+0x18] # On fait pointer eax sur le retour de geteuid
      0x08048f2a <+106>:	mov    DWORD PTR [esp+0x8],eax  # On le stocke a esp + 8 (== ebp - 24)
      0x08048f2e <+110>:	mov    eax,DWORD PTR [esp+0x18] # On fait pointer eax sur le retour de geteuid
      0x08048f32 <+114>:	mov    DWORD PTR [esp+0x4],eax  # On le stocke a esp + 4 (== ebp - 28)
      0x08048f36 <+118>:	mov    eax,DWORD PTR [esp+0x18] # On fait pointer eax sur le retour de geteuid
      0x08048f3a <+122>:	mov    DWORD PTR [esp],eax      # On le stocke a esp (== ebp - 32)
      0x08048f3d <+125>:	call   0x8054690 <setresuid>    # On call setresuid avec nos parametres précédement setup

      # On call execv(path="/bin/sh", argv=["/bin/sh", NULL]) et on jump au return
      0x08048f42 <+130>:	lea    eax,[esp+0x10]             # On met esp + 16 (["/bin/sh", NULL] => voir main+32 -> +48) dans eax
      0x08048f46 <+134>:	mov    DWORD PTR [esp+0x4],eax    # On stocke esp + 16 sur la stack a esp + 4
      0x08048f4a <+138>:	mov    DWORD PTR [esp],0x80c5348  # On stocke l'addresse "/bin/sh" sur la stack a esp
      0x08048f51 <+145>:	call   0x8054640 <execv>          # On call execv avec les arguments ci dessus
      0x08048f56 <+150>:	jmp    0x8048f80 <main+192>       # Jump au retour de la fonction main

      # On arrive ici depuis le jump main+30 si l'input est different de 423
      # On print "No !" sur la sortie d'erreur (call fwrite("No !\n", 1, 5, stderr))
      0x08048f58 <+152>:	mov    eax,ds:0x80ee170         # On stocke la valeur du data segment 0x80ee170 (stderr) dans eax
      0x08048f5d <+157>:	mov    edx,eax                  # On stocke eax (stderr) dans edx
      0x08048f5f <+159>:	mov    eax,0x80c5350            # On stocke la valeur a l'adressse 0x80c5350 ("No !\n") dans eax
      0x08048f64 <+164>:	mov    DWORD PTR [esp+0xc],edx  # On push edx (stderr) sur la stack
      0x08048f68 <+168>:	mov    DWORD PTR [esp+0x8],0x5  # On push 5 sur la stack
      0x08048f70 <+176>:	mov    DWORD PTR [esp+0x4],0x1  # On push 1 sur la stack
      0x08048f78 <+184>:	mov    DWORD PTR [esp],eax      # On push eax ("No !\n")
      0x08048f7b <+187>:	call   0x804a230 <fwrite>       # On call fwrite avec les argument push

      # Sortie de programme, return 0
      0x08048f80 <+192>:	mov    eax,0x0  # On met 0 dans eax
      0x08048f85 <+197>:	leave           # On leave
      0x08048f86 <+198>:	ret             # On ret

      End of assembler dump.
  ```

## 2: Comportement
> Une fois recomposé, on comprend que le code check si le parametre commence bien par 423 et lance un shell, sinon il print "No !" et return

## 3: Exploit
> L'exploit coule donc de source, il suffit d'appeler le binaire avec 423 en parametre

```shell
  level0@RainFall:/tmp$ ~/level0 423
  $ whoami
    level1
  $ cat /home/user/level1/.pass
    1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
  $ exit
  level0@RainFall:/tmp$ su level1
    Password: 1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
  RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
  No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   /home/user/level1/level1
  level1@RainFall:~$
```