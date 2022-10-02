// C'est a cause de tous ces include que le info function est illisible
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>

int         main(int argc, char **argv) {
    char    *cli_args[2];
    gid_t   gid;
    uid_t   uid;

    // If input != 423 print No ! and return
    if (atoi(argv[1]) != 423) {
        fwrite(2, 5, 1, "No !\n"); // 2 == stderr
        return(0);
    }
    // On prépare les arguments a passer a execv
    execv_args[0] = strdup("/bin/sh");
    execv_args[1] = NULL;

    // On set les droits du user lancant le binaire sur ceux du fichier
    gid = getegid();
    uid = geteuid();
    setresgid(gid, gid, gid);
    setresuid(uid, uid, uid);

    // On lance la commande /bin/sh /bin/sh (On lance un shell via le shell) et on return
    execv("/bin/sh", cli_args);
    return(0);
}
