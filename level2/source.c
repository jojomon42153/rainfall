#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// J'ai choisi de ne pas représenter frame_dummy puisque seule son instruction call eax nous intéresse.
// On aurait pu en prendre une autre.
// Ca n'enleve pas le fait que frame_dummy est une fonction, ca enlève juste du travail inutile :D

char        *p() {
    // 64 parceque dans l'assembleur meme si on prend EPB-76 on stocke une addresse dans EPB - 12 donc 76-12=64
    char    buffer[64];
    void    *eip;

    fflush(stdout);
    // On prend l'input
    gets(buffer);
    // On prend l'EIP
    eip = __builtin_return_address(0);
    // Si l'eip est sur la stack on le print et on exit
    if (((int)eip & 0xb0000000) == 0xb0000000) {
        printf("%p\n", eip);
        exit(1);
    }
    // Sinon on print l'input et on return une copie du buffer
    puts(buffer);
    return(strdup(buffer));
}

int         main(void) {
    // Ouais main fait que ça
    p();
    return(0);
}
