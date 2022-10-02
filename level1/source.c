#include <stdio.h>

void        run() {
    fwrite("Good... Wait what?\n", 19, 1, stdout);
    system("/bin/sh");
    return();
}

int         main(void) {
    char    buffer[64];
    return(gets(buffer));
}
