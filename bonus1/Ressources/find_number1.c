#include <stdlib.h>
#include <stdio.h>

int     main(int argc, char **argv)
{
    int number1;

    number1 = atoi(argv[1]);
    printf("%d %zu\n", number1, number1 * 4);
    return (0);
}