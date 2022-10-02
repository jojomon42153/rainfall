int         main(int argc, char **argv)
{
    char    buffer[40];
    int     number;

    number = atoi(argv[1]);
    if (number > 9)
        return (1);
    memcpy(buffer, argv[2], number * 4);
    if (number == 1464814662)
        execl("/bin/sh", "sh", NULL);
    return(0);
}
