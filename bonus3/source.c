#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int         main(int argc, char **argv)
{
	int     ret;
    int     input_number;
	char    buffer[132];    // 0x9c - 0x18
	FILE    *fd;
    
    fd = fopen("/home/user/end/.pass", "r");
	memset(buffer, 0, 132);
	if (!fd || argc != 2)
		return(-1);
    fread(buffer, 1, 66, fd);
    buffer[65] = "\0";
    input_number = atoi(argv[1]);
    buffer[input_number] = "\0";
    fread(&buffer[66], 1, 65, fd);
    fclose(fd);

    if (!strcmp(buffer, argv[1]))
        execl("/bin/sh", "sh", NULL);
    else
        puts(&buffer[66]);
	return (0);
}