#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

char	    *p(char *dest, char *to_print)
{
	char	buffer[4096];

	puts(to_print);
	read(0, buffer, 4096);
	*strchr(buffer, '\n') = 0;
	return (strncpy(dest, buffer, 20));
}

char	    *pp(char *buffer)
{
	char	input1[20];
	char	input2[20];
    int     len = -1;

	p(input1, " - ");
	p(input2, " - ");
	strcpy(buffer, input1);
	len = strlen(buffer);
	buffer[len - 1] = ' ';
	buffer[len] = 0;
	return (strcat(buffer, input2));
}

int	        main(void)
{
	char	buffer[42];

	pp(buffer);
	puts(buffer);
	return (0);
}