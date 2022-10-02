#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void 		n(void) {
	// Cette fonction n'est pas appelée
	system("/bin/cat /home/user/level7/.pass");
}

void 		m(void) {
	puts("Nope");
}

int 		main(int argc, char **argv)
{
	char 	*str;
	// On fait un pointeur sur fonction pour stocker m
	void 	(*ptr)(void);

	str = malloc(64);
	// On le malloc
	ptr = malloc(4);
	ptr = &m;

	strcpy(str, argv[1]);
	ptr();

	return (0);
}
