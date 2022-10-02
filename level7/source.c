#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

char    c[68];

void    m(void) {
  printf("%s - %d\n", c, time(0));
}

int main(int argc, char **argv) {
  int   *array1;
  int   *array2;
  
  array1 = malloc(8);
  array1[0] = 1;
  array1[1] = malloc(8);

  array2 = malloc(8);
  array2[0] = 2;
  array2[1] = malloc(8);

  // Lors de l'exploit ce strcpy vient réécrire l'addresse contenue dans array2[1]
  strcpy(array1[1], argv[1]);
  // Donc cette addresse envoyée au 2eme strcpy n'est pas l'addresse de array2[1] mais celle de la reference a puts.
  // Vu qu'on écrit argv[2] qui sera l'addresse de m(), quand on va call puts on call en fait m
  strcpy(array2[1], argv[2]);
  
  fgets(c, 68, fopen("/home/user/level8/.pass", "r"));
  puts("~~");
  return(0);
}
