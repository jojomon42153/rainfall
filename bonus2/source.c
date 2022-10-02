#include <string.h>

int         language = 0;

void        greetuser(char *to_concat)
{
    char    *to_print,;
    
    if (language == 1)
        strcpy(to_print, "Hyvää päivää ");
    else if (language == 2)
        strcpy(to_print, "Goedemiddag! ");
    else if (language == 0) {
        strcpy(to_print, "Hello ");

    strcat(to_print, to_concat);
    puts(to_print);
    return;
}

int         main(int argc, char **argv)
{
    char    *env_lang;
    char    input_1[40];
    char    input_2[32];
    
    if (argc != 3)
        return (1);
    strncpy(input_1, argv[1], 40);
    strncpy(input_2, argv[2], 32);
    env_lang = getenv("LANG");
    if (env_lang)
    {
        if (!memcmp(env_lang, "fi", 2))
            language = 1;
        else if (!memcmp(env_lang, "nl", 2))
            language = 2;
    }
    greetuser(input_1);
    return (0);
}