class N {
public:
    // La ligne suivante présente dans l'asm fait rapport a la virtualtable en cpp pour accéder plus vite aux méthodes de fonction.
    // Je ne sais pas si c'est under the hood dans la compilation ou si c'est dû à un prototypage, donc je n'essaye pas de le recoder.
    // Ce n'est de toute manière pas important pour l'exploit, juste pour comprendre les déréférencements de pointeurs sur ces classes.
    // int     (N::*virtual_func)(N &);
    char    annotation[100];
    int     number;

    N(int n) {
        this->virtual_func = N::operator+;
        this->number = n;
    }

    int operator+(N &n) {
        return(this->number + n.number);
    }

    int operator-(N &n) {
        return(this->number - n.number);
    }

    void setAnnotation(char *str) {
        memcpy(this->annotation, str, strlen(str));
    }
};

int     main(int argc, char **argv)
{
    if (argc <= 1)
        exit(1);
    // L'asm fait des choses avec des pointeurs sur ces classes mais ici c'est du pseudocode. TOZ.
    N   *number5;
    N   *number6;

    number5 = new N(5);
    number6 = new N(6);

    number5->setAnnotation(argv[1]);
    return (*number5 + *number6);
}
