int system(const char *);
int execvp(const char *, char **);

int main(int argc, char *argv[])
{
    system("mycmd");
    system("./prog");
    system("/usr/bin/ls");
    system(argv[1]);
    char *user_cmd = argv[1];
    char *path     = getenv("PATH");
    char *args1[] = {"ls", NULL};
    execvp("ls", args1);
    char *args2[] = {"./foo", NULL};
    execvp("./foo", args2);
    system(user_cmd);
    system(path);
}