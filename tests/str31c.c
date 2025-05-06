void bad_gets(void)  {
    char buf[16];
    gets(buf);
}

void bad_scanf(void) {
    char arg[8];
    scanf("%s", arg);
    fscanf(stdin, "%10s", arg);
}

void bad_sprintf(void) {
    char out[6];
    sprintf(out, "%s %s", "hi", "all");
}

void ok_cases(void) {
    char good[8];
    strcpy(good, "seven\0");
    char name[128];
    scanf("%127s", name);
}
