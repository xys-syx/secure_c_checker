void bad_const_subscript(void)
{
    int a[5];
    a[5] = 0;
    int x = a[-1];
}

void bad_pointer_arith(void)
{
    char buf[8];
    char *p = buf + 9;
    *p = 'x';
}

void ok_cases(void)
{
    int b[3];
    b[2] = 7;
    int *q = b + 3;
}