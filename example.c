int main() {
    char buf[10];
    goto ERROR;
ERROR:
    gets(buf);
    return 0;
}
