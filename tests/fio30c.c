int main(int argc, char *argv[]) {
    char *user   = argv[1];
    printf(user);
    char fmt[] = "User = %s\n";
    printf(fmt, user);
    printf("Safe literal: %s\n", user);
    char buf[64];
    sprintf(buf, "prefix %s", user);
    printf(buf);
    return 0;
}
