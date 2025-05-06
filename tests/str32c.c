int main(void) {
    char dest[5];
    strncpy(dest, "ABCDE", sizeof(dest));
    printf("Dest: %s\n", dest);

    int fd = open("/dev/urandom", O_RDONLY);
    char buf[10];
    read(fd, buf, sizeof(buf));
    close(fd);
    size_t len = strlen(buf);
    printf("Length: %zu\n", len);
    return 0;
}
