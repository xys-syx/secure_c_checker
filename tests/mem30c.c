int main(void) {
    char *buf = malloc(10);
    if (buf == NULL) {
        return 1;
    }
    strcpy(buf, "Hello");
    free(buf);
    strcpy(buf, "World");
    return 0;
}