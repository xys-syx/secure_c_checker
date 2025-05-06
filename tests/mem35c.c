int main(void) {
    int *ptr;
    ptr = malloc(sizeof(ptr) * 10);
    for (int i = 0; i < 10; ++i) {
        ptr[i] = i;
    }
    free(ptr);

    size_t len = 5;
    char *buf = malloc(len);
    strcpy(buf, "Hello");
    free(buf);
    return 0;
}
