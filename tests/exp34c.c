int main(void) {
    int *p = (int*)0;
    *p = 5;

    int *q = NULL;
    if (q == NULL) {
        int val = *q;
    }

    int *r = malloc(10 * sizeof(int));
    *r = 42;
    free(r);
    return 0;
}
