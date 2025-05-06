int *gp;

void test_uninit(int flag) {
    int x;
    int y = 5;
    int z;
    if (flag) {
        z = 10;
    }
    printf("%d\n", x);
    printf("%d\n", y);
    int a = z + 1;
    if (!flag) {
        z = 0;
    }
    printf("%d\n", z);

    int *p;
    if (flag) {
        p = malloc(sizeof(int));
        *p = 42;
    }
    if (!flag) {
        printf("%d\n", *p);
    }
    if (!flag) {
        p = &(y);
    }
    printf("%d\n", *p);

    int idx;
    int arr[5] = {0};
    arr[idx] = 1;

    int k;
    k++;

    char *q;
    free(q);
}

int main(void) {
    if (gp == NULL) {
        printf("gp is null\n");
    }
    test_uninit(0);
    test_uninit(1);
    return 0;
}
