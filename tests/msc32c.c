int main(void) {
    int r = rand();
    printf("%d\n", r);
    srand(42);
    int r = rand();
    printf("%d\n", r);
    srand(time(NULL));
    printf("%d\n", rand());
}