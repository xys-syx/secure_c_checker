int main(void) {
    long big = 5000000000;
    int truncated = (int) big;
    printf("Truncated value: %d (original %ld)\n", truncated, big);

    int neg = -42;
    unsigned int asUnsigned = (unsigned int) neg;
    printf("Negative as unsigned: %u (original %d)\n", asUnsigned, neg);

    int largeInt = INT_MAX;
    short narrowed = (short) largeInt;
    printf("Narrowed value: %d (original %d)\n", narrowed, largeInt);
    return 0;
}
