int main(void) {
    unsigned int max_u = UINT_MAX;
    unsigned int x = max_u + 1;
    printf("Wrapped value: %u\n", x);

    unsigned int length = 800000000U;
    unsigned int total = length * 2;
    char buf[100];
    if (total < length) {
        printf("Overflow detected: total=%u < length=%u\n", total, length);
    }
    for (unsigned int i = 0; i < total; ++i) {
        buf[i % sizeof(buf)] = 'A';
    }
    return 0;
}
