int global_array[5];

void free_wrapper(int *p) {
    free(p);
}

int main(void) {
    int *heap1 = malloc(4 * sizeof(int));
    int *heap2 = malloc(4 * sizeof(int));
    if (heap1) {
        int *mid = heap1 + 1;
        free(mid);
    }
    free(global_array);
    int local;
    free(&local);
    char *str = "Hello";
    free(str);

    if (heap1) free(heap1);
    if (heap2) free(heap2);

    char *data = malloc(10);
    free(data);

    int *not_heap = global_array;
    free_wrapper(not_heap);

    int *heap3 = malloc(16);
    if (heap3) {
        free_wrapper(heap3);
    }

    return 0;
}
