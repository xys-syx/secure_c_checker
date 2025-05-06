#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    size_t n = 1000000000;
    char *data = malloc(n);
    strcpy(data, "Hello");

    data = realloc(data, n * 2);
    strcat(data, " World");

    printf("%s\n", data);
    free(data);
    return 0;
}
