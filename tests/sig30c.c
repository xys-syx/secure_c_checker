void handler(int sig) {
    printf("Caught signal %d\n", sig);
    int *p = malloc(sizeof(int));
    if (p) {
        free(p);
    }
}

int main(void) {
    signal(SIGINT, handler);
    printf("Signal handler installed. Press Ctrl+C to trigger it...\n");
    return 0;
}
