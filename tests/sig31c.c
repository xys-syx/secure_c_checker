int g_count = 0;
int *g_ptr = NULL;
volatile sig_atomic_t flag = 0;

void term_handler(int sig) {
    g_count++;
    if (g_ptr != NULL) {
        free(g_ptr);
        g_ptr = NULL;
    }
    flag = 1;
    printf("Handled SIGTERM, g_count=%d\n", g_count);
}

int main(void) {
    g_ptr = malloc(16);
    signal(SIGTERM, term_handler);
    printf("Ready. Send SIGTERM to this process (PID %d).\n", getpid());
    // Simulate some work:
    for (int i = 0; i < 100000000; ++i) {
        g_count += 2;
        if (flag) break;
    }
    if (flag) {
        printf("Flag set by handler, program terminating.\n");
    }
    free(g_ptr);
    return 0;
}
