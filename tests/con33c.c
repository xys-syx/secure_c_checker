char *shared_str = "token1,token2,token3";
pthread_mutex_t lock;

void *do_work(void *arg) {
    char buf[50];
    strcpy(buf, shared_str);
    char *tok = strtok(buf, ",");
    while (tok) {
        printf("Thread %ld got token: %s\n", (long)arg, tok);
        time_t t = time(NULL);
        char *timestr = asctime(localtime(&t));
        printf("Time: %s", timestr);
        tok = strtok(NULL, ",");
    }
    return NULL;
}

int main(void) {
    pthread_t t1, t2;
    pthread_create(&t1, NULL, do_work, (void*)1);
    pthread_create(&t2, NULL, do_work, (void*)2);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    return 0;
}
