#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int main(void) {
    const char *path = "/tmp/data.txt";
    if (access(path, W_OK) == 0) {
        int fd = open(path, O_RDWR);
        if (fd >= 0) {
            write(fd, "Hello\n", 6);
            close(fd);
        }
    }

    struct stat st;
    if (stat(path, &st) == 0) {
        FILE *f = fopen(path, "r");
        if (f) {
            char buf[100];
            fgets(buf, sizeof(buf), f);
            fclose(f);
        }
    }
    return 0;
}
