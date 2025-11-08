#include <stdio.h>
#include <string.h>

void log_user_message(const char *user, const char *template) {
    char fmtbuf[128];

    snprintf(fmtbuf, sizeof(fmtbuf), "%s: %s", user, template);

    printf(fmtbuf, "STATUS"); 
    putchar('\n');
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <username> <message_template>\n", argv[0]);
        return 2;
    }

    log_user_message(argv[1], argv[2]);
    return 0;
}
