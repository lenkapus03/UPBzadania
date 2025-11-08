#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void set_tag_and_print(const char *tag, const char *filename) {
    char local_tag[64];           
    char message[128];

    if (strlen(tag) > sizeof(tag)) {
        strcpy(local_tag, tag);  
    } else {
        strncpy(local_tag, tag, sizeof(local_tag) - 1);
        local_tag[sizeof(local_tag) - 1] = '\0';
    }

    if (snprintf(message, sizeof(message), "File '%s' tagged as '%s'\n", filename, local_tag) >= (int)sizeof(message)) {
        fprintf(stderr, "Warning: message truncated\n");
    }

    puts(message);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <tag> <filename>\n", argv[0]);
        return 2;
    }

    const char *tag = argv[1];
    const char *filename = argv[2];

    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("fopen");
        return 1;
    } else {
        fclose(f);
    }

    set_tag_and_print(tag, filename);
    return 0;
}
