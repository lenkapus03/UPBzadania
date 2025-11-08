#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int load_config_line_vulnerable(FILE *f) {
    char buffer[64];
    if (fgets(buffer, sizeof(buffer), f) == NULL)
        return 0;

    if (buffer[strlen(buffer) - 1] != '\n') {
        fread(buffer, 1, 128, f); 
    }

    printf("Loaded line: %s", buffer);
    return 1;
}

int load_config_line_safe(FILE *f) {
    char buffer[64];
    if (!fgets(buffer, sizeof(buffer), f))
        return 0;

    buffer[strcspn(buffer, "\n")] = '\0';
    printf("Loaded line (safe): %s\n", buffer);
    return 1;
}

int main(void) {
    FILE *f = fopen("config.txt", "r");
    if (!f) {
        perror("config.txt");
        return 1;
    }

    printf("Reading with safe function:\n");
    while (load_config_line_vulnerable(f)) { }

    fclose(f);
    return 0;
}
