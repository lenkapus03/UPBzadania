
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SESSIONS 16
#define LINE_BUF 256

typedef struct {
    int id;
    char *name;
} session;

static session *sessions[MAX_SESSIONS] = {0};

static int parse_id(const char *s) {
    char *end;
    long v = strtol(s, &end, 10);
    if (*end != '\0' || v < 0 || v >= MAX_SESSIONS) return -1;
    return (int)v;
}

static void do_create(int id, const char *name) {
    if (sessions[id]) {
        printf("slot %d already in use\n", id);
        return;
    }
    session *s = malloc(sizeof(*s));
    if (!s) { perror("malloc"); exit(1); }
    s->id = id;
    s->name = strdup(name);
    sessions[id] = s;
    printf("created session %d (%s)\n", id, s->name);
}

static void do_close(int id) {
    session *s = sessions[id];
    if (!s) { printf("slot %d empty\n", id); return; }
    free(s->name);
    free(s);
    printf("closed session %d\n", id);
}

static void do_send(int id, const char *msg) {
    session *s = sessions[id];
    if (!s) { printf("slot %d empty\n", id); return; }
    printf("[%d:%s] %s\n", s->id, s->name, msg);
}

static void do_list(void) {
    for (int i = 0; i < MAX_SESSIONS; ++i) {
        if (sessions[i]) printf("[%d] %s\n", i, sessions[i]->name);
        else printf("[%d] <empty>\n", i);
    }
}

int main(void) {
    char line[LINE_BUF];

    printf("sessionmgr_vuln> (type 'quit' to exit)\n");
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = '\0';

        if (strncmp(line, "quit", 4) == 0) break;
        if (strncmp(line, "list", 4) == 0) {
            do_list();
            continue;
        }

        char *cmd = strtok(line, " ");
        if (!cmd) continue;

        if (strcmp(cmd, "create") == 0) {
            char *id_s = strtok(NULL, " ");
            char *name = strtok(NULL, "");
            if (!id_s || !name) { printf("usage: create <id> <name>\n"); continue; }
            int id = parse_id(id_s);
            if (id < 0) { printf("bad id\n"); continue; }
            do_create(id, name);
        } else if (strcmp(cmd, "close") == 0) {
            char *id_s = strtok(NULL, " ");
            if (!id_s) { printf("usage: close <id>\n"); continue; }
            int id = parse_id(id_s);
            if (id < 0) { printf("bad id\n"); continue; }
            do_close(id);
        } else if (strcmp(cmd, "send") == 0) {
            char *id_s = strtok(NULL, " ");
            char *msg = strtok(NULL, "");
            if (!id_s || !msg) { printf("usage: send <id> <message>\n"); continue; }
            int id = parse_id(id_s);
            if (id < 0) { printf("bad id\n"); continue; }
            do_send(id, msg);
        } else {
            printf("unknown command\n");
        }
    }

    return 0;
}
