#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct user{
    char *name;
    struct user *prev, *next;
} user;

typedef struct USERS{
    user *first, *last;
} USERS;

int main(int argc, char *argv[])
{
    char line[101];
    long long traffic = 0;
    int usernum = 0;
    USERS *userlist = (USERS *)malloc(sizeof(USERS));
    userlist->first = (user *)malloc(sizeof(user));
    userlist->last = (user *)malloc(sizeof(user));
    userlist->first->name = NULL;
    userlist->last->name = NULL;
    userlist->first->prev = NULL;
    userlist->last->next = NULL;
    userlist->first->next = userlist->last;
    userlist->last->prev = userlist->first;

    while (fgets(line, sizeof(line), stdin) != NULL) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';

        if (line[0] == '+') {
            user *newuser = (user *)malloc(sizeof(user));
            newuser->name = (char *)malloc(strlen(line + 1) + 1);
            strcpy(newuser->name, line + 1);
            newuser->next = userlist->first->next;
            newuser->prev = userlist->first;
            userlist->first->next->prev = newuser;
            userlist->first->next = newuser;
            usernum++;
        } else if (line[0] == '-') {
            user *moving = userlist->first->next;
            while (moving != userlist->last && strcmp(moving->name, line + 1) != 0)
                moving = moving->next;
            if (moving != userlist->last) {
                moving->prev->next = moving->next;
                moving->next->prev = moving->prev;
                free(moving->name);
                free(moving);
                usernum--;
            }
        } else {
            int i;
            for (i = 0; line[i] != '\0' && line[i] != ':'; i++)
                ;
            if (line[i] == ':')
                traffic += (long long)usernum * (long long)strlen(line + i + 1);
        }
    }

    printf("%lld", traffic);
    return 0;
}
