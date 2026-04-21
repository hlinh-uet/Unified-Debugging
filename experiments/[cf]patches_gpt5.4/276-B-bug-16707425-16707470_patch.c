#include<stdio.h>
#include<string.h>

char s[1001];
int c[27];

int main(int argc, char *argv[])
{
    int i, count = 0, len;
    scanf("%1000s", s);

    len = strlen(s);
    for(i = 0; i < len; i++) c[s[i] - 'a']++;

    for(i = 0; i < 26; i++) if(c[i] % 2 == 1) count++;

    if(count == 0 || (count % 2 == 1))
        printf("First\n");
    else
        printf("Second\n");

    return 0;
}
