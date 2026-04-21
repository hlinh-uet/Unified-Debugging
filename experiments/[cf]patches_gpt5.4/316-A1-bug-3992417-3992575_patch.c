#include <stdio.h>
int main(int argc, char *argv[])
{
    long long a[10] = {0}, ans = 1, num = 10, i;
    int q = 0, len = 0;
    char c, first;

    first = getchar();
    if (first == EOF) {
        printf("0");
        return 0;
    }

    if (first >= 'A' && first <= 'J') a[first - 'A'] = 1;
    else if (first == '?') q++;
    len++;

    while ((c = getchar()) != '\n' && c != EOF) {
        if (c >= 'A' && c <= 'J') a[c - 'A'] = 1;
        else if (c == '?') q++;
        len++;
    }

    if (first >= '1' && first <= '9') {
        ans = 1;
    } else if (first >= 'A' && first <= 'J') {
        ans = 9;
        num = 9;
        a[first - 'A'] = 0;
    } else if (first == '?') {
        ans = 9;
        q--;
    } else {
        ans = 1;
    }

    for (i = 0; i < 10; i++) {
        if (a[i] == 1) ans *= num--;
    }

    while (q-- > 0) ans *= 10;

    printf("%lld", ans);
    return 0;
}
