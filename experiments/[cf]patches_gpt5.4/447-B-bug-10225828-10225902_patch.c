#include <stdio.h>
#include <stdlib.h>
#include<string.h>

int main(int argc, char *argv[])
{
    int i, k, w1, max = 0;
    long long sum = 0;
    int a[26];
    char s[1001];

    scanf("%1000s", s);
    w1 = strlen(s);
    scanf("%d", &k);

    for (i = 0; i < 26; i++)
    {
        scanf("%d", &a[i]);
        if (a[i] > max)
            max = a[i];
    }

    for (i = 0; i < w1; i++)
    {
        sum += (long long)(i + 1) * a[s[i] - 'a'];
    }

    sum += (long long)max * ((long long)k * (w1 + 1) + ((long long)k * (k - 1)) / 2);

    printf("%lld", sum);
    return 0;
}
