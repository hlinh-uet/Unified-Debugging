#include <stdio.h>
#include <stdlib.h>
#include<string.h>

int main(int argc, char *argv[])
{
    int t, flag = 0, i, j, k, w1, l, n, m, max = 0, ct, z, a[26], sum = 0;
    char s[1001];
    fgets(s, sizeof(s), stdin);
    w1 = strlen(s) - 1; // Adjust for newline character
    scanf("%d", &k);
    for(i = 0; i < 26; i++)
    {
        scanf("%d", &a[i]);
        if(a[i] > max)
            max = a[i];
    }
    for(i = 0; i < w1; i++)
    {
        sum += (i + 1) * (a[s[i] - 'a']); // Use character value for indexing
    }
    sum += max * (k * (w1 + 1) + (k * (k - 1)) / 2);
    printf("%d", sum);
    return 0;
}
