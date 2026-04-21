#include<stdio.h>
int main(int argc, char *argv[])
{
    int m, n, i, j;
    scanf("%d %d", &n, &m);

    if (n == 0 && m > 0)
        printf("Impossible");
    else
    {
        if (m > 0)
            i = n + m - 1;
        else
            i = n + m;

        if (m > n)
            j = m;
        else
            j = n;

        printf("%d %d", j, i);
    }

    return 0;
}
