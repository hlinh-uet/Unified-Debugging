#include<stdio.h>
int main(int argc, char *argv[])
{
    int n, m, z;
    scanf("%d%d", &n, &m);

    z = (n + 1) / 2;

    while (z <= n && z % m != 0) {
        z++;
    }

    if (z <= n)
        printf("%d", z);
    else
        printf("-1");

    return 0;
}
