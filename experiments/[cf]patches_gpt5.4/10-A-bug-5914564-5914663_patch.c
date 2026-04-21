#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    int n, p1, p2, p3, t1, t2, a, b, i, lr = 0;
    long long power = 0;
    scanf("%d %d %d %d %d %d", &n, &p1, &p2, &p3, &t1, &t2);
    scanf("%d %d", &a, &b);
    power += (long long)(b - a) * p1;
    lr = b;
    for (i = 1; i < n; i++)
    {
        scanf("%d %d", &a, &b);
        power += (long long)(b - a) * p1;
        int gap = a - lr;
        if (gap > 0)
        {
            if (gap <= t1)
            {
                power += (long long)gap * p1;
            }
            else if (gap <= t1 + t2)
            {
                power += (long long)t1 * p1 + (long long)(gap - t1) * p2;
            }
            else
            {
                power += (long long)t1 * p1 + (long long)t2 * p2 + (long long)(gap - t1 - t2) * p3;
            }
        }
        lr = b;
    }
    printf("%lld", power);

    return 0;
}
