#include <stdio.h>
#include <math.h>
int main(int argc, char *argv[])
{
	int a, b;
	int i;
	long long sum;
	int n;
	while (scanf("%d %d", &a, &b) != EOF)
	{
		sum = 0;
		for (i = 1; i <= a; i++)
		{
			scanf("%d", &n);
			sum += n;
		}
		sum = llabs(sum);
		if (sum == 0)
		{
			printf("0\n");
			continue;
		}
		if (b <= 0)
		{
			printf("0\n");
			continue;
		}
		printf("%lld\n", (sum + b - 1) / b);
	}
	return 0;
}
