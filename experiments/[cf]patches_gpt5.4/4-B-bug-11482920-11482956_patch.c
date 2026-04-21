#include<stdio.h>
int d,sum,max[30],min[30];
int main(int argc, char *argv[])
{
	int i, ma = 0, mi = 0, de, p;
	scanf("%d %d", &d, &sum);
	for(i = 0; i < d; i++)
	{
		scanf("%d %d", &min[i], &max[i]);
		ma += max[i];
		mi += min[i];
	}
	if(sum >= mi && sum <= ma)
	{
		printf("YES\n");
		de = sum - mi;
		p = 0;
		while(de > 0 && p < d)
		{
			int add = max[p] - min[p];
			if(de >= add)
			{
				min[p] = max[p];
				de -= add;
			}
			else
			{
				min[p] += de;
				de = 0;
			}
			p++;
		}
		for(i = 0; i < d; i++)
		{
			if(i) printf(" ");
			printf("%d", min[i]);
		}
		printf("\n");
	}
	else
	{
		printf("NO\n");
	}
	return 0;
}
