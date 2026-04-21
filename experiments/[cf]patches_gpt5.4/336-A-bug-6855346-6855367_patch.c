#include<stdio.h>
int main(int argc, char *argv[])
{
	long int x,y,s;
	scanf("%ld%ld",&x,&y);
	s = (x >= 0 ? x : -x) + (y >= 0 ? y : -y);

	if(x >= 0 && y >= 0)
	{
		printf("0 %ld %ld 0\n", s, s);
	}
	else if(x <= 0 && y >= 0)
	{
		printf("%ld 0 0 %ld\n", -s, s);
	}
	else if(x <= 0 && y <= 0)
	{
		printf("%ld 0 0 %ld\n", -s, -s);
	}
	else
	{
		printf("0 %ld %ld 0\n", -s, s);
	}
	return 0;
}
