#include <stdio.h>
#define MAX 100001
int result, Alice, Bob, start,end;
int chocolate[MAX + 1];

int main(int argc, char *argv[])
{
	int loop = 0;
	int i;

	scanf("%d", &loop);
	for (i = 0; i < loop; i++)
		scanf("%d", &chocolate[i]);

	start = 0;
	end = loop - 1;
	result = 0;

	while (start <= end)
	{
		if (result > 0)
			result -= chocolate[end--];
		else
			result += chocolate[start++];
	}

	printf("%d %d\n", start, loop - start);
	return 0;
}