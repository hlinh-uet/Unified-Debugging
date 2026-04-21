#include <stdio.h>
#define MAX 100001
int result, Alice, Bob, start,end;
int chocolate[MAX + 1];

int main(int argc, char *argv[])
{
	int loop = 0;
	int i;
	
	scanf("%d", &loop);
	end = 0; // Initialize end to 0
	while (end < loop)
		scanf("%d", &chocolate[end++]);

	result = 0; // Initialize result to 0
	while (end > start)
	{
		if (result > 0)
			result -= chocolate[--end]; // Decrement end before accessing chocolate
		else
			result += chocolate[start++];
	}
	
	printf("%d %d\n", start, loop - start); 
	return 0;
}