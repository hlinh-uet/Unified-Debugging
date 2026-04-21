#include<stdio.h>
int main(int argc, char *argv[])
{
	int gl, gr, bl, br;
	scanf("%d %d %d %d", &gl, &gr, &bl, &br);
	if ((gl == 0 && br == 0) || (gr == 0 && bl == 0))
		printf("YES");
	else if ((gl > 0 && br >= gl - 1 && br <= gl + 1) || (gr > 0 && bl >= gr - 1 && bl <= gr + 1))
		printf("YES");
	else
		printf("NO");
	return 0;
}