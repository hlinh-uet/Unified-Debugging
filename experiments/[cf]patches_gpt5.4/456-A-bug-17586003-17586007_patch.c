#include <stdio.h>
#include <math.h>
int main(int argc, char *argv[]){
    int n;
    scanf("%d", &n);

    int prev_a, prev_b;
    scanf("%d %d", &prev_a, &prev_b);

    int happy = 0;
    for (int i = 1; i < n; i++) {
        int a, b;
        scanf("%d %d", &a, &b);
        if ((a > prev_a && b < prev_b) || (a < prev_a && b > prev_b)) {
            happy = 1;
        }
        prev_a = a;
        prev_b = b;
    }

    if (happy) {
        printf("Happy Alex");
    } else {
        printf("Poor Alex");
    }

    return 0;
}
