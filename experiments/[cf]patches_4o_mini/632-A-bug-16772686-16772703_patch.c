#include<stdio.h>
int main(int argc, char *argv[]){
    int a,b,k;
    char arr[50];
    char store[50];
    scanf("%d%d",&a,&b);
    getchar();
    double s=0;
    double res=0; 
    double x=0;
    int i;
    for(i=0;i<a;i++){
        fgets(arr, sizeof(arr), stdin);
        arr[strcspn(arr, "\n")] = 0; // Remove newline character
        if(strlen(arr)==8){
            store[i]='2';
        }
        else{
            store[i]='1';
        }
    }
    for(k=a-1;k>=0;k--){ // Change loop to iterate over all inputs
        if(store[k]=='2'){
            s=(2*res)+0.5;
            res=s;
            x=x+(res*b);
        }
        else{
            s=(2*res);
            res=s;
            x=x+(res*b);
        }
    }
    printf("%lld",(long long int)x);
    return 0;
}
