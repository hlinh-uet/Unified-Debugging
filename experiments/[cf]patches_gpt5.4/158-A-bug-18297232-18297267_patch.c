#include<stdio.h>
int main(int argc, char *argv[]){
  int n,k,i,c=0;
  scanf("%d %d",&n,&k);
  int score[n];
  for(i=0;i<n;i++){
    scanf("%d",&score[i]);
  }
  if(k > n) k = n;
  for(i=0;i<n;i++){
    if(score[i] > 0 && (k == 0 || score[i] >= score[k-1])) c++;
  }
  printf("%d",c);
  return 0;
}
