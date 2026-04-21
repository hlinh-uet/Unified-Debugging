#include<stdio.h>
int main(int argc, char *argv[])
{
    int a,b,x1,y,z,x;
    scanf("%d%d",&a,&b);
    if(b>a)
        printf("%d",b);
    else
    {   x1=a+1;
        while(1)
        { x=x1;
          y=b;
          int match = 1; // Added to track if all digits match
          while(x>0)
          {
              z=x%10;
              if(z==4||z==7)
              {
                  if(z==y%10)
                      y=y/10;
                  else
                  {
                      match = 0; // Set match to false if digits don't match
                      break;
                  }
              }
              x=x/10;
          }
          if(match && y==0) // Check if all digits matched and y is 0
          {
              printf("%d",x1);
              break;
          }
          x1++;
        }
    }
    return(0);
}
