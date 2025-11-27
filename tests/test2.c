#include<stdio.h>
#include <stdlib.h>
int main(){
    int sum;
    printf("anter the size u whant to allocate\n");
    scanf("%d",&sum);
    printf("the size u enter is:%d\n",sum);
    char *ptr=malloc(sum);
    for(int i=0;i<sum;i++){
        ptr[i]=0;
    }
    for(int j=0;j<sum;j++){
        printf("%d ",ptr[j]);
    }
    free(ptr);
    

    return 0;
}
