#include<stdio.h>
#include<unistd.h>
int main(){
    puts("start");
    sleep(1);
    puts("middle");
    sleep(1);
    puts("end");
    return 0;
}