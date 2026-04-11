#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void win() {
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) {
        printf("Flag file not found!\n");
        return;
    }
    char flag[64];
    fgets(flag, sizeof(flag), f);
    printf("Congratulations! %s\n", flag);
    fclose(f);
}

void vuln() {
    char buf[32];
    printf("Enter your name: ");
    fflush(stdout);
    gets(buf);  // Vulnerable!
    printf("Hello, %s!\n", buf);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    
    printf("Welcome to the PWN challenge!\n");
    vuln();
    return 0;
}
