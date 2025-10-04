# User input

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    int age;
    char name[30];
    char fullName[30];

    // First name
    printf("What is your firt name? ");
    scanf("%s", name);

    // Full name
    printf("What is your full name? ");
    fgets(fullName, sizeof(fullName), stdin);
    fullName[strlen(fullName)-1] = '\0';

    // Age
    printf("How old are you? ");
    scanf("%d", &age);

    printf("Your name is %s.\n", name);
    printf("Your full name is %s.\n", fullName);
    printf("You age is %d.\n", age);
    return 0;
}
```
