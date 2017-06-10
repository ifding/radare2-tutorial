/* 
 * Binary challenge used for the Radare 2 Primer. 
 * By superkojiman - http://blog.techorganic.com
 * 
*/ 

#include <stdio.h>
#include <string.h>

int check_password(char *pass) {
    int stage2 = 0; 

    /* stage 1, check the first 5 letters */ 
    if (pass[0] == 'h') {
        if (pass[1] == 'e') {
            if (pass[2] == 'l') {
                if (pass[3] == 'l') {
                    if (pass[4] == 'o') {
                        stage2 = 1; 
                    }
                }
            }
        }
    }

    /* stage 2, check the next 5 letters */ 
    if (stage2) {
            if (pass[5] == 'w') {
                if (pass[6] == 'o') {
                    if (pass[7] == 'r') {
                        if (pass[8] == 'l') {
                            if (pass[9] == 'd') {
                                return 0; 
                            }
                        }
                    }
                }
            }
    } else {
        return -1;
    }
}

int check_pass_len(char *pass) {
    int i = 0; 
    while(pass[i] != '\0') {
        i++;
    }
    return i; 
}

int main(int argc, char *argv[]) {
    char pass[10]; 
    int stage2 = 0; 

    printf("Enter password: "); 
    scanf("%s", pass);
    printf("Got [%s]\n", pass); 

 
    if ((check_pass_len(pass) == 10) && 
        (check_password(pass) == 0)) {
        printf("Win!\n");
    } else {
        printf("Fail!\n"); 
    }
    return 0;
}
