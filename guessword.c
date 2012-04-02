/*
 * guessword.c
 *
 *  Created on: Apr 2, 2012
 *      Author: jS88
 */

#include <stdio.h>

// /etc/passwd format
// jeffrey:x:1000:1000:Jeffrey Klardie:/home/jeffrey:/bin/bash

int main ( int argc, char *argv[] ){
    if(argc != 3){
        printf("usage: %s password_path shadow_path\n\n", argv[0]);
    } else {
        FILE *passwdfp = fopen(argv[1], "r");
        if(passwdfp != NULL){
            char line[120];
            while(fgets(line, sizeof(line), passwdfp) != NULL ){
                printf(line);
                fflush(stdout);
            }

            fclose (passwdfp);
        } else {
            perror(argv[1]);
        }
    }

    return 0;
}
