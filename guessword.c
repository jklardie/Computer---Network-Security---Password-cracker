/*
 * guessword.c
 *
 *  Created on: Apr 2, 2012
 *      Author: jS88
 */

#include <stdio.h>
#include <string.h>
#include <crypt.h>

/*
 * assumptions:
 * - passwd and shadow files have 4096 lines
 * - passwd and shadow files have same order of usernames
 *
 */


/*
 * /etc/passwd format
 * jeffrey:x:1000:1000:Jeffrey Klardie:/home/jeffrey:/bin/bash
 *
 * /etc/shadow format
 * jeffrey:$6$CVt2kdq7zD4WjEny$m7RG1Xa2pN/8qNsgCNk:15430:0:99999:7:::
 */


const char* DELIMITER = ":";
const char* PASSWORD_DELIMITER = "$";

const int MAX_LINE_LENGTH = 128;
const int NUM_USERS = 4096;

int foundPasswds, dict250Passwds, dictFullPasswds, yearPasswds;

int numEleet = 15;
char eleet[numEleet][2] = {
    {'a', '@'},
    {'a', '4'},
    {'b', '8'},
    {'c', '('},
    {'c', '<'},
    {'e', '3'},
    {'i', '1'},
    {'i', '!'},
    {'k', 'X'},
    {'o', '0'},
    {'s', '5'},
    {'t', '7'},
    {'l', '1'},
    {'l', '7'},
    {'z', '2'}
};

typedef struct _user {
    char *username;
    char *fullname;
    char *passEnc;
    char *passPlain;
    char *salt;
} user;

void strreplace(char *str, char old, char new)  {
    char *pos;
    while(1){
        pos = strchr(str, old);
        if (pos == NULL)  {
            break;
        }
        *pos = new;
    }
}

int checkPass(char *pass, user users[], int numUsers){
    char *nl = strrchr(pass, '\r');
    if (nl) *nl = '\0';
    nl = strrchr(pass, '\n');
    if (nl) *nl = '\0';

    char *password = crypt(pass, users[0].salt);

    int i, foundPasswdsStart = foundPasswds;
    for(i=0; i<numUsers; i++){
        if(users[i].passPlain == NULL && strcmp(password, users[i].passEnc) == 0){
            asprintf(&users[i].passPlain, "%s", pass);
            printf("%5d  %s:%s\n", ++foundPasswds, users[i].username, pass);
            fflush(stdout);
        }
    }

    return foundPasswds - foundPasswdsStart;
}

void checkNumberPasswords(char *password, user users[], int numUsers){
    int i;
    char *newPass;
    for(i=1; i<10; i++){
        asprintf(&newPass, "%s%d", password, i);
        checkPass(newPass, users, numUsers);
    }

    for(i=85; i<100; i++){
        asprintf(&newPass, "%s%d", password, i);
        checkPass(newPass, users, numUsers);
    }
}

void checkEleetPasswords(char *password, user users[], int numUsers){
    int i;
    for(i=0; i<numEleet; i++){
        strreplace(password, eleet[i][0], eleet[i][1]);
        checkPass(password, users, numUsers);
    }
}

void checkDictPasswords(char *dictPath, user users[], int numUsers){
    FILE *dictfp = fopen(dictPath, "r");
    if(dictfp != NULL){
        char password[MAX_LINE_LENGTH];

        while(fgets(password, MAX_LINE_LENGTH, dictfp) != NULL ){
            checkPass(password, users, numUsers);
            //checkNumberPasswords(password, users, numUsers);
            checkEleetPasswords(password, users, numUsers);
        }
    }
}

void extractPass(char *shadowPath, user users[]){
    FILE *shadowfp = fopen(shadowPath, "r");
    if(shadowfp != NULL){
        char line[MAX_LINE_LENGTH];
        char *username = NULL, *password = NULL, *algorithm = NULL, *salt = NULL;

        int i = -1;
        while(fgets(line, MAX_LINE_LENGTH, shadowfp) != NULL ){
            username = strtok(line, DELIMITER);
            password = strtok(NULL, DELIMITER);

            salt = strdup(password);
            algorithm = strtok(salt, PASSWORD_DELIMITER);
            salt = strtok(NULL, PASSWORD_DELIMITER);

            if(strcmp(users[++i].username, username) != 0)
                printf("Usernames not correct. Passwd username: %s, shadow username: %s\n", users[i].username, username);

            asprintf(&users[i].passEnc, "%s", password);
            asprintf(&users[i].salt, "$%s$%s$", algorithm, salt);
            users[i].passPlain = NULL;
        }

        fclose (shadowfp);
    } else {
        perror(shadowPath);
    }
}

void extractName(char *passwdPath, user users[]){
    FILE *passwdfp = fopen(passwdPath, "r");
    if(passwdfp != NULL){
        char line[MAX_LINE_LENGTH];
        char *username = NULL, *fullname = NULL;

        int i = -1;
        while(fgets(line, MAX_LINE_LENGTH, passwdfp) != NULL ){
            username = strtok(line, DELIMITER);

            strtok(NULL, DELIMITER); // skip passwd field
            strtok(NULL, DELIMITER); // skip userid field
            strtok(NULL, DELIMITER); // skip groupid field

            fullname = strtok(NULL, DELIMITER);

            strtok(NULL, DELIMITER); // skip home folder field
            if(strtok(NULL, DELIMITER) == NULL) // if shell is empty, the account had no user
                fullname = "";

            asprintf(&users[++i].username, "%s", username);

            char *name = NULL;
            if((name = strtok(fullname, ",")) != NULL)
                fullname = name;

            asprintf(&users[i].fullname, "%s", fullname);
        }

        fclose (passwdfp);
    } else {
        perror(passwdPath);
    }
}

void extractData(char *passwdPath, char *shadowPath, user users[]){
    extractName(passwdPath, users);
    extractPass(shadowPath, users);
}

int main(int argc, char *argv[] ){
    if(argc != 3){
        printf("usage: %s password_path shadow_path\n\n", argv[0]);
    } else {
        user users[NUM_USERS];
        extractData(argv[1], argv[2], users);

        checkDictPasswords("./files/dictionary-top250.txt", users, NUM_USERS);
//        checkDictPasswords("./files/dictionary-bnc.txt", users, NUM_USERS);
    }

    return 0;
}
