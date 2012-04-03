/*
 * guessword.c
 *
 *  Created on: Apr 2, 2012
 *      Author: jS88
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <crypt.h>
#include <unistd.h>

/*
 * assumptions:
 * - passwd and shadow files have 4096 lines
 * - passwd and shadow files have same order of usernames
 *
 */


const char* DELIMITER = ":";
const char* PASSWORD_DELIMITER = "$";

const int MAX_LINE_LENGTH = 128;
const int NUM_USERS = 4096;

int foundPasswds, dict250Passwds, dictFullPasswds, yearPasswds;
int res;

const int NUM_ELEET = 17;
char eleet[17][2] = {
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
    {'z', '2'},
    {'h', '#'},
    {'g', '9'}
};

int checkedPos = 0;
char *checkedWords[250];

const int NUM_SUPER_ELEET = 13;
char* superEleet[13][2] = {
    {"a", "/\\"},
    {"u", "|_|"},
    {"o", "()"},
    {"n", "|\\|"},
    {"d", "|)"},
    {"d", "[)"},
    {"m", "/\\/\\"},
    {"m", "/V\\"},
    {"x", "><"},
    {"w", "\\/\\/"},
    {"h", "|-|"},
    {"k", "|<"},
    {"l", "|_"}
};

typedef struct _user {
    char *username;
    char *fullname;
    char *passEnc;
    char *passPlain;
    char *salt;
} user;

int strreplace(char *str, char old, char new, int offset)  {
    int i=0;
    
    while(*str != '\0'){
        if(*str == old && ++i > offset){
            *str = new;
            return i;
        }
        str++;
    }
    
    return 0;
}

int strstrreplace(char **str, char *old, char *new, int offset)  {
    int i=0;
    char *newstr, *result;
    char oldChar = *old;
    
    res = asprintf(&newstr, "%s%s", *str, new);
    result = newstr;
    
    while(**str != '\0'){
        if(**str == oldChar && ++i > offset){
            while(*new != '\0'){
                *newstr = *new;
                newstr++;
                new++;
            }
            
            (*str)++;
            
            // cp last part of str
            while(**str != '\0'){
                *newstr = **str;
                newstr++;
                (*str)++;
            }
            
            // go to end of str and remove last char 
            while(*newstr != '\0'){
                (*newstr)++;
            }
            *newstr = '\0';
            
            res = asprintf(str, "%s", result);
            return i;
        }
        
        newstr++;
        (*str)++;
    }
    
    return 0;
}

void checkPassForUser(char *pass, char *encryptedPass, user* user){
    if(!user->passPlain && strcmp(encryptedPass, user->passEnc) == 0){
        res = asprintf(&user->passPlain, "%s", pass);
        ++foundPasswds;
        printf("%s:%s\n", user->username, pass);
        fflush(stdout);
    }
}

int checkPass(char *pass, user users[], int numUsers){
    char *password = crypt(pass, users[0].salt);

    int i, foundPasswdsStart = foundPasswds;
    for(i=0; i<numUsers; i++){
        checkPassForUser(pass, password, &users[i]);
    }

    return foundPasswds - foundPasswdsStart;
}

void checkNumberPasswords(char *password, user users[], int numUsers, user* user){
    if(user != NULL && user->passPlain != NULL) return;
        
    int i;
    char *cryptPass;
    char *newPass;
    for(i=1; i<10; i++){
        res = asprintf(&newPass, "%s%d", password, i);
        if(users == NULL){
            cryptPass = crypt(newPass, user->salt);
            checkPassForUser(newPass, cryptPass, user);
            if(user != NULL && user->passPlain != NULL) return;
        } else {
            checkPass(newPass, users, numUsers);
        }
    }

    for(i=85; i<100; i++){
        res = asprintf(&newPass, "%s%d", password, i);
        if(users == NULL){
            cryptPass = crypt(newPass, user->salt);
            checkPassForUser(newPass, cryptPass, user);
            if(user != NULL && user->passPlain != NULL) return;
        } else {
            checkPass(newPass, users, numUsers);
        }
            
        res = asprintf(&newPass, "%s19%d", password, i);
        if(users == NULL){
            cryptPass = crypt(newPass, user->salt);
            checkPassForUser(newPass, cryptPass, user);
            if(user != NULL && user->passPlain != NULL) return;
        } else {
            checkPass(newPass, users, numUsers);
        }
    }
}

void checkEleetPasswords(char *password, user users[], int numUsers, user* user){
    if(user != NULL && user->passPlain != NULL) return;
    
    int i;
    char *cryptPass;
    char *newPass;
    int offset, offsetSuperEleet;
    for(i=0; i<NUM_ELEET; i++){
        offset = 0;
        res = asprintf(&newPass, "%s", password);

        while((offset = strreplace(newPass, eleet[i][0], eleet[i][1], offset)) > 0){
            if(users == NULL){
                cryptPass = crypt(newPass, user->salt);
                checkPassForUser(newPass, cryptPass, user);
                if(user != NULL && user->passPlain != NULL) return;
            } else {
                checkPass(newPass, users, numUsers);
            }
            
            res = asprintf(&newPass, "%s", password);
            
        }
    }
    
    for(i=0; i<NUM_SUPER_ELEET; i++){
        offsetSuperEleet = 0;
        res = asprintf(&newPass, "%s", password);
        
        while((offsetSuperEleet = strstrreplace(&newPass, superEleet[i][0], superEleet[i][1], offsetSuperEleet)) > 0){
            if(users == NULL){
                cryptPass = crypt(newPass, user->salt);
                checkPassForUser(newPass, cryptPass, user);
                if(user != NULL && user->passPlain != NULL) return;
            } else {
                checkPass(newPass, users, numUsers);
            }
            
            res = asprintf(&newPass, "%s", password);
        }
    }
}

void checkCapitalPasswords(char *password, user users[], int numUsers, user* user){
    if(user != NULL && user->passPlain != NULL) return;
    
    char *pass = password;
    char *prevPass;
    char *cryptPass;

    int pos = 0;
    while(*password != '\0'){
        if(user != NULL && user->passPlain != NULL) return;
    
        res = asprintf(&prevPass, "%s\n", password);
        if(pos++ > 0){
            --password;
            *password = tolower((unsigned char) *password);            
            
            ++password;
        }
        
        *password = toupper((unsigned char) *password);
        ++password;
        
        if(strcmp(password, prevPass) == 0)
            continue;
            
        if(users == NULL){
            cryptPass = crypt(pass, user->salt);
            checkPassForUser(pass, cryptPass, user);
            if(user != NULL && user->passPlain != NULL) return;
        } else {
            checkPass(pass, users, numUsers);
        }
    }

    if(user != NULL && user->passPlain != NULL) return;
            
    password = pass;
    prevPass = password;
    while(*password != '\0'){
        *password = toupper((unsigned char) *password);
        ++password;
        
        if(strcmp(password, prevPass) == 0)
            return;
    }
    
    if(users == NULL){
        cryptPass = crypt(pass, user->salt);
        checkPassForUser(pass, cryptPass, user);
        if(user != NULL && user->passPlain != NULL) return;
    } else {
        checkPass(pass, users, numUsers);
    }
}

int alreadyCheckedWord(char* password){
    int i;
    for(i=0; i<checkedPos; i++)
        if(strcmp(password, checkedWords[i]) == 0)
            return 1;

    return 0;
}

void checkDictPasswords(char *dictPath, user users[], int numUsers){
    FILE *dictfp = fopen(dictPath, "r");
    if(dictfp != NULL){
        char password[MAX_LINE_LENGTH];
        while(fgets(password, MAX_LINE_LENGTH, dictfp) != NULL ){
            char *nl = strrchr(password, '\r');
            if (nl) *nl = '\0';
            nl = strrchr(password, '\n');
            if (nl) *nl = '\0';
            
            if(alreadyCheckedWord(password) == 1)
                continue;

            if(checkedPos < 250){
                res = asprintf(&checkedWords[checkedPos++], "%s", password);
            }

            checkPass(password, users, numUsers);
            checkEleetPasswords(password, users, numUsers, NULL);
            checkNumberPasswords(password, users, numUsers, NULL);
            checkCapitalPasswords(password, users, numUsers, NULL);
        }
        fclose (dictfp);
    } else {
        perror(dictPath);
    }
}

void checkSimplePasswords(user users[], int numUsers){
    checkPass("666666", users, numUsers);
    checkPass("7777777", users, numUsers);
    checkPass("88888888", users, numUsers);
    checkPass("999999999", users, numUsers);
    checkPass("werty", users, numUsers);
    checkPass("abcdefg", users, numUsers);
    checkPass("bcdefg", users, numUsers);
    checkPass("asdfghj", users, numUsers);
    checkPass("tyuiop", users, numUsers);    
    checkPass("dfghj", users, numUsers);    
    

   int i;
    char* pass;
    for(i=0; i<99999; i++){
        res = asprintf(&pass, "%d", i);
        checkPass(pass, users, numUsers);
    }
    
}

void checkBruteForceNumberPasswords(user users[], int numUsers){
    int i;
    char* pass;
    for(i=100000; i<9999999; i++){
        res = asprintf(&pass, "%d", i);
        checkPass(pass, users, numUsers);
    }
    
}

void checkBruteForceCharPasswords(user users[], int numUsers){
    int i, j, k, l ,m;
    char* pass;
    int a = (int)'a';
    int z = (int)'z';
    
    for(i=a; i<=z; i++){
        for(j=a; j<=z; j++){
            for(k=a; k<=z; k++){
                res = asprintf(&pass, "%c%c%c", (char)i,(char)j,(char)k);
                checkPass(pass, users, numUsers);
                
                for(l=a; l<=z; l++){
                    res = asprintf(&pass, "%c%c%c%c", (char)i,(char)j,(char)k,(char)l);
                    checkPass(pass, users, numUsers);
                    
                    for(m=a; m<=z; m++){
                        res = asprintf(&pass, "%c%c%c%c%c", (char)i,(char)j,(char)k,(char)l,(char)m);
                        checkPass(pass, users, numUsers);
                    }
                }
            }
        }
    }
    
}

void checkBirthdayPasswords(user users[], int numUsers){
    int d, m, y;
    char* pass;
    for(d=1; d<=31; d++){
        for(m=1; m<=12; m++){
            for(y=60; y<100; y++){
                res = asprintf(&pass, "%d%d%d", m, d, y);
                checkPass(pass, users, numUsers);
            }
        }
    }
}

void checkNamePasswords(user users[], int numUsers){
    int i;
    char *firstname, *lastname;
    char *password;

    for(i=0; i<numUsers; i++){
        if(users[i].passPlain != NULL) continue; 
        
        firstname = strtok(users[i].fullname, " ");
        if(firstname == NULL) continue;

        *firstname = tolower((unsigned char) *firstname);

        password = crypt(firstname, users[i].salt);
        checkPassForUser(firstname, password, &users[i]);
        
        checkNumberPasswords(firstname, NULL, 0, &users[i]);
        checkEleetPasswords(firstname, NULL, 0, &users[i]);
        
        *firstname = toupper((unsigned char) *firstname);
        checkEleetPasswords(firstname, NULL, 0, &users[i]);
        checkNumberPasswords(firstname, NULL, 0, &users[i]);
        checkCapitalPasswords(firstname, NULL, 0, &users[i]);
        
        // check lastname
        lastname = strtok(NULL, " ");
        if(lastname == NULL) continue;

        *lastname = tolower((unsigned char) *lastname);

        password = crypt(lastname, users[i].salt);
        checkPassForUser(lastname, password, &users[i]);
        
        checkNumberPasswords(lastname, NULL, 0, &users[i]);
        checkEleetPasswords(lastname, NULL, 0, &users[i]);
        
        *lastname = toupper((unsigned char) *lastname);
        checkEleetPasswords(lastname, NULL, 0, &users[i]);
        checkNumberPasswords(lastname, NULL, 0, &users[i]);
        checkCapitalPasswords(lastname, NULL, 0, &users[i]);
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

            res = asprintf(&users[i].passEnc, "%s", password);
            res = asprintf(&users[i].salt, "$%s$%s$", algorithm, salt);
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
        int res;
        while(fgets(line, MAX_LINE_LENGTH, passwdfp) != NULL ){
            username = strtok(line, DELIMITER);

            strtok(NULL, DELIMITER); // skip passwd field
            strtok(NULL, DELIMITER); // skip userid field
            strtok(NULL, DELIMITER); // skip groupid field

            fullname = strtok(NULL, DELIMITER);

            strtok(NULL, DELIMITER); // skip home folder field
            if(strtok(NULL, DELIMITER) == NULL) // if shell is empty, the account had no user
                fullname = "";

            res = asprintf(&users[++i].username, "%s", username);

            char *name = NULL;
            if((name = strtok(fullname, ",")) != NULL)
                fullname = name;

            res = asprintf(&users[i].fullname, "%s", fullname);
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

        
        checkDictPasswords("./dicts/dictionary-top250.txt", users, NUM_USERS);
        checkSimplePasswords(users, NUM_USERS);
        checkNamePasswords(users, NUM_USERS);
        checkDictPasswords("./dicts/dictionary-bnc.txt", users, NUM_USERS);
        checkBirthdayPasswords(users, NUM_USERS);
        
        int pid = fork();
        if(pid == 0){
            // let child brute force numbers       
            checkBruteForceNumberPasswords(users, NUM_USERS);
        } else {
            // let parent brute force chars
            checkBruteForceCharPasswords(users, NUM_USERS);
        }
    }

    return 0;
}
