#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>
#include <stdarg.h>
#include <dirent.h>

#ifdef _WIN32
    #include <windows.h>
    #include <bcrypt.h>
#else
    #include <termios.h>
    #include <unistd.h>
    #include <sys/random.h>
#endif

#include "cson.h"
#include "AES.h"
#include "bt_utils.h"

size_t bt_strlen(const char* str){
    if(str == NULL){
        return 0;
    }
    size_t i =0;
    while(str[i] != '\0'){
        i++;
    }
    return i;
}


int bt_strcmp(const char* str1,const char* str2){
    if(str1 == NULL && str2 == NULL){
        return 0;
    }else if(str1 == NULL && str2 != NULL){
        return -1;
    }else if(str1 != NULL && str2 == NULL){
        return 1;
    }

    size_t size_1 = bt_strlen(str1);

    for(size_t i=0;i <= size_1;i++){
        unsigned char c1 = str1[i];
        unsigned char c2 = str2[i];
        if(c1 == c2){
            continue;
        }else if(c1 > c2){
            return 1;
        }else if(c1 < c2){
            return -1;
        }
    }
    return 0;
}

int bt_strchr(char* str,char c){
    size_t len_str = bt_strlen(str);
    for(size_t i=0;i<len_str;i++){
        if(str[i] == c){
            return i;
        }
    }
    return -1;
}

int bt_strchrxt(const char* str,char c,int x){
    size_t len_str = bt_strlen(str);
    int y = 0;
    for(size_t i=0;i<len_str;i++){
        if(str[i] == c){
            if(x == y){
                return i;
            }else{
                y++;
            }
        }
    }
    return -1;
}

// String copy between x and y
int bt_strcpybxy(char **dest, const char *src, size_t x, size_t y){
    if(src == NULL){
        return 1;
    }

    if (y < x) {
        return 1;
    }

    size_t size = y - x + 2;
    // realloc dans tmp : s'il échoue, *dest garde l'ancien bloc (sinon il fuit)
    char* tmp;
    if (*dest == NULL) {
        tmp = malloc(size);
    } else {
        tmp = realloc(*dest, size);
    }
    if (tmp == NULL) {
        return 1;
    }
    *dest = tmp;

    size_t index = 0;
    for (size_t i = x; i <= y; i++) {
        (*dest)[index] = src[i];
        index++;
    }

    (*dest)[index] = '\0';
    return 0;
}

int bt_strcpy(char** dest,const char* src){
    if(src == NULL){
        return 1;
    }
    size_t size = bt_strlen(src) + 1;

    // realloc dans tmp : s'il échoue, *dest garde l'ancien bloc (sinon il fuit)
    char* tmp;
    if (*dest == NULL) {
        tmp = malloc(size);
    } else {
        tmp = realloc(*dest, size);
    }
    if (tmp == NULL) {
        return 1;
    }
    *dest = tmp;

    for(size_t i = 0;i<size;i++){
        (*dest)[i] = src[i];
    }
    (*dest)[size-1] = '\0';
    return 0;
}

int bt_strcat(char** str1,const char* str2){
    if(str1 == NULL || str2 == NULL){
        return 1;
    }
    size_t len_str1 =  bt_strlen(*str1);
    size_t len_str2 = bt_strlen(str2);
    char* tmp = realloc(*str1,(len_str1 + len_str2 + 1) * sizeof(char));
    if(tmp == NULL){
        return 1;
    }
    *str1 = tmp;

    size_t index = 0;
    for(size_t i=len_str1;i<len_str1+len_str2;i++){
        (*str1)[i] = str2[index];
        index++;
    }

    (*str1)[len_str1+len_str2] = '\0';
    return 0;
}

int bt_isOneOfThemEqual(const char* str,size_t nbrOfElement,...){
    va_list liste;
    va_start(liste, nbrOfElement);
    int res = 0;
    for(size_t i=0;i<nbrOfElement;i++){
        if(bt_strcmp(va_arg(liste, const char*),str) == 0){
            res = 1;
            break;
        }
    }
    va_end(liste);
    return res; 
}

int bt_vaultAreadyCreated(const char* selectedName){
    int state;
    char* projectRoot = NULL;
    char* confPath = calloc(512, sizeof(char));
    if(confPath == NULL){
        return -1;
    }
    state = bt_getCShildDir(&projectRoot);
    if(state){
        free(confPath);
        return -1;
    }

    snprintf(confPath,512,"%s/.config/conf.json",projectRoot);
    free(projectRoot);

    JsonValue conf = initCsonFromFile(confPath);
    if(conf.type == JSON_ERROR){
        // Erreur log (Ouverture JSON)
        free(confPath);
        freeValue(conf);
        return -1;
    }
    size_t indexPath = getIndexFromObject(conf.value.object,"vaults_dir_path");
    if(indexPath == (size_t) -1){
        // pas de clé "vaults_dir_path" dans le conf.json
        free(confPath);
        freeValue(conf);
        return -1;
    }
    char* vaultsPath = calloc(512,sizeof(char));
    if(vaultsPath == NULL){
        // Erreur log (OOM)
        free(confPath);
        free(vaultsPath);
        freeValue(conf);
        return -1;
    }

    state = bt_strcpy(&vaultsPath,conf.value.object->listeOfPair[indexPath].value.value.string);
    if(state){
        // Erreur log (cpy str)
        free(confPath);
        free(vaultsPath);
        freeValue(conf);
        return -1;
    }

    DIR *d = opendir(vaultsPath);
    if(d == NULL){
        // Erreur log (Ouverture dir vaults)
        free(confPath);
        free(vaultsPath);
        freeValue(conf);
        return -1;
    }
    struct dirent *e;

    while ((e = readdir(d)) != NULL) {
        if(bt_strcmp(e->d_name,".") == 0 || bt_strcmp(e->d_name,"..") == 0){
            continue;
        }
        char *parsedName = NULL;
        state = parseVaultName(&parsedName,e->d_name);
        if(state){
            free(parsedName);
            continue;
        }
        if(bt_strcmp(selectedName,parsedName) == 0){
            free(parsedName);
            closedir(d);
            free(confPath);
            free(vaultsPath);
            freeValue(conf);
            return 1;
        }
        free(parsedName);
    }

    closedir(d);
    freeValue(conf);
    free(confPath);
    free(vaultsPath);
    
    return 0;
}

int parseVaultName(char** dest,const char* src){
    if(dest == NULL || src == NULL){
        return 1;
    }

    int state;
    int x = bt_strchrxt(src,'.',0);
    int y = bt_strchrxt(src,'.',1);

    if (x == -1 || y == -1 || y <= x + 1) {
        return 1;
    }

    state = bt_strcpybxy(dest,src,x+1,y-1);
    if(state){
        return 1;
    }

    return 0;
}

int bt_getCShildDir(char** pathDest){
    if(pathDest == NULL){
        return 1;
    }

    const char* base = NULL;
    #ifdef _WIN32
        base = getenv("APPDATA");
    #elif defined(__linux__)
        base = getenv("HOME");
    #endif
    if(base == NULL){
        // Erreur log (erreur env ou OS non reconnu)
        return 1;
    }

    size_t size = bt_strlen(base) + bt_strlen("/CShild") + 1;
    char* tmp = calloc(size,sizeof(char));
    if(tmp == NULL){
        // Erreur log (OOM)
        return 1;
    }

    snprintf(tmp,size,"%s/CShild",base);

    free(*pathDest);
    *pathDest = tmp;
    return 0;
}

void bt_multiFree(size_t numberToFree,...){
    va_list liste;
    va_start(liste, numberToFree);
    for(size_t i=0;i<numberToFree;i++){
        free(va_arg(liste,void*));
    }
    va_end(liste);
}

void bt_deepFree(size_t numberToFree,void** p){
    if(p == NULL){
        return;
    }
    for(size_t i=0;i<numberToFree;i++){
        free(p[i]);
    }
    free(p);
}

void nukeString(char* str,size_t size){
    volatile char* p = str;
    for(size_t i=0;i<size;i++){
        p[i] = 0x00;
    }
}

#ifdef _WIN32
    int bt_fgetss(char** dest){
        fflush(stdout);
        if(dest == NULL){
            return 1;
        }
        *dest = NULL;
        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        DWORD ancienMode;

        if (!GetConsoleMode(hIn, &ancienMode)) {
            printf("Pas une vraie console (entree redirigee, Git Bash ?)\n");
            return 1;
        }

        // On désactive les flag q'on veut pas
        DWORD nouveauMode = ancienMode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
        SetConsoleMode(hIn, nouveauMode);

        size_t len_mdp = 0;
        size_t size = 0;
        char* tmp = calloc(len_mdp+1,sizeof(char));
        if(tmp == NULL){
            SetConsoleMode(hIn, ancienMode);
            return 1;
        }
        *dest = tmp;
        char c;
        
        unsigned char uc;
        DWORD lus;
        while(1){
            if (!ReadFile(hIn, &c, 1, &lus, NULL) || lus == 0) {
                SetConsoleMode(hIn, ancienMode);
                nukeString(*dest, size + 1);
                free(*dest);
                *dest = NULL;
                
                return 1;
            }
            uc = c;

            if (uc == '\r') { // Entrée
                break;                      
            } else if (uc == 8) { // Backspace
                if(len_mdp > 0){
                    fputs("\b \b", stdout);
                    fflush(stdout);
                    len_mdp --;
                }
            } else if (uc == 3){ // ctrl + c
                SetConsoleMode(hIn, ancienMode);
                nukeString(*dest, size + 1);
                free(*dest);
                *dest = NULL;
                return 1;
            } else if (32 <= uc && uc <= 126) {
                len_mdp ++;
                size ++ ;
                tmp = realloc(*dest,size+1);
                if(tmp == NULL){
                    SetConsoleMode(hIn, ancienMode);
                    nukeString(*dest, size);
                    free(*dest);
                    *dest = NULL;
                    return 1;
                }
                *dest = tmp;
                (*dest)[len_mdp-1] = uc;
                putchar('*');
                fflush(stdout);
            }
        }
        SetConsoleMode(hIn, ancienMode);
        putchar('\n');
        if(len_mdp == 0){
            nukeString(*dest, size + 1);
            free(*dest);
            *dest = NULL;
            return 2;
        }
        nukeString(*dest + len_mdp + 1, size - len_mdp);
        (*dest)[len_mdp] = '\0';

        return 0;
    }

    int bt_pwdGen(char** dest,size_t length,int uppercase,int lowercase,int digits,int symbols){
        if(dest == NULL){
            return 1;
        }
        if(uppercase == 0 && lowercase == 0 && digits == 0 && symbols == 0){
            return 1;
        }

        char* tmp = realloc(*dest,(length+1) * sizeof(char));
        if(tmp == NULL){
            return 1;
        }
        *dest = tmp;

        size_t len_alphabet = 0;
        char* alphabet = NULL;

        int state = 0;
        if(uppercase){
            state = bt_strcat(&alphabet,"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
            if(state){
                free(alphabet);
                return 1;
            }
            len_alphabet += 26;
        }
        if(lowercase){
            state = bt_strcat(&alphabet,"abcdefghijklmnopqrstuvwxyz");
            if(state){
                free(alphabet);
                return 1;
            }
            len_alphabet += 26;
        }
        if(digits){
            state = bt_strcat(&alphabet,"0123456789");
            if(state){
                free(alphabet);
                return 1;
            }
            len_alphabet += 10;
        }
        if(symbols){
            state = bt_strcat(&alphabet,"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~");
            if(state){
                free(alphabet);
                return 1;
            }
            len_alphabet += 32;
        }

        int limite = 256 - (256 % len_alphabet);
        size_t index = 0;
        while(index < length){
            unsigned char oct;
            NTSTATUS st = BCryptGenRandom(NULL, &oct, 1, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if(st != 0){
                // Erreur log (random)
                free(alphabet);
                return 1;
            }
            if(oct >= limite){
                continue;
            }
            (*dest)[index] = alphabet[oct % len_alphabet];
            index ++;
        }
        (*dest)[length] = '\0';

        free(alphabet);
        return 0;
    }
#else
    int bt_fgetss(char** dest){
        fflush(stdout);
        if(dest == NULL){
            return 1;
        }
        *dest = NULL;
        struct termios ancien, nouveau;
        if (tcgetattr(STDIN_FILENO, &ancien) != 0) {
            return 1;
        }

        nouveau = ancien;
        nouveau.c_lflag &= ~(ICANON | ECHO | ISIG);
        nouveau.c_cc[VMIN] = 1;
        nouveau.c_cc[VTIME] = 0;

        tcsetattr(STDIN_FILENO, TCSAFLUSH, &nouveau);

        size_t len_mdp = 0;
        size_t size = 0;
        char* tmp = calloc(len_mdp+1,sizeof(char));
        if(tmp == NULL){
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &ancien);
            return 1;
        }
        *dest = tmp;
        char c;
        unsigned char uc;

        while(1){
            if (read(STDIN_FILENO, &c, 1) != 1){
                tcsetattr(STDIN_FILENO, TCSAFLUSH, &ancien);
                nukeString(*dest, size + 1);
                free(*dest);
                *dest = NULL;
                
                return 1;
            }
            uc = c;

            if (uc == '\r' || uc == '\n') { // Entrée
                break;                      
            } else if (uc == 8 || uc == 127) { // Backspace
                if(len_mdp > 0){
                    fputs("\b \b", stdout);
                    fflush(stdout);
                    len_mdp --;
                }
            } else if (uc == 3){ // ctrl + c
                tcsetattr(STDIN_FILENO, TCSAFLUSH, &ancien);
                nukeString(*dest, size + 1);
                free(*dest);
                *dest = NULL;
                return 1;
            } else if (32 <= uc && uc <= 126) {
                len_mdp ++;
                size ++ ;
                tmp = realloc(*dest,size+1);
                if(tmp == NULL){
                    tcsetattr(STDIN_FILENO, TCSAFLUSH, &ancien);
                    nukeString(*dest, size);
                    free(*dest);
                    *dest = NULL;
                    return 1;
                }
                *dest = tmp;
                (*dest)[len_mdp-1] = uc;
                putchar('*');
                fflush(stdout);
            }
        }

        tcsetattr(STDIN_FILENO, TCSAFLUSH, &ancien);
        putchar('\n');
        if(len_mdp == 0){
            nukeString(*dest, size + 1);
            free(*dest);
            *dest = NULL;
            return 2;
        }
        nukeString(*dest + len_mdp + 1, size - len_mdp);
        (*dest)[len_mdp] = '\0';

        return 0;
    }

    int bt_pwdGen(char** dest,size_t length,int uppercase,int lowercase,int digits,int symbols){
        if(dest == NULL){
            return 1;
        }
        if(uppercase == 0 && lowercase == 0 && digits == 0 && symbols == 0){
            return 1;
        }

        char* tmp = realloc(*dest,(length+1) * sizeof(char));
        if(tmp == NULL){
            return 1;
        }
        *dest = tmp;

        size_t len_alphabet = 0;
        char* alphabet = NULL;

        int state = 0;
        if(uppercase){
            state = bt_strcat(&alphabet,"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
            if(state){
                free(alphabet);
                return 1;
            }
            len_alphabet += 26;
        }
        if(lowercase){
            state = bt_strcat(&alphabet,"abcdefghijklmnopqrstuvwxyz");
            if(state){
                free(alphabet);
                return 1;
            }
            len_alphabet += 26;
        }
        if(digits){
            state = bt_strcat(&alphabet,"0123456789");
            if(state){
                free(alphabet);
                return 1;
            }
            len_alphabet += 10;
        }
        if(symbols){
            state = bt_strcat(&alphabet,"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~");
            if(state){
                free(alphabet);
                return 1;
            }
            len_alphabet += 32;
        }

        int limite = 256 - (256 % len_alphabet);
        size_t index = 0;
        while(index < length){
            unsigned char oct;
            if(getrandom(&oct, 1, 0) != 1){
                // Erreur log (random)
                free(alphabet);
                return 1;
            }
            if(oct >= limite){
                continue;
            }
            (*dest)[index] = alphabet[oct % len_alphabet];
            index ++;
        }
        (*dest)[length] = '\0';

        free(alphabet);
        return 0;
    }
#endif
