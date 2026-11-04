#include <stdint.h> 
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
    #include <direct.h>
    #define MKDIR(p) _mkdir(p)
#else
    #include <sys/stat.h>
    #define MKDIR(p) mkdir(p, 0700)
#endif

#include "cson.h"
#include "bt_utils.h"
#include "bt_log.h"

// Ne jamais appeler LOG_ERROR depuis bt_strcpy / bt_strcat / bt_strlen : bt_logError les utilise (boucle infinie).
void bt_logError(const char* file,int line,const char* func,const char* reason){
    const char* base = NULL;
    #ifdef _WIN32
        base = getenv("APPDATA");
    #elif defined(__linux__)
        base = getenv("HOME");
    #endif
    if(base == NULL){
        return;
    }

    char* path = NULL;
    if(bt_strcpy(&path,base) || bt_strcat(&path,"/CShild/UNSTABLE/log/error.log")){
        free(path);
        return;
    }

    // Crée CShild/, UNSTABLE/ et log/ s'ils n'existent pas (l'erreur "existe déjà" est ignorée)
    for(size_t i = bt_strlen(base) + 1; path[i] != '\0'; i++){
        if(path[i] == '/'){
            path[i] = '\0';
            MKDIR(path);
            path[i] = '/';
        }
    }

    FILE* log_f = fopen(path, "a");
    free(path);
    if(log_f == NULL){
        return;
    }

    char time_str[32] = "?";
    time_t t = time(NULL);
    struct tm* now = localtime(&t);
    if(now != NULL){
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", now);
    }

    fprintf(log_f, "[%s] - Error : %s:%d %s() - %s\n", time_str, file, line, func, reason);
    fclose(log_f);
}    