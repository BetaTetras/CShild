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

void bt_logAction(char methode,char* vault,int numberOfModif){
    int state;
    state = isActionLoggerActivated();
    if(state == -1){
        LOG_ERROR("Something append while fetching the statu of log_action in the conf");
        return;
    }else if(state == 0){
        // Logger == false -> On log rien
        return;
    }

    char* logActionPath = NULL;
    state = getActionLoggerPath(&logActionPath);
    if(state == 1){
        LOG_ERROR("Something append while fetching the path of the action logger");
        return;
    }
    FILE* log_f = fopen(logActionPath, "a");
    free(logActionPath);
    if(log_f == NULL){
        LOG_ERROR("Impossible to open the action log file (log_action_path in conf.json, does the folder exist ?)");
        return;
    }

    char time_str[32] = "?";
    time_t t = time(NULL);
    struct tm* now = localtime(&t);
    if(now != NULL){
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", now);
    }

    if(methode == '-'){
        if(numberOfModif > 1){
            fprintf(log_f,"[%c] - %s - '%s' - Remove %d entries\n",methode,time_str,vault,numberOfModif);
        }else{
            fprintf(log_f,"[%c] - %s - '%s' - Remove %d entry\n",methode,time_str,vault,numberOfModif);
        }
    }else if( methode == '+'){
        fprintf(log_f,"[%c] - %s - '%s' - Add new entry\n",methode,time_str,vault);
    }else if(methode == '*'){
        fprintf(log_f,"[%c] - %s - '%s' - Modify an entry\n",methode,time_str,vault);
    }else if(methode == '!'){
        fprintf(log_f,"[%c] - %s - '%s' - Password of vault changed\n",methode,time_str,vault);
    }else if(methode == '@'){
        fprintf(log_f,"[%c] - %s - '%s' - Wrong password\n",methode,time_str,vault);
    }else if(methode == 'v'){
        fprintf(log_f,"[+] - %s - '%s' - Vault created\n",time_str,vault);
    }else{
        fprintf(log_f,"[%c] - %s - '%s' - unknown action\n",'?',time_str,vault);
    }
    fclose(log_f);
}