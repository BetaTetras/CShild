#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>
#include <stdarg.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>

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
#include "bt_log.h"

// 64 MO =  67 108 864 O
#define VAULT_MAX_SIZE (64L * 1024 * 1024)

// len = lenght
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

// cmp = compare
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

int bt_strpbrk(const char* str,const char* list){
    size_t len_str = bt_strlen(str);
    size_t len_list = bt_strlen(list);
    for(size_t i = 0;i<len_str;i++){
        for(size_t j=0;j<len_list;j++){
            if(str[i] == list[j]){
                return i;
            }
        }
    }
    return -1;
}

// chr = cherche
int bt_strchr(char* str,char c){
    size_t len_str = bt_strlen(str);
    for(size_t i=0;i<len_str;i++){
        if(str[i] == c){
            return i;
        }
    }
    return -1;
}

// chrxt = cherche x time
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

// cpybxy = copy between x and y
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

// cpy = copy
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

// cat = concaténation
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

// rc = replace char
int bt_strrc(char* str,char target,char replacementChar){
    if(str == NULL){
        return 1;
    }
    size_t str_len = bt_strlen(str);

    for(size_t i=0;i<str_len;i++){
        if(str[i] == target){
            str[i] = replacementChar;
        }
    }
    return 0;
}

int isOneOfThemEqual(const char* str,size_t nbrOfElement,...){
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

int getConfPath(char** dest){
    if(dest == NULL){
        LOG_ERROR("Corrupted pointer (dest == NULL)");
        return 1;
    }

    int state;
    char* projectRoot = NULL;
    char* confPath = calloc(512, sizeof(char));
    if(confPath == NULL){
        LOG_ERROR("Error while allocating memory (confPath calloc)");
        return 1;
    }
    state = getCShildDir(&projectRoot);
    if(state){
        free(confPath);
        LOG_ERROR("Impossible to fetch the CShild directory (getCShildDir)");
        return 1;
    }

    snprintf(confPath,512,"%s/.config/conf.json",projectRoot);
    free(projectRoot);
    *dest = confPath;
    return 0;
}

int getErrorLogPath(char** dest){
    if(dest == NULL){
        LOG_ERROR("Corrupted pointer (dest == NULL)");
        return 1;
    }

    int state;
    char* projectRoot = NULL;
    char* confPath = calloc(512, sizeof(char));
    if(confPath == NULL){
        LOG_ERROR("Error while allocating memory (confPath calloc)");
        return 1;
    }
    state = getCShildDir(&projectRoot);
    if(state){
        free(confPath);
        LOG_ERROR("Impossible to fetch the CShild directory (getCShildDir)");
        return 1;
    }

    snprintf(confPath,512,"%s/UNSTABLE/log/error.log",projectRoot);
    free(projectRoot);
    *dest = confPath;
    return 0;
}

int getConf(JsonValue* destConf){
    int state;
    char* confPath = NULL;

    state = getConfPath(&confPath);
    if(state == 1){
        return 1;
    }

    *destConf = initCsonFromFile(confPath);
    free(confPath);
    if(destConf->type == JSON_ERROR){
        LOG_ERROR("Impossible to read conf.json (initCsonFromFile)");
        return 1;
    }

    return 0;
}

int isFileOpenable(char* path){
    if(path == NULL){
        return 0;
    }

    FILE* f = fopen(path,"r");
    if(f == NULL){
        return 0;
    }
    fclose(f);
    return 1;
}

int vaultAreadyCreated(const char* selectedName){
    int state = 0;
    JsonValue conf;
    state = getConf(&conf);
    if(state == 1){
        LOG_ERROR("Impossible to fetch the conf (getConf)");
        return -1;
    }
    if(conf.type != JSON_OBJECT){
        // Conf non valide
        freeValue(conf);
        LOG_ERROR("conf.json invalid (root is not an object)");
        return -1;
    }

    size_t indexPath = getIndexFromObjectWithKey(conf.value.object,"vaults_dir_path");
    if(indexPath == (size_t) -1){
        // pas de clé "vaults_dir_path" dans le conf.json
        freeValue(conf);
        LOG_ERROR("conf.json altered or corrupted, key 'vaults_dir_path' not found");
        return -1;
    }
    char* vaultsPath = calloc(512,sizeof(char));
    if(vaultsPath == NULL){
        free(vaultsPath);
        freeValue(conf);
        LOG_ERROR("Error while allocating memory (vaultsPath calloc)");
        return -1;
    }

    state = bt_strcpy(&vaultsPath,conf.value.object->listeOfPair[indexPath].value.value.string);
    if(state){
        free(vaultsPath);
        freeValue(conf);
        LOG_ERROR("copy of an string failed (bt_strcpy)");
        return -1;
    }

    DIR *d = opendir(vaultsPath);
    if(d == NULL){
        free(vaultsPath);
        freeValue(conf);
        LOG_ERROR("Impossible to open the vaults directory (opendir)");
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
            free(vaultsPath);
            freeValue(conf);
            return 1;
        }
        free(parsedName);
    }

    closedir(d);
    freeValue(conf);
    free(vaultsPath);
    
    return 0;
}

int parseVaultName(char** dest, const char* src){
    if(dest == NULL || src == NULL){
        return 1;
    }

    size_t len = bt_strlen(src);
    int dot = -1;
    for(size_t i = 0; i < len; i++){
        if(src[i] == '.'){
            dot = (int)i;
        }
    }

    if(dot <= 0){
        return 1;
    }
    if(bt_strcmp(src + dot, ".cshild") != 0){
        return 1;
    }
    int state = 0;
    state = bt_strcpybxy(dest, src, 0, dot - 1);
    if(state){
        return 1;
    }

    return 0;
}

int getCShildDir(char** pathDest){
    if(pathDest == NULL){
        LOG_ERROR("Corrupted pointer (pathDest == NULL)");
        return 1;
    }

    const char* base = NULL;
    #ifdef _WIN32
        base = getenv("APPDATA");
    #elif defined(__linux__)
        base = getenv("HOME");
    #endif
    if(base == NULL){
        LOG_ERROR("Environment variable not found or OS not recognized (APPDATA / HOME)");
        return 1;
    }

    size_t size = bt_strlen(base) + bt_strlen("/CShild") + 1;
    char* tmp = calloc(size,sizeof(char));
    if(tmp == NULL){
        LOG_ERROR("Error while allocating memory (tmp calloc)");
        return 1;
    }

    snprintf(tmp,size,"%s/CShild",base);

    free(*pathDest);
    *pathDest = tmp;
    if(bt_strrc(*pathDest,'\\','/')){
        LOG_ERROR("Error while standardizing path (bt_strrc(*pathDest,'\\','/'))");
        return 1;
    }
    return 0;
}

double getVersionCShild(){
    JsonValue conf;
    if(getConf(&conf)){
        return -1;
    }

    size_t versionIndex = getIndexFromObjectWithKey(conf.value.object,"version");
    if(versionIndex == (size_t)-1){
        LOG_ERROR("conf.json altered or corrupted, key 'version' not found");
        freeValue(conf);
        return -1;
    }
    double version = conf.value.object->listeOfPair[versionIndex].value.value.decimal;
    freeValue(conf);
    return version;
}

int getVaultPathFromName(char** destPath,const char* vaultName){
    if(destPath == NULL || vaultName == NULL){
        LOG_ERROR("One of the pointer was null (destPath == NULL or vaultName == NULL)");
        return 1;
    }

    char* vaultsPath = NULL;
    if(getVaultsPath(&vaultsPath)){
        LOG_ERROR("Error while getting the vaults path");
        return 1;
    }
    size_t vaultsPath_size = bt_strlen(vaultsPath);
    size_t final_size = vaultsPath_size + bt_strlen(vaultName) + 9;
    char* ThaoLin = realloc(vaultsPath,final_size);
    if(ThaoLin == NULL){
        free(vaultsPath);
        LOG_ERROR("Error while allocating memory");
        return 1;
    }
    vaultsPath = ThaoLin;

    int state = snprintf(vaultsPath + vaultsPath_size,final_size - vaultsPath_size,"/%s.cshild",vaultName);
    if(state < 0 || (size_t) state >= final_size - vaultsPath_size){
        free(vaultsPath);
        LOG_ERROR("Path troncate    ");
        return 1;
    }

    free(*destPath); 
    *destPath = vaultsPath; 
    return 0;
}

int readVault(uint8_t** dest,size_t* size,const char* path){
    if(dest == NULL || size == NULL || path == NULL){
        LOG_ERROR("One of the parameter is null");
        return 1;
    }
    FILE* f = fopen(path,"rb");
    if(f == NULL){
        LOG_ERROR(strerror(errno));
        return 1;
    }

    if(fseek(f,0,SEEK_END) != 0){
        LOG_ERROR("Error fseek");
        fclose(f);
        return 1;
    }
    long len = ftell(f);
    if(len > VAULT_MAX_SIZE){
        LOG_ERROR("Vault too big or wrong path (ftell > 64MO)");
        fclose(f);
        return 2;
    }
    if(len <= 0){
        LOG_ERROR("Error from ftell");
        fclose(f);
        return 1;
    }
    rewind(f);
    
    uint8_t* buffer = calloc((size_t)len,sizeof(uint8_t));
    if(buffer == NULL){
        LOG_ERROR("Error while allocating memory");
        fclose(f);
        return 1;
    }
    if(fread(buffer,1,(size_t)len,f) != (size_t)len){
        LOG_ERROR("Read the wrong amount of octet");
        free(buffer);
        fclose(f);
        return 1;
    }
    fclose(f);
    *dest = buffer;
    *size = (size_t)len;
    return 0;
}

int writeVault(const uint8_t* src,const size_t size,const char* path){
    if(src == NULL || size == 0 || path == NULL){
        LOG_ERROR("One of the pointer was null or size was zero (src == NULL or size == 0 or path == NULL)");
        return 1;
    }
    char* pathTmp = NULL;
    if(bt_strcpy(&pathTmp,path)){
        LOG_ERROR("Error while copying a string (bt_strcpy(&pathTmp,path))");
        free(pathTmp);
        return 1;
    }
    if(bt_strcat(&pathTmp,".tmp")){
        LOG_ERROR("Error while copying a string (bt_strcat(&pathTmp,\".tmp\"))");
        free(pathTmp);
        return 1;
    }
    FILE* f = fopen(pathTmp,"wb");
    if(f == NULL){
        LOG_ERROR(strerror(errno));
        free(pathTmp);
        return 1;
    }

    if(fwrite(src,size,1,f) != 1){
        LOG_ERROR(strerror(errno));
        fclose(f);
        remove(pathTmp);
        free(pathTmp);
        return 1;
    }
    
    if(fclose(f) != 0){
        LOG_ERROR(strerror(errno));
        remove(pathTmp);
        free(pathTmp);
        return 1;
    }

    #ifdef _WIN32
        if(!MoveFileExA(pathTmp, path, MOVEFILE_REPLACE_EXISTING)){
            char error[64];
            sprintf(error,"MoveFileExA failed (code = %lu)",(long unsigned)GetLastError());
            LOG_ERROR(error);
            remove(pathTmp);
            free(pathTmp);
            return 1;
        }
    #else
        if(rename(pathTmp,path)){
            LOG_ERROR(strerror(errno));
            remove(pathTmp);
            free(pathTmp);
            return 1;
        }
    #endif

    free(pathTmp);
    return 0;
}

int getVaultsPath(char** dest){
    if(dest == NULL){
        LOG_ERROR("Corrupted pointer (dest == NULL)");
        return 1;
    }
    JsonValue conf;
    if(getConf(&conf)){
        LOG_ERROR("Impossible to get conf.json");
        return 1;
    }
    if(conf.type != JSON_OBJECT){
        LOG_ERROR("conf.json altered (conf.json is not a object)");
        freeValue(conf);
        return 1;
    }
    
    size_t indexPath = getIndexFromObjectWithKey(conf.value.object,"vaults_dir_path");
    if(indexPath == (size_t)-1){
        LOG_ERROR("conf.json altered (no \"vaults_dir_path\" key)");
        freeValue(conf);
        return 1;
    }
    if(conf.value.object->listeOfPair[indexPath].value.type != JSON_STRING){
        LOG_ERROR("conf.json altered (\"vaults_dir_path\" is not a string)");
        freeValue(conf);
        return 1;
    }
    char* path = NULL;
    if(bt_strcpy(&path,conf.value.object->listeOfPair[indexPath].value.value.string)){
        LOG_ERROR("Error while copying a string (bt_strcpy)");
        free(path);
        freeValue(conf);
        return 1;
    }
    *dest = path;
    freeValue(conf);
    return 0;
}

int getValidation(void){
    int rep = getchar();
    int c = rep;
    while (c != '\n' && c != EOF){
        c = getchar();
    }

    if (rep == 'Y' || rep == 'y'){
        return 1;
    }
    if (rep == 'N' || rep == 'n'){
        return 0;
    }

    return 2;
}

void bt_multiFree(size_t numberToFree,...){
    va_list liste;
    va_start(liste, numberToFree);
    for(size_t i=0;i<numberToFree;i++){
        free(va_arg(liste,void*));
    }
    va_end(liste);
}

void bt_multiFreeValue(size_t numberToFree,...){
    va_list liste;
    va_start(liste, numberToFree);
    for(size_t i=0;i<numberToFree;i++){
        freeValue(*va_arg(liste,JsonValue*));
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

int initNewBlankVault(char* nomVault){
    if(nomVault == NULL){
        LOG_ERROR("Corrupted pointer (nomVault == NULL)");
        return 1;
    }
    // Nom invalide : vide, commence par '.', ou contient un caractère de chemin / interdit sous Windows
    if(nomVault[0] == '\0' || nomVault[0] == '.' || bt_strpbrk(nomVault,"/\\:*?\"<>|") != -1){
        return 2;
    }
    if(vaultAreadyCreated(nomVault) == 1){
        return 3;
    }
    int state;
    double version_d = getVersionCShild();
    if(version_d == -1){
        LOG_ERROR("Impossible to fetch the version of CShild (getVersionCShild)");
        return 1;
    }
    JsonValue newVault = initJsonValue(JSON_OBJECT);
    state = newJsonObject(&newVault);
    if(state == 1){
        LOG_ERROR("Something append while creating a new Json object (newJsonObject(&newVault))");
        return 1;
    }
    JsonValue version_v = initJsonValue(JSON_DECIMAL);
    version_v.value.decimal = version_d;
    JsonValue apps_obj = initJsonValue(JSON_OBJECT);
    state = newJsonObject(&apps_obj);
    if(state == 1){
        LOG_ERROR("Something append while creating a new Json object (newJsonObject(&apps_obj))");
        freeValue(newVault);
        return 1;
    }

    state = addToObject(newVault.value.object,"version",version_v,0);
    if(state == 1){
        LOG_ERROR("Adding a new value in an object failed (addToObject)");
        freeValue(apps_obj);
        freeValue(newVault);
        return 1;
    }
    state = addToObject(newVault.value.object,"apps",apps_obj,1);
    freeValue(apps_obj);    // addToObject en a fait une copie : l'original est à libérer
    if(state == 1){
        LOG_ERROR("Adding a new value in an object failed (addToObject)");
        freeValue(newVault);
        return 1;
    }

    char* fullPath = NULL;
    state = getVaultPathFromName(&fullPath,nomVault);
    if(state == 1){
        LOG_ERROR("Error while getting the vault path (getVaultPathFromName)");
        freeValue(newVault);
        return 1;
    }

    // "wx" : échoue si le fichier existe déjà (même s'il a été créé entre-temps), il n'est donc jamais écrasé
    FILE* json = fopen(fullPath,"wx");
    if(json == NULL){
        int alreadyExists = (errno == EEXIST);
        if(!alreadyExists){
            LOG_ERROR(strerror(errno));
        }
        free(fullPath);
        freeValue(newVault);
        if(alreadyExists){
            return 3;
        }
        return 1;
    }

    state = fprintfValue(json,newVault);
    freeValue(newVault);
    if(state == 1){
        LOG_ERROR("Error while writting the json file");
        fclose(json);
        remove(fullPath);       // On l'a créé nous-même juste avant : on peut le supprimer
        free(fullPath);
        return 1;
    }
    if(fclose(json) != 0){
        LOG_ERROR("Error while closing the json file");
        remove(fullPath);
        free(fullPath);
        return 1;
    }
    free(fullPath);
    return 0;
}

#ifdef _WIN32
    int bt_fgetss(char** dest){
        fflush(stdout);
        if(dest == NULL){
            LOG_ERROR("The destination was null (dest == NULL)");
            return 1;
        }
        *dest = NULL;
        HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
        DWORD ancienMode;

        if (!GetConsoleMode(hIn, &ancienMode)) {
            LOG_ERROR("Not a real terminal (redirected input, Git Bash ?)");
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
            LOG_ERROR("Error while allocating memory (tmp = calloc(len_mdp+1,sizeof(char)))");
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
                LOG_ERROR("Error while reading inputs");
                
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
                LOG_ERROR("Input canceled by the user (Ctrl+C)");
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
                    LOG_ERROR("Error while allocating memory (tmp = realloc(*dest,size+1))");
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
            LOG_ERROR("The destination was null (dest == NULL)");
            return 1;
        }
        if(uppercase == 0 && lowercase == 0 && digits == 0 && symbols == 0){
            return 1;
        }

        char* tmp = realloc(*dest,(length+1) * sizeof(char));
        if(tmp == NULL){
            LOG_ERROR("Error while allocating memory (tmp = realloc(*dest,(length+1) * sizeof(char)))");
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
                LOG_ERROR("Error while building the alphabet (bt_strcat)");
                return 1;
            }
            len_alphabet += 26;
        }
        if(lowercase){
            state = bt_strcat(&alphabet,"abcdefghijklmnopqrstuvwxyz");
            if(state){
                free(alphabet);
                LOG_ERROR("Error while building the alphabet (bt_strcat)");
                return 1;
            }
            len_alphabet += 26;
        }
        if(digits){
            state = bt_strcat(&alphabet,"0123456789");
            if(state){
                free(alphabet);
                LOG_ERROR("Error while building the alphabet (bt_strcat)");
                return 1;
            }
            len_alphabet += 10;
        }
        if(symbols){
            state = bt_strcat(&alphabet,"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~");
            if(state){
                free(alphabet);
                LOG_ERROR("Error while building the alphabet (bt_strcat)");
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
                free(alphabet);
                LOG_ERROR("Random generation failed (BCryptGenRandom)");
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
            LOG_ERROR("The destination was null (dest == NULL)");
            return 1;
        }
        *dest = NULL;
        struct termios ancien, nouveau;
        if (tcgetattr(STDIN_FILENO, &ancien) != 0) {
            LOG_ERROR("Not a real terminal (redirected input)");
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
            LOG_ERROR("Error while allocating memory (tmp = calloc(len_mdp+1,sizeof(char)))");
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
                LOG_ERROR("Error while reading inputs");
                
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
                LOG_ERROR("Input canceled by the user (Ctrl+C)");
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
                    LOG_ERROR("Error while allocating memory (tmp = realloc(*dest,size+1))");
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
            LOG_ERROR("The destination was null (dest == NULL)");
            return 1;
        }
        if(uppercase == 0 && lowercase == 0 && digits == 0 && symbols == 0){
            return 1;
        }

        char* tmp = realloc(*dest,(length+1) * sizeof(char));
        if(tmp == NULL){
            LOG_ERROR("Error while allocating memory (tmp = realloc(*dest,(length+1) * sizeof(char)))");
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
                LOG_ERROR("Error while building the alphabet (bt_strcat)");
                return 1;
            }
            len_alphabet += 26;
        }
        if(lowercase){
            state = bt_strcat(&alphabet,"abcdefghijklmnopqrstuvwxyz");
            if(state){
                free(alphabet);
                LOG_ERROR("Error while building the alphabet (bt_strcat)");
                return 1;
            }
            len_alphabet += 26;
        }
        if(digits){
            state = bt_strcat(&alphabet,"0123456789");
            if(state){
                free(alphabet);
                LOG_ERROR("Error while building the alphabet (bt_strcat)");
                return 1;
            }
            len_alphabet += 10;
        }
        if(symbols){
            state = bt_strcat(&alphabet,"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~");
            if(state){
                free(alphabet);
                LOG_ERROR("Error while building the alphabet (bt_strcat)");
                return 1;
            }
            len_alphabet += 32;
        }

        int limite = 256 - (256 % len_alphabet);
        size_t index = 0;
        while(index < length){
            unsigned char oct;
            if(getrandom(&oct, 1, 0) != 1){
                free(alphabet);
                LOG_ERROR("Random generation failed (getrandom)");
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
