#ifndef BT_UTILS_H
#define BT_UTILS_H

#include <stddef.h>
#include <stdint.h>

#include "../CSON/cson.h"

typedef struct {
    char* app;
    char* id;
    char* pwd;
    char* note;
    char** tags;
    size_t nbOfTags;
    char* newAppName;
    char* newIDName;
    int newPassword;
    int tagsMethode;
}CShildEntry;

// Fonctions de chaînes partagées par CSON, AES et le CLI.
// Les paramètres const ne sont que lus.

size_t bt_strlen(const char* str);                                   // 0 si str est NULL
int bt_strcmp(const char* str1, const char* str2);                    // <0, 0 ou >0 comme strcmp
int bt_strpbrk(const char* str,const char* list);                    // index du 1er caractère de str présent dans list, -1 sinon
int bt_strchr(char* str,char c);
int bt_strchrxt(const char* str,char c,int x);
int bt_strcpybxy(char** dest, const char* src, size_t x, size_t y);   // copie src[x..y] dans *dest
int bt_strcpy(char** dest, const char* src);                         // copie src dans *dest (malloc/realloc)
int bt_strcat(char** str1,const char* str2);

int isOneOfThemEqual(const char* str, size_t nbrOfElement, ...);  // 1 si str vaut l'une des chaînes suivantes
int vaultAreadyCreated(const char* selectedName);
int getConfPath(char** dest);
int getConf(JsonValue* destConf);
int parseVaultName(char** dest,const char* src);
int getCShildDir(char** pathDest);
double getVersionCShild(void);
int getVaultsPath(char** dest);
int getErrorLogPath(char** dest);
int getActionLoggerPath(char** dest);
int getVaultPathFromName(char** destPath,const char* vaultName);
// Crée <dossier des vaults>/<nomVault>.cshild contenant un vault vide (JSON en clair : à chiffrer ensuite avec AES_GCM_Encrypt_File).
// Ne remplace jamais un vault existant. Renvoie 0 si créé, 1 en cas d'erreur interne,
// 2 si le nom est invalide (vide, commence par '.', contient / \ : * ? " < > |), 3 si ce vault existe déjà.
int initNewBlankVault(char* nomVault);
int getValidation(void);
int isFileOpenable(char* path);
int isActionLoggerActivated(void);
int readVault(uint8_t** dest,size_t* size,const char* path);
int writeVault(const uint8_t* src,const size_t size,const char* path);
void bt_multiFree(size_t numberToFree,...);
void bt_multiFreeValue(size_t numberToFree,...);
void bt_deepFree(size_t numberToFree,void** p);
void nukeString(char* str,size_t size);
void uint8_tToZero(uint8_t* p_uint8_t,size_t size);   // définie dans AES.c (non déclarée dans AES.h upstream)

int bt_fgetss(char** dest);
int bt_pwdGen(char** dest,size_t length,int uppercase,int lowercase,int digits,int symbols);

#endif
