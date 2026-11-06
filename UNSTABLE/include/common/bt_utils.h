#ifndef BT_UTILS_H
#define BT_UTILS_H

#include <stddef.h>
#include <stdint.h>

#include "../CSON/cson.h"

typedef struct {
    const char* app;
    const char* id;
    const char* pwd;
    const char* note;
    const char** tags;
    size_t nbOfTags;
}CShildEntry;

// Fonctions de chaînes partagées par CSON, AES et le CLI.
// Les paramètres const ne sont que lus.

size_t bt_strlen(const char* str);                                   // 0 si str est NULL
int bt_strcmp(const char* str1, const char* str2);                    // <0, 0 ou >0 comme strcmp
int bt_strchr(char* str,char c);
int bt_strchrxt(const char* str,char c,int x);
int bt_strcpybxy(char** dest, const char* src, size_t x, size_t y);   // copie src[x..y] dans *dest
int bt_strcpy(char** dest, const char* src);                         // copie src dans *dest (malloc/realloc)
int bt_strcat(char** str1,const char* str2);

int isOneOfThemEqual(const char* str, size_t nbrOfElement, ...);  // 1 si str vaut l'une des chaînes suivantes
int vaultAreadyCreated(const char* selectedName);
int getConf(JsonValue* destConf);
int parseVaultName(char** dest,const char* src);
int getCShildDir(char** pathDest);
int getVersionCShild();
int getVaultPathFromName(char** destPath,const char* vaultName);
int readVault(uint8_t** dest,size_t* size,const char* path);
void bt_multiFree(size_t numberToFree,...);
void bt_multiFreeValue(size_t numberToFree,...);
void bt_deepFree(size_t numberToFree,void** p);
void nukeString(char* str,size_t size);

int bt_fgetss(char** dest);
int bt_pwdGen(char** dest,size_t length,int uppercase,int lowercase,int digits,int symbols);

#endif
