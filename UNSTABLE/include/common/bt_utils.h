#ifndef BT_UTILS_H
#define BT_UTILS_H

#include <stddef.h>

// Fonctions de chaînes partagées par CSON, AES et le CLI.
// Les paramètres const ne sont que lus.

size_t bt_strlen(const char* str);                                   // 0 si str est NULL
int bt_strcmp(const char* str1, const char* str2);                    // <0, 0 ou >0 comme strcmp
int bt_strchr(char* str,char c);
int bt_strchrxt(const char* str,char c,int x);
int bt_strcpybxy(char** dest, const char* src, size_t x, size_t y);   // copie src[x..y] dans *dest
int bt_strcpy(char** dest, const char* src);                          // copie src dans *dest (malloc/realloc)

int bt_isOneOfThemEqual(const char* str, size_t nbrOfElement, ...);  // 1 si str vaut l'une des chaînes suivantes
int bt_vaultAreadyCreated(const char* selectedName);
int parseVaultName(char** dest,const char* src);
int bt_getCShildDir(char** pathDest);
void bt_multiFree(size_t numberToFree,...);
void bt_deepFree(size_t numberToFree,void** p);

#endif
