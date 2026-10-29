#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "cson.h"
#include "AES.h"
#include "bt_utils.h"

int main(int argc, char *argv[]) {
    if(argc == 1){
        // Faire le CLI custom
    }

    // Général
    if(argc == 2){
        if(isOneOfThemEqual(argv[1],3,"--info","-I","-i")){
            // Donner des information
        }else if(isOneOfThemEqual(argv[1],3,"--help","-H","-h")){
            // Donner de l'aide
        }else if(isOneOfThemEqual(argv[1],3,"--version","-V","-v")){
            // Donner la version
        }else if(bt_strcmp(argv[1],"vaults")){
            // Erreur
        }
    }

    //

    return 0;
}


static int isOneOfThemEqual(char* str,size_t nbrOfElement,...){
    va_list liste;
    va_start(liste, nbrOfElement);
    int res = 0;
    for(size_t i=0;i<nbrOfElement;i++){
        if(bt_strcmp(va_arg(liste, char*),str) == 0){
            res = 1;
            break;
        }
    }
    va_end(liste);
    return res; 
}