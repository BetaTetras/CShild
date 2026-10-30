#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "cson.h"
#include "AES.h"
#include "bt_utils.h"

typedef enum {
    crt,
    dlt,
    mdf,
    shw,
    gen,
    oth
} methode;

int main(int argc, char *argv[]) {
    int state;
    if(argc == 1){
        // Faire le CLI custom
    }
    methode m;

    if(isOneOfThemEqual(argv[1],2,"creat","crt")){
        m = crt;
    }else if(isOneOfThemEqual(argv[1],2,"delete","dlt")){
        m = dlt;
    }else if(isOneOfThemEqual(argv[1],2,"modify","mdf")){
        m = mdf;
    }else if(isOneOfThemEqual(argv[1],2,"show","shw")){
        m = shw;
    }else if(isOneOfThemEqual(argv[1],2,"generate","gen")){
        m = gen;
    }else if(isOneOfThemEqual(argv[1],3,"--info","i","I") ||
             isOneOfThemEqual(argv[1],3,"--help","h","H") ||
             isOneOfThemEqual(argv[1],3,"--version","v","V")){
        m = oth;
    }else{
        // Erreur, methode non-connue
    }

    switch (m)
    {
    case crt:{
        if(argc < 3){
            // Not enough param
        }
        size_t len_vaultTarget = bt_strlen(argv[2]);
        state = bt_vaultAreadyCreated(argv[2]);
        if(state == -1){
            return 1;
        }

    break;
    }
    
    
    default:
        break;
    }

    return 0;
}


static int vaultAlreadyExist(char* vaultName){
    DIR *d = opendir("");
}