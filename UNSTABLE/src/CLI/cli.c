#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>

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
        return 0;
    }
    methode m;

    if(isOneOfThemEqual(argv[1],2,"create","crt")){
        m = crt;
    }else if(isOneOfThemEqual(argv[1],2,"delete","dlt")){
        m = dlt;
    }else if(isOneOfThemEqual(argv[1],2,"modify","mdf")){
        m = mdf;
    }else if(isOneOfThemEqual(argv[1],2,"show","shw")){
        m = shw;
    }else if(isOneOfThemEqual(argv[1],2,"generate","gen")){
        m = gen;
    }else if(isOneOfThemEqual(argv[1],3,"--info","-i","-I") ||
             isOneOfThemEqual(argv[1],3,"--help","-h","-H") ||
             isOneOfThemEqual(argv[1],3,"--version","-v","-V")){
        m = oth;
    }else{
        // Erreur, methode non-connue
        return 1;
    }

    switch (m)
    {
    case crt:{
        if(argc < 3){
            // Not enough param
            return 1;
        }
        state = vaultAreadyCreated(argv[2]);
        if(state != 1){
            return 1;
        }

        int paramAPP = 0;
        char* app = NULL;
        int paramID = 0;
        char* id = NULL;
        int paramNOTE = 0;
        char* note = NULL;
        int paramTAGS = 0;
        size_t numOfTags = 0;
        char** tags = NULL;

        CShildEntry e = {0};

        for(size_t i=3;i<argc;i++){
            if(isOneOfThemEqual(argv[i],2,"--app","-a")){
                if(i+1 >= argc){
                    // Il manque l'app dans la commande
                    bt_multiFree(3,app,id,note);
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                if(paramAPP == 1){
                    // Param deja entrée
                    bt_multiFree(3,app,id,note);
                    bt_deepFree(numOfTags, (void**)tags); 
                    return 1;
                }
                paramAPP = 1;
                e.app,argv[i+1];

                if(state == 1){
                    // Erreur de copie
                    bt_multiFree(3,app,id,note);
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                i++;
            }else if(isOneOfThemEqual(argv[i],2,"--id","-i")){
                if(i+1 >= argc){
                    // Il manque l'app dans la commande
                    bt_multiFree(3,app,id,note);
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                if(paramID == 1){
                    // Param deja entrée
                    bt_multiFree(3,app,id,note);
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                paramID = 1;
                e.id = argv[i+1];
                if(state == 1){
                    // Erreur de copie
                    bt_multiFree(3,app,id,note);
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                i++;
            }else if(isOneOfThemEqual(argv[i],2,"--note","-n")){
                if(i+1 >= argc){
                    // Il manque l'app dans la commande
                    bt_multiFree(3,app,id,note);
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                if(paramNOTE == 1){
                    // Param deja entrée
                    bt_multiFree(3,app,id,note);
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                paramNOTE = 1;
                state = bt_strcpy(&note,argv[i+1]);
                e.note = argv[i+1];
                if(state == 1){
                    // Erreur de copie
                    bt_multiFree(3,app,id,note);
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                i++;
            }else if(isOneOfThemEqual(argv[i],2,"--tags","-t")){
                if(paramTAGS == 1){
                    bt_multiFree(3,app,id,note);
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                paramTAGS = 1;
                // Calcule du nombre de tag
                for(size_t j=i+1;j<argc;j++){
                    if((argv[j])[0] == '-'){
                        break;
                    }
                    numOfTags ++;
                }
                if(numOfTags == 0){
                    bt_multiFree(3,app,id,note);
                    // Pas de tags
                    return 1;
                }
                char** tmp = realloc(tags,numOfTags * sizeof(char*));
                if(tmp == NULL){
                    bt_multiFree(3,app,id,note);
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                tags = tmp;
                for(size_t j=0;j<numOfTags;j++){
                    tags[j] = NULL;
                }
                // Allocation de tout les tags
                for(size_t j=0;j<numOfTags;j++){
                    state = bt_strcpy(&tags[j], argv[i+1+j]);
                    if(state == 1){
                        bt_multiFree(3,app,id,note);
                        bt_deepFree(numOfTags, (void**)tags);
                        return 1;
                    }
                }
                i += numOfTags;
                e.nbOfTags = numOfTags;
                e.tags = tags;
            }else{
                // Commande de crt non reconnue
                bt_multiFree(3,app,id,note);
                bt_deepFree(numOfTags, (void**)tags);
                return 1;
            }
        }
        int state = 0;
        char* vaultPWD = NULL;
        char* newPWD = NULL;
        char* vaultPath = NULL;

        // Entrée du mot de passe
        printf("Enter the password of the vault : ");
        state = bt_fgetss(&vaultPWD);
        if(state != 0){
            return 1;
        }
        state = getVaultPathFromName(&vaultPath,argv[2]);
        if(state == 1){
            return 1;
        }
        uint8_t* b_encryptedVault = NULL;
        uint8_t* b_decryptedVault = NULL;
        size_t size_encryptedVault;
        size_t size_decryptedVault;
        state = readVault(&b_encryptedVault,&size_encryptedVault,vaultPath);
        if(state == 1){
            return 1;
        }
        AES_GCM_Decrypt(&b_decryptedVault,&size_decryptedVault,b_encryptedVault,size_encryptedVault,vaultPWD);
        JsonValue vaultRoot = initCson((char*)b_decryptedVault);

        bt_multiFree(3,app,id,note);
        bt_deepFree(numOfTags, (void**)tags);
        break;
    }
    
    
    default:
        break;
    }

    return 0;
}

int enterPassword(char** dest){

}