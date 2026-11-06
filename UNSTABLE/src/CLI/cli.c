#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>

#include "../../include/CSON/cson.h"
#include "../../include/AES-256-GCM/AES.h"
#include "../../include/common/bt_utils.h"
#include "../../include/common/bt_printf.h"
#include "../../include/common/bt_api.h"

typedef enum {
    crt,
    dlt,
    mdf,
    shw,
    gen,
    oth
} methode;

static int fillUpEntryFromARGV(CShildEntry* e,char* argv[],int argc);

int main(int argc, char *argv[]) {
    int state = 0;
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
        return 1;
    }

    switch (m)
    {
    case crt:{
        if(argc < 3){
            print_ERR("Not enough arguments (%d aruments)",argc);
            return 1;
        }
        state = vaultAreadyCreated(argv[2]);
        if(state != 1){
            print_ERR("vault name '%s' not found",argv[2]);
            return 1;
        }

        CShildEntry e;

        state = fillUpEntryFromARGV(&e,argv,argc);
        if(state == 1){
            return 1;
        }

        char* vaultPWD = NULL;
        char* newPWD = NULL;
        char* vaultPath = NULL;

        // Entrée du mot de passe
        printf("Enter the password of the vault : ");
        state = bt_fgetss(&vaultPWD);
        if(state != 0){
            print_ERR("Error while getting the entred password");
            return 1;
        }
        state = getVaultPathFromName(&vaultPath,argv[2]);
        if(state == 1){
            print_ERR("Error while getting the path of the path of the vault '%s'",argv[2]);
            return 1;
        }
        
        uint8_t* b_encryptedVault = NULL;
        uint8_t* b_decryptedVault = NULL;
        size_t size_encryptedVault;
        size_t size_decryptedVault;
        state = readVault(&b_encryptedVault,&size_encryptedVault,vaultPath);
        if(state == 1){
            print_ERR("Error while getting the path of the path of the vault '%s'",argv[2]);
            return 1;
        }
        AES_GCM_Decrypt(&b_decryptedVault,&size_decryptedVault,b_encryptedVault,size_encryptedVault,vaultPWD);
        JsonValue vaultRoot = initCson((char*)b_decryptedVault);

        state = addEntry(&vaultRoot,e);
        if(state == 1){
            print_ERR("Something went wrong during opperation of creation");
        }else if(state == 2){
            print_ERR("Password Empty");
        }else if(state == 3){
            print_ERR("Entry alread existing");
        }
        print_SUC("New entry successfully push");

        uint8_tToZero(&b_encryptedVault,size_encryptedVault);
        uint8_tToZero(&b_decryptedVault,size_decryptedVault);
        nukeString(&vaultPWD,bt_strlen(vaultPWD));

        break;
    }
    
    
    default:
        break;
    }

    return 0;
}



static int fillUpEntryFromARGV(CShildEntry* e,char* argv[],int argc){
    int state = 0;
    int paramAPP = 0;
    int paramID = 0;
    int paramNOTE = 0;
    int paramTAGS = 0;
    size_t numOfTags = 0;
    char** tags = NULL;

    *e = (CShildEntry){0};

    for(int i=3;i<argc;i++){
        if(isOneOfThemEqual(argv[i],2,"--app","-a")){
            if(i+1 >= argc){
                // Il manque l'app dans la commande
                print_ERR("App name missing after app balise");
                bt_deepFree(numOfTags, (void**)tags);
                return 1;
            }
            if(paramAPP == 1){
                // Param deja entrée
                print_ERR("Parameter '%s' already use",argv[i]);
                bt_deepFree(numOfTags, (void**)tags); 
                return 1;
            }
            paramAPP = 1;
            e->app = argv[i+1];
            i++;
        }else if(isOneOfThemEqual(argv[i],2,"--id","-i")){
            if(i+1 >= argc){
                // Il manque l'id dans la commande
                print_ERR("ID name missing after ID balise");
                bt_deepFree(numOfTags, (void**)tags);
                return 1;
            }
            if(paramID == 1){
                // Param deja entrée
                print_ERR("Parameter '%s' already use",argv[i]);
                bt_deepFree(numOfTags, (void**)tags);
                return 1;
            }
            paramID = 1;
            e->id = argv[i+1];
            i++;
        }else if(isOneOfThemEqual(argv[i],2,"--note","-n")){
            if(i+1 >= argc){
                // Il manque la note dans la commande
                print_ERR("Note missing after note balise");
                bt_deepFree(numOfTags, (void**)tags);
                return 1;
            }
            if(paramNOTE == 1){
                // Param deja entrée
                print_ERR("Parameter '%s' already use",argv[i]);
                bt_deepFree(numOfTags, (void**)tags);
                return 1;
            }
            paramNOTE = 1;
            e->note = argv[i+1];
            i++;
        }else if(isOneOfThemEqual(argv[i],2,"--tags","-t")){
            if(paramTAGS == 1){
                print_ERR("Parameter '%s' already use",argv[i]);
                bt_deepFree(numOfTags, (void**)tags);
                return 1;
            }
            paramTAGS = 1;
            // Calcule du nombre de tag
            for(int j=i+1;j<argc;j++){
                if((argv[j])[0] == '-'){
                    break;
                }
                numOfTags ++;
            }
            if(numOfTags == 0){
                print_ERR("No tag provided after tags balise");
                return 1;
            }
            char** tmp = realloc(tags,numOfTags * sizeof(char*));
            if(tmp == NULL){
                print_ERR("Error while allocating tags memory");
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
                    print_ERR("Error while allocating a tag memory");
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
            }
            i += numOfTags;
            e->nbOfTags = numOfTags;
            e->tags = (const char**)tags;
        }else{
            // Commande de crt non reconnue
            print_ERR("Argument '%s' does not exist for the command '%s'",argv[i],argv[1]);
            bt_deepFree(numOfTags, (void**)tags);
            return 1;
        }
    }

    if(paramAPP == 0 && paramID == 0){
        print_ERR("App and ID parameter missing");
        return 1;
    }else if(paramAPP == 0){
        print_ERR("App parameter missing");
        return 1;
    }else if(paramID == 0){
        print_ERR("ID parameter missing");
        return 1;
    }

    return 0;
}