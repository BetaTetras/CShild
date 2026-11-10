#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>

#include "../../include/CSON/cson.h"
#include "../../include/AES-256-GCM/AES.h"
#include "../../include/common/bt_utils.h"
#include "../../include/common/bt_printf.h"
#include "../../include/common/bt_api.h"

// Chemin réel de error.log (voir bt_log.c) : %APPDATA% sous Windows, $HOME sous Linux.
// Ce texte passe dans print_ERR (format printf) : le % de %APPDATA% doit être doublé.
#ifdef _WIN32
    #define ERR_SYSTEM_MSG "Error system, reason is inside '%%APPDATA%%\\CShild\\UNSTABLE\\log\\error.log'"
#else
    #define ERR_SYSTEM_MSG "Error system, reason is inside '~/CShild/UNSTABLE/log/error.log'"
#endif

#define VERSION_CSHILD 0.1

typedef enum {
    crt,
    dlt,
    mdf,
    shw,
    gen,
    mng,
    inf
} methode;

static int fillUpEntryFromARGV(CShildEntry* e,char* argv[],int argc,methode m);
int AES_GCM_Decrypt_returnCodeHandler(int code);
int AES_GCM_Encrypt_returnCodeHandler(int code);


int main(int argc, char *argv[]) {
    initConsole();
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
        m = inf;
    }else if(isOneOfThemEqual(argv[1],3,"init","vaults","password")){
        m = mng;
    }else{
        print_WRN("Methode '%s' non-existant...",argv[1]);
        printf("\n");
        print_INF("You can check command with 'chsild --help'");
        return 1;
    }

    switch (m){
    case crt:{
        if(argc < 3){
            print_WRN("Not enough arguments (%d arguments)",argc);
            return 1;
        }
        state = vaultAreadyCreated(argv[2]);
        if(state == -1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }
        if(state != 1){
            print_WRN("vault name '%s' not found",argv[2]);
            return 1;
        }

        CShildEntry e;

        state = fillUpEntryFromARGV(&e,argv,argc,m);
        if(state == 1){
            return 1;
        }

        char* vaultPWD = NULL;
        char* vaultPath = NULL;

        // Entrée du mot de passe
        printf("Enter the password of the vault : ");
        state = bt_fgetss(&vaultPWD);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state != 0){
            print_WRN("The entered password is empty");
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }
        state = getVaultPathFromName(&vaultPath,argv[2]);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        uint8_t* b_encryptedVault = NULL;
        uint8_t* b_decryptedVault = NULL;
        size_t size_encryptedVault;
        size_t size_decryptedVault;
        state = readVault(&b_encryptedVault,&size_encryptedVault,vaultPath);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state == 2){
            print_ERR("Vault size >= 64 MO");
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        state = AES_GCM_Decrypt(&b_decryptedVault,&size_decryptedVault,b_encryptedVault,size_encryptedVault,vaultPWD);
        if(AES_GCM_Decrypt_returnCodeHandler(state)){
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        JsonValue vaultRoot = initCson((char*)b_decryptedVault);

        state = addEntry(&vaultRoot,e);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state == 2){
            print_WRN("Password empty");
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state == 3){
            print_WRN("Entry already existing");
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        char* jsonTmp = NULL;
        if(sprintfValue(&jsonTmp,vaultRoot)){
            print_ERR("An error occured while transforming an JsonValue in a string");
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }
        uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
        free(b_decryptedVault);
        b_decryptedVault = (uint8_t*)jsonTmp;
        size_decryptedVault = bt_strlen(jsonTmp);

        free(b_encryptedVault);
        b_encryptedVault = NULL;
        state = AES_GCM_Encrypt(&b_encryptedVault,&size_encryptedVault,b_decryptedVault,size_decryptedVault,vaultPWD);
        if(AES_GCM_Encrypt_returnCodeHandler(state)){
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        state = writeVault(b_encryptedVault,size_encryptedVault,vaultPath);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        print_SUC("New entry successfully saved");

        uint8_tToZero(b_encryptedVault,size_encryptedVault);
        uint8_tToZero(b_decryptedVault,size_decryptedVault);
        nukeString(vaultPWD,bt_strlen(vaultPWD));

        free(b_encryptedVault);
        free(b_decryptedVault);
        free(vaultPWD);
        free(vaultPath);
        freeValue(vaultRoot);
        bt_deepFree(e.nbOfTags,(void**)e.tags);

        break;
    }
    case dlt:{
        if(argc < 3){
            print_WRN("Not enough arguments (%d arguments)",argc);
            return 1;
        }
        state = vaultAreadyCreated(argv[2]);
        if(state == -1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }
        if(state != 1){
            print_WRN("vault name '%s' not found",argv[2]);
            return 1;
        }

        CShildEntry e;

        state = fillUpEntryFromARGV(&e,argv,argc,m);
        if(state == 1){
            return 1;
        }
        if(e.id == NULL){
            print_WRN("ID not provided, will proceed to remove ALL entries from '%s'",e.app);
            printf("Continue ? : ");printf("[");char_RGB(0,255,0,'Y');printf("/");char_RGB(255,0,0,'n');printf("] : ");
            state = getValidation();

            if(state == 0){
                print_INF("Action canceled");
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }else if(state == 2){
                print_WRN("Not a valid respond, Action canceled (Must respond with 'Y' or 'N')");
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }
        }

        // 1. On récupére le path du vault et le mdp
        char* vaultPWD = NULL;
        char* vaultPath = NULL;

        printf("Enter the password of the vault : ");
        state = bt_fgetss(&vaultPWD);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state != 0){
            print_WRN("The entered password is empty");
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }
        state = getVaultPathFromName(&vaultPath,argv[2]);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        // 2. On récupére le vault en mémoire
        uint8_t* b_encryptedVault = NULL;
        uint8_t* b_decryptedVault = NULL;
        size_t size_encryptedVault;
        size_t size_decryptedVault;
        state = readVault(&b_encryptedVault,&size_encryptedVault,vaultPath);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state == 2){
            print_ERR("Vault size >= 64 MO");
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        // 3. On décrypte le vault en mémoire
        state = AES_GCM_Decrypt(&b_decryptedVault,&size_decryptedVault,b_encryptedVault,size_encryptedVault,vaultPWD);
        if(AES_GCM_Decrypt_returnCodeHandler(state)){
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        // 4. On extract son JSON avec CSON pour le manipuler
        JsonValue vaultRoot = initCson((char*)b_decryptedVault);

        // 5. On applique l'api
        int numberOfRemovedEntry;
        state = removeEntry(&vaultRoot,e,&numberOfRemovedEntry);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state == 2){
            print_WRN("No application named '%s' inside '%s'",e.app,argv[2]);
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state == 3){
            print_WRN("No ID '%s' in the application '%s' inside '%s'",e.id,e.app,argv[2]);
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state == 4){
            print_INF("No more ID inside application name '%s', app removed",e.app);
        }

        // 6. On réecrit le Json de CSON en char en mémoire
        char* jsonTmp = NULL;
        if(sprintfValue(&jsonTmp,vaultRoot)){
            print_ERR("An error occured while transforming an JsonValue in a string");
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }
        uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
        free(b_decryptedVault);
        b_decryptedVault = (uint8_t*)jsonTmp;
        size_decryptedVault = bt_strlen(jsonTmp);

        // 7. On ré-encrypte
        free(b_encryptedVault);
        b_encryptedVault = NULL;
        state = AES_GCM_Encrypt(&b_encryptedVault,&size_encryptedVault,b_decryptedVault,size_decryptedVault,vaultPWD);
        if(AES_GCM_Encrypt_returnCodeHandler(state)){
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        // 8. On le replace dans l'ancien path
        state = writeVault(b_encryptedVault,size_encryptedVault,vaultPath);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        // 9. On informe l'utilisateur
        print_SUC("%d entry successfully removed",numberOfRemovedEntry);

        // 10. On clean tout en mémoire
        uint8_tToZero(b_encryptedVault,size_encryptedVault);
        uint8_tToZero(b_decryptedVault,size_decryptedVault);
        nukeString(vaultPWD,bt_strlen(vaultPWD));

        free(b_encryptedVault);
        free(b_decryptedVault);
        free(vaultPWD);
        free(vaultPath);
        freeValue(vaultRoot);
        bt_deepFree(e.nbOfTags,(void**)e.tags);

        break;
    }
    case mdf:{
        if(argc < 3){
            print_WRN("Not enough arguments (%d arguments)",argc);
            return 1;
        }
        state = vaultAreadyCreated(argv[2]);
        if(state == -1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }
        if(state != 1){
            print_WRN("vault name '%s' not found",argv[2]);
            return 1;
        }

        CShildEntry e;

        state = fillUpEntryFromARGV(&e,argv,argc,m);
        if(state == 1){
            return 1;
        }if(e.tagsMethode == 1){
            print_WRN("New tag(s) provided through '--tags', old tag(s) will be overwrite");
            printf("Continue ? : ");printf("[");char_RGB(0,255,0,'Y');printf("/");char_RGB(255,0,0,'n');printf("] : ");
            state = getValidation();

            if(state == 0){
                print_INF("If you want to add or remove tags you can use flags '--add-tags' or '--remove-tags'");
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }else if(state == 2){
                print_WRN("Not a valid respond, Action canceled (Must respond with 'Y' or 'N')");
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }
        }

        char* vaultPWD = NULL;
        char* vaultPath = NULL;

        // Entrée du mot de passe
        printf("Enter the password of the vault : ");
        state = bt_fgetss(&vaultPWD);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state != 0){
            print_WRN("The entered password is empty");
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        state = getVaultPathFromName(&vaultPath,argv[2]);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        uint8_t* b_encryptedVault = NULL;
        uint8_t* b_decryptedVault = NULL;
        size_t size_encryptedVault;
        size_t size_decryptedVault;
        state = readVault(&b_encryptedVault,&size_encryptedVault,vaultPath);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }else if(state == 2){
            print_ERR("Vault size >= 64 MO");
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        state = AES_GCM_Decrypt(&b_decryptedVault,&size_decryptedVault,b_encryptedVault,size_encryptedVault,vaultPWD);
        if(AES_GCM_Decrypt_returnCodeHandler(state)){
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(b_encryptedVault);
            free(vaultPWD);
            free(vaultPath);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        if(e.newPassword == 1){
            printf("Enter the new password : ");
            state = bt_fgetss(&e.pwd);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }else if(state != 0){
                print_WRN("The entered password is empty");
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }

            char* buffer = NULL;
            printf("Enter the new password again: ");
            state = bt_fgetss(&buffer);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                nukeString(e.pwd,bt_strlen(e.pwd));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                free(e.pwd);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }else if(state != 0){
                print_WRN("The entered password is empty");
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                nukeString(e.pwd,bt_strlen(e.pwd));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                free(e.pwd);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }
            if(bt_strcmp(e.pwd,buffer) != 0){
                print_WRN("The two password are not the same");
                uint8_tToZero(b_encryptedVault,size_encryptedVault);
                uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                nukeString(e.pwd,bt_strlen(e.pwd));
                nukeString(buffer,bt_strlen(buffer));
                free(b_encryptedVault);
                free(b_decryptedVault);
                free(vaultPWD);
                free(vaultPath);
                free(e.pwd);
                free(buffer);
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }
            nukeString(buffer, bt_strlen(buffer)); free(buffer);
        }

        JsonValue vaultRoot = initCson((char*)b_decryptedVault);

        size_t badtag = (size_t)-1;
        state = modEntry(&vaultRoot,e,&badtag);
        if(state != 0){
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
            }else if(state == 2){
                print_WRN("No application named '%s' inside '%s'",e.app,argv[2]);
            }else if(state == 3){
                print_WRN("No ID '%s' in the application '%s' inside '%s'",e.id,e.app,argv[2]);
            }else if(state == 4){
                print_WRN("Application name '%s' already inside '%s'",e.newAppName,argv[2]);
            }else if(state == 5){
                print_WRN("ID name '%s' already inside '%s'",e.newIDName,e.app);
            }else if(state == 6){
                print_WRN("New password for the app '%s' in ID '%s' is empty",e.app,e.id);
            }else if(state == 7){
                print_WRN("Tag '%s' already inside the application '%s' in ID '%s'",e.tags[badtag],e.app,e.id);
            }else if(state == 8){
                print_WRN("Tag '%s' is not inside the application '%s' in ID '%s'",e.tags[badtag],e.app,e.id);
            }
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            nukeString(e.pwd,bt_strlen(e.pwd));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            free(e.pwd);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        char* jsonTmp = NULL;
        if(sprintfValue(&jsonTmp,vaultRoot)){
            print_ERR("An error occured while transforming an JsonValue in a string");
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            nukeString(e.pwd,bt_strlen(e.pwd));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            free(e.pwd);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }
        uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
        free(b_decryptedVault);
        b_decryptedVault = (uint8_t*)jsonTmp;
        size_decryptedVault = bt_strlen(jsonTmp);

        free(b_encryptedVault);
        b_encryptedVault = NULL;
        state = AES_GCM_Encrypt(&b_encryptedVault,&size_encryptedVault,b_decryptedVault,size_decryptedVault,vaultPWD);
        if(AES_GCM_Encrypt_returnCodeHandler(state)){
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            nukeString(e.pwd,bt_strlen(e.pwd));
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            free(e.pwd);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        state = writeVault(b_encryptedVault,size_encryptedVault,vaultPath);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            uint8_tToZero(b_encryptedVault,size_encryptedVault);
            uint8_tToZero(b_decryptedVault,size_decryptedVault + 1);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            nukeString(e.pwd,bt_strlen(e.pwd));
            free(b_encryptedVault);
            free(b_decryptedVault);
            free(vaultPWD);
            free(vaultPath);
            free(e.pwd);
            freeValue(vaultRoot);
            bt_deepFree(e.nbOfTags,(void**)e.tags);
            return 1;
        }

        print_SUC("Modification successfully saved");

        uint8_tToZero(b_encryptedVault,size_encryptedVault);
        uint8_tToZero(b_decryptedVault,size_decryptedVault);
        nukeString(vaultPWD,bt_strlen(vaultPWD));
        nukeString(e.pwd,bt_strlen(e.pwd));

        free(b_encryptedVault);
        free(b_decryptedVault);
        free(vaultPWD);
        free(vaultPath);
        free(e.pwd);
        freeValue(vaultRoot);
        bt_deepFree(e.nbOfTags,(void**)e.tags);

        break;
    }
    case shw:{
        print_INF("methode shw not implemented");
        break;
    }
    case gen:{
        print_INF("methode gen not implemented");
        break;
    }
    case mng:{
        if(bt_strcmp(argv[1],"init") == 0){
            if(argc > 3 ){
                print_WRN("Too many parameters (%d)",argc);
                return 1;
            }else if(argc < 3){
                print_WRN("Not enough parameters (%d)",argc);
                return 1;
            }

            // Le chemin est récupéré AVANT la création : s'il échoue, aucun fichier n'est créé
            char* pathNewVault = NULL;
            state = getVaultPathFromName(&pathNewVault,argv[2]);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                return 1;
            }

            state = initNewBlankVault(argv[2]);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                free(pathNewVault);
                return 1;
            }else if(state == 2){
                print_WRN("Invalid name: empty, start with '.' or contain path char / forbidden under Windows");
                free(pathNewVault);
                return 1;
            }else if(state == 3){
                print_WRN("Vault '%s' already exists",argv[2]);
                free(pathNewVault);
                return 1;
            }

            char* vaultPWD = NULL;
            char* buffer = NULL;
            print_INF("Remember or write down your master key, if you lost it NO RECOVERY POSSIBLE");
            printf("Enter the password of the vault : ");
            state = bt_fgetss(&vaultPWD);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                remove(pathNewVault);
                free(pathNewVault);
                return 1;
            }else if(state != 0){
                print_WRN("The entered password is empty");
                remove(pathNewVault);
                free(pathNewVault);
                return 1;
            }
            printf("Enter the password of the vault again : ");
            state = bt_fgetss(&buffer);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                remove(pathNewVault);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(pathNewVault);
                return 1;
            }else if(state != 0){
                print_WRN("The entered password is empty");
                remove(pathNewVault);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(pathNewVault);
                return 1;
            }

            if(bt_strcmp(vaultPWD,buffer) != 0){
                print_WRN("The two password are not the same");
                remove(pathNewVault);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                nukeString(buffer,bt_strlen(buffer));
                free(vaultPWD);
                free(buffer);
                free(pathNewVault);
                return 1;
            }
            nukeString(buffer,bt_strlen(buffer));
            free(buffer);

            state = AES_GCM_Encrypt_File(pathNewVault,vaultPWD);
            if(AES_GCM_Encrypt_returnCodeHandler(state)){
                remove(pathNewVault);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(pathNewVault);
                return 1;
            }

            print_SUC("New vault '%s' successfully created",argv[2]);

            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            free(pathNewVault);

        }else if(bt_strcmp(argv[1],"vaults") == 0){

        }else if(bt_strcmp(argv[1],"password") == 0){
            // 1. On vérifie que le nombre de param est correcte
            if(argc > 3 ){
                print_WRN("Too many parameters (%d)",argc);
                return 1;
            }else if(argc < 3){
                print_WRN("Not enough parameters (%d)",argc);
                return 1;
            }

            // 2. On vérifie que le vault existe bien
            state = vaultAreadyCreated(argv[2]);
            if(state == -1){
                print_ERR(ERR_SYSTEM_MSG);
                return 1;
            }else if(state == 0){
                print_WRN("Vault '%s' does not exist",argv[2]);
                return 1;
            }

            // 3. On récupére son path
            char* vaultPath = NULL;
            state = getVaultPathFromName(&vaultPath,argv[2]);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                return 1;
            }

            // 4. On demande le mdp du vault
            char* vaultPWD = NULL;
            char* buffer = NULL;
            printf("Enter the password of the vault : ");
            state = bt_fgetss(&vaultPWD);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                free(vaultPath);
                return 1;
            }else if(state != 0){
                print_WRN("The entered password is empty");
                free(vaultPath);
                return 1;
            }

            // 5. On décrypte en mémoire pour eviter de l'avoir dans le DD
            uint8_t* vault_Encrypted_b = NULL;
            size_t vault_Encrypted_b_size;

            uint8_t* vault_Decrypted_b = NULL;
            size_t vault_Decrypted_b_size;
            state = readVault(&vault_Encrypted_b,&vault_Encrypted_b_size,vaultPath);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(vaultPath);
                return 1;
            }else if(state == 2){
                print_ERR("Vault size >= 64 MO");
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(vaultPath);
                return 1;
            }

            state = AES_GCM_Decrypt(&vault_Decrypted_b,&vault_Decrypted_b_size,vault_Encrypted_b,vault_Encrypted_b_size,vaultPWD);
            if(AES_GCM_Decrypt_returnCodeHandler(state)){
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(vaultPath);
                return 1;
            }

            // 6. On demande le nouveau mot de passe
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            print_INF("Remember or write down your master key, if you lost it NO RECOVERY POSSIBLE");
            printf("Enter the new password of the vault : ");
            state = bt_fgetss(&vaultPWD);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                free(vaultPath);
                return 1;
            }else if(state != 0){
                print_WRN("The entered password is empty");
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                free(vaultPath);
                return 1;
            }
            printf("Enter the new password of the vault again : ");
            state = bt_fgetss(&buffer);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(vaultPath);
                return 1;
            }else if(state != 0){
                print_WRN("The entered password is empty");
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(vaultPath);
                return 1;
            }

            if(bt_strcmp(vaultPWD,buffer) != 0){
                print_WRN("The two password are not the same");
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                nukeString(buffer,bt_strlen(buffer));
                free(vaultPWD);
                free(buffer);
                free(vaultPath);
                return 1;
            }
            nukeString(buffer,bt_strlen(buffer));
            free(buffer);

            // 7. On ré-encrypte le vault avec le nouveau mdp
            uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
            free(vault_Encrypted_b);
            vault_Encrypted_b = NULL;
            state = AES_GCM_Encrypt(&vault_Encrypted_b,&vault_Encrypted_b_size,vault_Decrypted_b,vault_Decrypted_b_size,vaultPWD);
            if(AES_GCM_Encrypt_returnCodeHandler(state)){
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(vaultPath);
                return 1;
            }

            state = writeVault(vault_Encrypted_b,vault_Encrypted_b_size,vaultPath);
            if(state == 1){
                print_ERR(ERR_SYSTEM_MSG);
                uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
                free(vault_Encrypted_b);
                uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
                free(vault_Decrypted_b);
                nukeString(vaultPWD,bt_strlen(vaultPWD));
                free(vaultPWD);
                free(vaultPath);
                return 1;
            }

            print_SUC("The vault '%s' have successfully change password",argv[2]);

            uint8_tToZero(vault_Encrypted_b,vault_Encrypted_b_size);
            free(vault_Encrypted_b);
            uint8_tToZero(vault_Decrypted_b,vault_Decrypted_b_size);
            free(vault_Decrypted_b);
            nukeString(vaultPWD,bt_strlen(vaultPWD));
            free(vaultPWD);
            free(vaultPath);
        }else{

        }
        break;
    }
    case inf:{
        if(isOneOfThemEqual(argv[1],3,"--info","-i","-I")){
            int state;
            // On récupére le path de la conf
            char* configPath = NULL;
            state = getConfPath(&configPath);
            if(state == 1){
                print_ERR("Impossible to fetch config path");
                return 1;
            }
            if(isFileOpenable(configPath) == 0){
                print_ERR("No config json found in %s",configPath);
                free(configPath);
                return 1;
            }
            // On récupére le JSON
            JsonValue conf = initCsonFromFile(configPath);
            if(conf.type == JSON_ERROR){
                print_ERR("No config json found in %s - Erreur CSON",configPath);
                free(configPath);
                return 1;
            }else if(conf.type != JSON_OBJECT){
                print_ERR("Config json altered (not an object)");
                freeValue(conf);
                free(configPath);
                return 1;
            }
            // vaultPath et actionLogPath pointent DANS conf : ne jamais les free (freeValue(conf) s'en charge)
            char* vaultPath = NULL;
            size_t indexVault = getIndexFromObjectWithKey(conf.value.object,"vaults_dir_path");
            if(indexVault == (size_t)-1){
                print_ERR("Config json altered (key 'vaults_dir_path' not found)");
                freeValue(conf);
                free(configPath);
                return 1;
            }
            if(conf.value.object->listeOfPair[indexVault].value.type != JSON_STRING){
                print_ERR("Config json altered (key 'vaults_dir_path' is not a string)");
                freeValue(conf);
                free(configPath);
                return 1;
            }
            vaultPath = conf.value.object->listeOfPair[indexVault].value.value.string;
            // On récupére le path des log d'erreur
            char* errorLogPath = NULL;
            state = getErrorLogPath(&errorLogPath);
            if(state == 1){
                print_ERR("Impossible to fetch error log path");
                freeValue(conf);
                free(configPath);
                return 1;
            }
            // On récupére le path des log d'action
            char* actionLogPath = NULL;
            size_t indexActionLog = getIndexFromObjectWithKey(conf.value.object,"log_action_path");
            if(indexActionLog == (size_t)-1){
                print_ERR("Config json altered (key 'log_action_path' not found)");
                freeValue(conf);
                free(configPath);
                free(errorLogPath);
                return 1;
            }
            if(conf.value.object->listeOfPair[indexActionLog].value.type != JSON_STRING){
                print_ERR("Config json altered (key 'log_action_path' is not a string)");
                freeValue(conf);
                free(configPath);
                free(errorLogPath);
                return 1;
            }
            actionLogPath = conf.value.object->listeOfPair[indexActionLog].value.value.string;
            // On récupére le nombre d'itération PBKDF2
            size_t indexPBKDF2_iteration = getIndexFromObjectWithKey(conf.value.object,"pbkdf2_iterations");
            if(indexPBKDF2_iteration == (size_t)-1){
                print_ERR("Config json altered (key 'pbkdf2_iterations' not found)");
                freeValue(conf);
                free(configPath);
                free(errorLogPath);
                return 1;
            }
            if(conf.value.object->listeOfPair[indexPBKDF2_iteration].value.type != JSON_NUMBER){
                print_ERR("Config json altered (key 'pbkdf2_iterations' is not a number)");
                freeValue(conf);
                free(configPath);
                free(errorLogPath);
                return 1;
            }
            int PBKDF2_iteration = conf.value.object->listeOfPair[indexPBKDF2_iteration].value.value.integer;
            // On récupére le param de logAction
            size_t indexLogActionStatu = getIndexFromObjectWithKey(conf.value.object,"log_action");
            if(indexLogActionStatu == (size_t)-1){
                print_ERR("Config json altered (key 'log_action' not found)");
                freeValue(conf);
                free(configPath);
                free(errorLogPath);
                return 1;
            }
            if(conf.value.object->listeOfPair[indexLogActionStatu].value.type != JSON_BOOL){
                print_ERR("Config json altered (key 'log_action' is not a boolean)");
                freeValue(conf);
                free(configPath);
                free(errorLogPath);
                return 1;
            }
            int logActionStatu = conf.value.object->listeOfPair[indexLogActionStatu].value.value.integer;
            // On récupére le param de generation
            size_t indexGenerator = getIndexFromObjectWithKey(conf.value.object,"generator");
            if(indexGenerator == (size_t)-1){
                print_ERR("Config json altered (key 'generator' not found)");
                freeValue(conf);
                free(configPath);
                free(errorLogPath);
                return 1;
            }
            if(conf.value.object->listeOfPair[indexGenerator].value.type != JSON_OBJECT){
                print_ERR("Config json altered (conf>generator is not an object)");
                freeValue(conf);
                free(configPath);
                free(errorLogPath);
                return 1;
            }
            JsonObject* generator = conf.value.object->listeOfPair[indexGenerator].value.value.object;
            //length
            size_t indexLenght = getIndexFromObjectWithKey(generator,"length");
            if(indexLenght == (size_t)-1){
                print_ERR("Config json altered (key 'length' not found)");
                freeValue(conf);
                free(configPath);
                free(errorLogPath);
                return 1;
            }
            if(generator->listeOfPair[indexLenght].value.type != JSON_NUMBER){
                print_ERR("Config json altered (key 'length' is not a number)");
                freeValue(conf);
                free(configPath);
                free(errorLogPath);
                return 1;
            }
            int length = generator->listeOfPair[indexLenght].value.value.integer;
            //uppercase
            size_t indexUppercase = getIndexFromObjectWithKey(generator,"uppercase");
            if(indexUppercase == (size_t)-1){
                print_ERR("Config json altered (key 'uppercase' not found)");
                freeValue(conf);
                free(configPath);
                free(errorLogPath);
                return 1;
            }
            if(generator->listeOfPair[indexUppercase].value.type != JSON_BOOL){
                print_ERR("Config json altered (key 'uppercase' is not a boolean)");
                freeValue(conf);
                free(configPath);
                free(errorLogPath);
                return 1;
            }
            int uppercase = generator->listeOfPair[indexUppercase].value.value.integer;
            //lowercase
            size_t indexLowercase = getIndexFromObjectWithKey(generator,"lowercase");
            if(indexLowercase == (size_t)-1){
                print_ERR("Config json altered (key 'lowercase' not found)");
                freeValue(conf);
                free(configPath);
                free(errorLogPath);
                return 1;
            }
            if(generator->listeOfPair[indexLowercase].value.type != JSON_BOOL){
                print_ERR("Config json altered (key 'lowercase' is not a boolean)");
                freeValue(conf);
                free(configPath);
                free(errorLogPath);
                return 1;
            }
            int lowercase = generator->listeOfPair[indexLowercase].value.value.integer;
            //digits
            size_t indexDigits = getIndexFromObjectWithKey(generator,"digits");
            if(indexDigits == (size_t)-1){
                print_ERR("Config json altered (key 'digits' not found)");
                freeValue(conf);
                free(configPath);
                free(errorLogPath);
                return 1;
            }
            if(generator->listeOfPair[indexDigits].value.type != JSON_BOOL){
                print_ERR("Config json altered (key 'digits' is not a boolean)");
                freeValue(conf);
                free(configPath);
                free(errorLogPath);
                return 1;
            }
            int digits = generator->listeOfPair[indexDigits].value.value.integer;
            //symbols
            size_t indexSymbols = getIndexFromObjectWithKey(generator,"symbols");
            if(indexSymbols == (size_t)-1){
                print_ERR("Config json altered (key 'symbols' not found)");
                freeValue(conf);
                free(configPath);
                free(errorLogPath);
                return 1;
            }
            if(generator->listeOfPair[indexSymbols].value.type != JSON_BOOL){
                print_ERR("Config json altered (key 'symbols' is not a boolean)");
                freeValue(conf);
                free(configPath);
                free(errorLogPath);
                return 1;
            }
            int symbols = generator->listeOfPair[indexSymbols].value.value.integer;

            printf("\n");
            printf_RGB_BG(15,23,42,96,165,250," CShild v%.1f ",VERSION_CSHILD);printf_RGB(148,163,184,"  First CLI build");printf("\n");
            printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
            printf_RGB(96,165,250,"  %-14s","Config");printf_RGB(148,163,184,"%s",configPath);printf("\n");
            printf_RGB(96,165,250,"  %-14s","Vaults");printf_RGB(148,163,184,"%s",vaultPath);printf("\n");
            printf_RGB(96,165,250,"  %-14s","Error logs");printf_RGB(148,163,184,"%s",errorLogPath);printf("\n");
            printf_RGB(96,165,250,"  %-14s","Action logs");printf_RGB(148,163,184,"%s",actionLogPath);printf("   ");if(logActionStatu){printf_RGB(74,222,128,"✓");}else{printf_RGB(248,113,113,"✗");}printf("\n");
            printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
            printf_RGB(96,165,250,"  %-14s","PBKDF2");printf_RGB(148,163,184,"%d iterations",PBKDF2_iteration);printf("\n");
            printf_RGB(96,165,250,"  %-14s","Length");printf_RGB(148,163,184,"%d characters",length);printf("\n");
            printf_RGB(96,165,250,"  %-14s","Characters");
            printf_RGB(148,163,184,"A-Z ");if(uppercase){printf_RGB(74,222,128,"✓");}else{printf_RGB(248,113,113,"✗");}printf("   ");
            printf_RGB(148,163,184,"a-z ");if(lowercase){printf_RGB(74,222,128,"✓");}else{printf_RGB(248,113,113,"✗");}printf("   ");
            printf_RGB(148,163,184,"0-9 ");if(digits){printf_RGB(74,222,128,"✓");}else{printf_RGB(248,113,113,"✗");}printf("   ");
            printf_RGB(148,163,184,"sym ");if(symbols){printf_RGB(74,222,128,"✓");}else{printf_RGB(248,113,113,"✗");}printf("\n");
            printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
            
            // printf("Path :\n");
            // printf("    Config       %s\n",configPath);
            // printf("    Vaults       %s\n",vaultPath);
            // printf("    Error logs   %s\n",errorLogPath);
            // printf("    Action logs  %s\n",actionLogPath);
            // printf("Configuation :\n");
            // printf("    PBKDF2 iteration   %d\n",PBKDF2_iteration);
            // printf("    Log action         ");if(logActionStatu == 1){printf_RGB(0,255,0,"true\n");}else{printf_RGB(255,0,0,"false\n");};
            // printf("Generation configuarion:\n");
            // printf("    Lenght      %d char\n",length);
            // printf("    Uppercase   ");if(uppercase == 1){printf_RGB(0,255,0,"true\n");}else{printf_RGB(255,0,0,"false\n");};
            // printf("    Lowercase   ");if(lowercase == 1){printf_RGB(0,255,0,"true\n");}else{printf_RGB(255,0,0,"false\n");};
            // printf("    Digits      ");if(digits == 1){printf_RGB(0,255,0,"true\n");}else{printf_RGB(255,0,0,"false\n");};
            // printf("    Symbole     ");if(symbols == 1){printf_RGB(0,255,0,"true\n");}else{printf_RGB(255,0,0,"false\n");};

            freeValue(conf);
            free(configPath);
            free(errorLogPath);
        }else if(isOneOfThemEqual(argv[1],3,"--help","-h","-H")){
            printf("\n");
            printf_RGB_BG(15,23,42,96,165,250," CShild v%.1f ",VERSION_CSHILD);printf_RGB(148,163,184,"  Help");printf("\n");
            printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
            printf_RGB(148,163,184,"  Usage       ");printf("cshild <command> <vault> [options]\n");
            printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
            printf_RGB(148,163,184,"  Commands");printf("\n");
            printf_RGB(96,165,250,"  %-9s%-6s","create","crt");printf_RGB(148,163,184,"Add an entry to a vault");printf("\n");
            printf_RGB(96,165,250,"  %-9s%-6s","modify","mdf");printf_RGB(148,163,184,"Change an entry, rename an application or an ID");printf("\n");
            printf_RGB(96,165,250,"  %-9s%-6s","delete","dlt");printf_RGB(148,163,184,"Remove an entry, or a whole application");printf("\n");
            printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
            printf_RGB(148,163,184,"  Options");printf("\n");
            printf_RGB(96,165,250,"  %-15s%-6s","--app","-a");printf_RGB(148,163,184,"Application name");printf("\n");
            printf_RGB(96,165,250,"  %-15s%-6s","--id","-i");printf_RGB(148,163,184,"Entry identifier");printf("\n");
            printf_RGB(96,165,250,"  %-15s%-6s","--note","-n");printf_RGB(148,163,184,"Note");printf("\n");
            printf_RGB(96,165,250,"  %-15s%-6s","--tags","-t");printf_RGB(148,163,184,"Tags (replace all of them with modify)");printf("\n");
            printf_RGB(96,165,250,"  %-15s%-6s","--add-tags","-at");printf_RGB(148,163,184,"Add tags (modify only)");printf("\n");
            printf_RGB(96,165,250,"  %-15s%-6s","--remove-tags","-rt");printf_RGB(148,163,184,"Remove tags (modify only)");printf("\n");
            printf_RGB(96,165,250,"  %-15s%-6s","--new-app","-na");printf_RGB(148,163,184,"Rename an application (modify only)");printf("\n");
            printf_RGB(96,165,250,"  %-15s%-6s","--new-id","-ni");printf_RGB(148,163,184,"Rename an entry (modify only)");printf("\n");
            printf_RGB(96,165,250,"  %-15s%-6s","--password","-p");printf_RGB(148,163,184,"Change the password (modify only)");printf("\n");
            printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
            printf_RGB(148,163,184,"  Examples");printf("\n");
            printf_RGB(74,222,128,"  cshild crt perso --app Google --id main --tags mail perso");printf("\n");
            printf_RGB(74,222,128,"  cshild mdf perso --app Google --id main --add-tags work");printf("\n");
            printf_RGB(74,222,128,"  cshild mdf perso --app Google --new-app Gmail");printf("\n");
            printf_RGB(74,222,128,"  cshild dlt perso --app Google --id main");printf("\n");
            printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
            print_INF("Deleting without --id removes ALL entries of the application");
            print_INF("'-i' alone shows the configuration, after a command it means --id");
        }else if(isOneOfThemEqual(argv[1],3,"--version","-v","-V")){
            printf("\n");
            printf_RGB_BG(15,23,42,96,165,250," CShild v%.1f ",VERSION_CSHILD);printf_RGB(148,163,184,"  First CLI build");printf("\n");
            printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
            printf_RGB(148,163,184,"  %-15s%-10s%s","Component","Version","Source");printf("\n");
            printf_RGB(96,165,250,"  %-15s%-10.1f","CShild",VERSION_CSHILD);printf_RGB(148,163,184,"https://github.com/BetaTetras/CShild");printf("\n");
            printf_RGB(74,222,128,"  %-15s%-10.1f","CSON",VERSION_CSON);printf_RGB(148,163,184,"https://github.com/BetaTetras/CSON");printf("\n");
            printf_RGB(248,113,113,"  %-15s%-10d","AES-256-GCM",VERSION_AES);printf_RGB(148,163,184,"https://github.com/BetaTetras/AES-256-GCM");printf("\n");
            printf_RGB(148,163,184,"────────────────────────────────────────────────────────────────────");printf("\n");
        }
    }
    
    default:
        break;
    }

    return 0;
}

static int fillUpEntryFromARGV(CShildEntry* e,char* argv[],int argc,methode m){
    int state = 0;
    int paramAPP = 0;
    int paramID = 0;
    int paramNOTE = 0;
    int paramTAGS = 0;
    size_t numOfTags = 0;
    char** tags = NULL;

    int paramNewApp = 0;
    int paramNewID = 0;
    int paramNewPwd = 0;

    *e = (CShildEntry){0};

    for(int i=3;i<argc;i++){
        if(isOneOfThemEqual(argv[i],2,"--app","-a")){
            if(i+1 >= argc){
                // Il manque l'app dans la commande
                print_WRN("App name missing after app balise");
                bt_deepFree(numOfTags, (void**)tags);
                return 1;
            }
            if(paramAPP == 1){
                // Param deja entrée
                print_WRN("Parameter '%s' already use",argv[i]);
                bt_deepFree(numOfTags, (void**)tags); 
                return 1;
            }
            paramAPP = 1;
            e->app = argv[i+1];
            i++;
        }else if(isOneOfThemEqual(argv[i],2,"--id","-i")){
            if(m == mdf){
                if(paramNewApp == 1){
                    print_WRN("The parameter '--id' is useless when changing the name of an app");
                    i++;
                    continue;
                }
            }
            if(i+1 >= argc){
                // Il manque l'id dans la commande
                print_WRN("ID name missing after ID balise");
                bt_deepFree(numOfTags, (void**)tags);
                return 1;
            }
            if(paramID == 1){
                // Param deja entrée
                print_WRN("Parameter '%s' already use",argv[i]);
                bt_deepFree(numOfTags, (void**)tags);
                return 1;
            }
            paramID = 1;
            e->id = argv[i+1];
            i++;
        }else if(isOneOfThemEqual(argv[i],2,"--note","-n")){
            if(m == dlt){
                print_WRN("The parameter '--note' is useless for the methode dlt");
                i++;
                continue;
            }else if(m == mdf){
                if(paramNewApp == 1){
                    print_WRN("The parameter '--note' is useless while changing the name of an app");
                    i++;
                    continue;
                }if(paramNewID == 1){
                    print_WRN("The parameter '--note' is useless while changing the name of an ID");
                    i++;
                    continue;
                }
            }
            if(i+1 >= argc){
                // Il manque la note dans la commande
                print_WRN("Note missing after note balise");
                bt_deepFree(numOfTags, (void**)tags);
                return 1;
            }
            if(paramNOTE == 1){
                // Param deja entrée
                print_WRN("Parameter '%s' already use",argv[i]);
                bt_deepFree(numOfTags, (void**)tags);
                return 1;
            }
            paramNOTE = 1;
            e->note = argv[i+1];
            i++;
        }else if(isOneOfThemEqual(argv[i],6,"--tags","-t","--add-tags","-at","--remove-tags","-rt")){
            if(m == dlt){
                print_WRN("The parameter '--tags' is useless for the methode dlt");
                for(int j=i+1;j<argc;j++){
                    if((argv[j])[0] == '-'){
                        break;
                    }
                    i ++;
                }
                continue;
            }else if(m == mdf){
                if(paramNewApp == 1){
                    print_WRN("The parameter '--tags' is useless while changing the name of an app");
                }if(paramNewID == 1){
                    print_WRN("The parameter '--tags' is useless while changing the name of an ID");
                }
                if(paramNewApp == 1 || paramNewID == 1){
                    for(int j=i+1;j<argc;j++){
                        if((argv[j])[0] == '-'){
                            break;
                        }
                        i ++;
                    }
                    continue;
                }
                if(isOneOfThemEqual(argv[i],2,"--add-tags","-at")){
                    if(paramTAGS != 0){
                        print_WRN("Multiple tags flag use, one single methode allowed");
                        bt_deepFree(numOfTags, (void**)tags);
                        return 1;
                    }
                    paramTAGS = 2;
                    e->tagsMethode = paramTAGS;
                }else if(isOneOfThemEqual(argv[i],2,"--remove-tags","-rt")){
                    if(paramTAGS != 0){
                        print_WRN("Multiple tags flag use, one single methode allowed");
                        bt_deepFree(numOfTags, (void**)tags);
                        return 1;
                    }
                    paramTAGS = 3;
                    e->tagsMethode = paramTAGS;
                }else{
                    if(paramTAGS != 0){
                        print_WRN("Multiple tags flag use, one single methode allowed");
                        bt_deepFree(numOfTags, (void**)tags);
                        return 1;
                    }
                    paramTAGS = 1;
                    e->tagsMethode = paramTAGS;
                }
            }else if(m == crt){
                if(isOneOfThemEqual(argv[i],4,"--add-tags","-at","--remove-tags","-rt")){
                    print_WRN("Tags modifing methode does not apply with the create methode");
                    for(int j=i+1;j<argc;j++){
                        if((argv[j])[0] == '-'){
                            break;
                        }
                        i ++;
                    }
                    continue;
                }
                if(paramTAGS == 1){
                    print_WRN("Parameter '%s' already use",argv[i]);
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                paramTAGS = 1;
            }
            // Calcule du nombre de tag
            for(int j=i+1;j<argc;j++){
                if((argv[j])[0] == '-'){
                    break;
                }
                numOfTags ++;
            }
            if(numOfTags == 0){
                print_WRN("No tag provided after tags balise");
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
            e->tags = tags;
        }else if(m == mdf){
            if(isOneOfThemEqual(argv[i],2,"--new-app","-na")){
                if(i+1 >= argc){
                    // Il manque le nom de la nouvelle app
                    print_WRN("App name missing after new app name balise");
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                if(paramNewID == 1){
                    print_WRN("conflict of parameter, '--new-id' already typed");
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                if(paramNewApp == 1){
                    print_WRN("Parameter '%s' already use",argv[i]);
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                paramNewApp = 1;
                if(paramID == 1 || paramNOTE == 1 || paramTAGS != 0 || paramNewPwd == 1){
                    print_WRN("All parameter outside '--app' and '--new-app' is useless while changing the name of an app");
                }
                e->newAppName = argv[i+1];
                i++;
            }else if(isOneOfThemEqual(argv[i],2,"--new-id","-ni")){
                if(i+1 >= argc){
                    // Il manque le nouvel ID dans la commande
                    print_WRN("ID missing after new ID name balise");
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                if(paramNewApp == 1){
                    print_WRN("conflict of parameter, '--new-app' already typed");
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                if(paramNewID == 1){
                    print_WRN("Parameter '%s' already use",argv[i]);
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                paramNewID = 1;
                if(paramNOTE == 1 || paramTAGS != 0 || paramNewApp == 1 || paramNewPwd == 1){
                    print_WRN("All parameter outside '--app','--id' and '--new-id' is useless while changing the ID of an entry");
                }
                e->newIDName = argv[i+1];
                i++;
            }else if(isOneOfThemEqual(argv[i],2,"--password","-p")){
                if(paramNewApp == 1){
                    print_WRN("The parameter '--password' is useless while changing the name of an app");
                }if(paramNewID == 1){
                    print_WRN("The parameter '--password' is useless while changing the name of an ID");
                }
                if(paramNewPwd == 1){
                    print_WRN("Parameter '%s' already use",argv[i]);
                    bt_deepFree(numOfTags, (void**)tags);
                    return 1;
                }
                if(i+1 < argc){
                    if(argv[i+1][0] != '-'){
                        print_WRN("No password goes through parameters, secure input done later");
                        i++;
                    }
                }
                paramNewPwd = 1;
                e->newPassword = 1;
                continue;
            }else{
                // Commande non reconnue
                print_WRN("Argument '%s' does not exist for the command '%s'",argv[i],argv[1]);
                bt_deepFree(numOfTags, (void**)tags);
                return 1;
            }
        }else{
            // Commande non reconnue
            print_WRN("Argument '%s' does not exist for the command '%s'",argv[i],argv[1]);
            bt_deepFree(numOfTags, (void**)tags);
            return 1;
        }
    }

    // Vérification selon le type de methode
    if(m == crt){
        if(paramAPP == 0 && paramID == 0){
            print_WRN("--app and --id parameter missing");
            bt_deepFree(e->nbOfTags,(void**)tags);
            return 1;
        }else if(paramAPP == 0){
            print_WRN("--app parameter missing");
            bt_deepFree(e->nbOfTags,(void**)tags);
            return 1;
        }else if(paramID == 0){
            print_WRN("--id parameter missing");
            bt_deepFree(e->nbOfTags,(void**)tags);
            return 1;
        }
    }if(m == dlt){
        if(paramAPP == 0){
            print_WRN("--app parameter missing");
            return 1;
        }
    }if(m == mdf){
        if(paramAPP == 0){
            print_WRN("--app parameter missing");
            bt_deepFree(e->nbOfTags,(void**)tags);
            return 1;
        }
        if(paramNewID == 1 && paramID == 0){
            print_WRN("--id parameter missing");
            bt_deepFree(e->nbOfTags,(void**)tags);
            return 1;
        }
        if(paramNewApp == 0 && paramNewID == 0 && paramID == 0){
            print_WRN("--id parameter missing");
            bt_deepFree(e->nbOfTags,(void**)tags);
            return 1;
        }
        if(paramNewApp == 0 && paramNewID == 0 && paramNOTE == 0 && paramTAGS == 0 && paramNewPwd == 0){
            print_WRN("Nothing to modify, use '--note', '--tags', '--add-tags', '--remove-tags', '--password', '--new-app' or '--new-id'");
            return 1;
        }

        if(paramNewApp == 1){
            e->id = NULL;
            e->note = NULL;
            bt_deepFree(e->nbOfTags,(void**)tags);
            e->tags = NULL;
            e->nbOfTags = 0;
            e->newPassword = 0;
            e->tagsMethode = 0;
        }else if(paramNewID == 1){
            e->note = NULL;
            bt_deepFree(e->nbOfTags,(void**)tags);
            e->tags = NULL;
            e->nbOfTags = 0;
            e->newPassword = 0;
            e->tagsMethode = 0;
        }
    }

    return 0;
}

int AES_GCM_Decrypt_returnCodeHandler(int code){
    if(code == AES_ERR_PARAM){
        print_ERR("One of the parameter of AES_GCM_Decrypt is a null pointer");
        return 1;
    }else if(code == AES_ERR_VERSION){
        print_WRN("The encrypting file version is not the same as AES version");
        return 1;
        // A changée pour compatiblitée plus tard
    }else if(code == AES_ERR_MEMOIRE){
        print_ERR("Error occured while allocating memory");
        return 1;
    }else if(code == AES_ERR_MDP){
        print_WRN("Wrong password");
        return 1;
    }else if(code == AES_ERR_AUTH){
        print_ERR("Vault altered while encrypted");
        return 1;
    }else if(code == AES_ERR_FORMAT){
        print_ERR("The vault file is not valid encrypted data (too short or corrupted)");
        return 1;
    }else if(code != AES_OK){
        print_ERR("An unknow error occured...");
        return 1;
    }

    return 0;
}

int AES_GCM_Encrypt_returnCodeHandler(int code){
    if(code == AES_ERR_PARAM){
        print_ERR("One of the parameter of AES_GCM_Encrypt is a null pointer");
        return 1;
    }else if(code == AES_ERR_TAILLE){
        print_ERR("The size of the vault exed 64 GO");
        return 1;
    }else if(code == AES_ERR_ALEA){
        print_ERR("An error whith random occured (urandom or BCryptGenRandom)");
        return 1;
    }else if(code == AES_ERR_MEMOIRE){
        print_ERR("Error occured while allocating memory");
        return 1;
    }else if(code != AES_OK){
        print_ERR("An unknow error occured...");
        return 1;
    }

    return 0;
}