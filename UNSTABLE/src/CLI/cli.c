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

typedef enum {
    crt,
    dlt,
    mdf,
    shw,
    gen,
    oth
} methode;

static int fillUpEntryFromARGV(CShildEntry* e,char* argv[],int argc,methode m);
int AES_GCM_Decrypt_returnCodeHandler(int code);
int AES_GCM_Encrypt_returnCodeHandler(int code);


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
        print_ERR("Methode '%s' non-existant...",argv[1]);
        printf("\n");
        print_INF("You can check command with 'chsild --help'");
        return 1;
    }

    switch (m){
    case crt:{
        if(argc < 3){
            print_ERR("Not enough arguments (%d aruments)",argc);
            return 1;
        }
        state = vaultAreadyCreated(argv[2]);
        if(state == -1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }
        if(state != 1){
            print_ERR("vault name '%s' not found",argv[2]);
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
            return 1;
        }else if(state != 0){
            print_WRN("The entered password is empty");
            return 1;
        }
        state = getVaultPathFromName(&vaultPath,argv[2]);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }
        
        uint8_t* b_encryptedVault = NULL;
        uint8_t* b_decryptedVault = NULL;
        size_t size_encryptedVault;
        size_t size_decryptedVault;
        state = readVault(&b_encryptedVault,&size_encryptedVault,vaultPath);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }else if(state == 2){
            print_ERR("Vault size >= 64 MO");
            return 1;
        }

        state = AES_GCM_Decrypt(&b_decryptedVault,&size_decryptedVault,b_encryptedVault,size_encryptedVault,vaultPWD);
        if(AES_GCM_Decrypt_returnCodeHandler(state)){
            return 1;
        }

        JsonValue vaultRoot = initCson((char*)b_decryptedVault);

        state = addEntry(&vaultRoot,e);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }else if(state == 2){
            print_ERR("Password empty");
            return 1;
        }else if(state == 3){
            print_ERR("Entry alread existing");
            return 1;
        }

        char* jsonTmp = NULL;
        if(sprintfValue(&jsonTmp,vaultRoot)){
            print_ERR("An error occured while transforming an JsonValue in a string");
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
            return 1;
        }

        state = writeVault(b_encryptedVault,size_encryptedVault,vaultPath);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }

        print_SUC("New entry successfully save");

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
            print_ERR("Not enough arguments (%d aruments)",argc);
            return 1;
        }
        state = vaultAreadyCreated(argv[2]);
        if(state == -1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }
        if(state != 1){
            print_ERR("vault name '%s' not found",argv[2]);
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
                print_ERR("Not a valid respond, Action canceled (Must respond with 'Y' or 'N')");
                bt_deepFree(e.nbOfTags,(void**)e.tags);
                return 1;
            }
        }

        char* vaultPWD = NULL;
        char* vaultPath = NULL;

        printf("Enter the password of the vault : ");
        state = bt_fgetss(&vaultPWD);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }else if(state != 0){
            print_WRN("The entered password is empty");
            return 1;
        }
        state = getVaultPathFromName(&vaultPath,argv[2]);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }

        uint8_t* b_encryptedVault = NULL;
        uint8_t* b_decryptedVault = NULL;
        size_t size_encryptedVault;
        size_t size_decryptedVault;
        state = readVault(&b_encryptedVault,&size_encryptedVault,vaultPath);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }else if(state == 2){
            print_ERR("Vault size >= 64 MO");
            return 1;
        }

        state = AES_GCM_Decrypt(&b_decryptedVault,&size_decryptedVault,b_encryptedVault,size_encryptedVault,vaultPWD);
        if(AES_GCM_Decrypt_returnCodeHandler(state)){
            return 1;
        }

        JsonValue vaultRoot = initCson((char*)b_decryptedVault);

        int numberOfRemovedEntry;
        state = removeEntry(&vaultRoot,e,&numberOfRemovedEntry);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }else if(state == 2){
            print_WRN("No application named '%s' inside '%s'",e.app,argv[2]);
            return 1;
        }else if(state == 3){
            print_WRN("No ID '%s' in the application '%s' inside '%s'",e.id,e.app,argv[2]);
            return 1;
        }
        
        char* jsonTmp = NULL;
        if(sprintfValue(&jsonTmp,vaultRoot)){
            print_ERR("An error occured while transforming an JsonValue in a string");
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
            return 1;
        }

        state = writeVault(b_encryptedVault,size_encryptedVault,vaultPath);
        if(state == 1){
            print_ERR(ERR_SYSTEM_MSG);
            return 1;
        }

        print_SUC("%d entry successfully removed",numberOfRemovedEntry);

        uint8_tToZero(b_encryptedVault,size_encryptedVault);
        uint8_tToZero(b_decryptedVault,size_decryptedVault);
        nukeString(vaultPWD,bt_strlen(vaultPWD));

        free(b_encryptedVault);
        free(b_decryptedVault);
        free(vaultPWD);
        free(vaultPath);
        freeValue(vaultRoot);

        break;
    }
    case mdf:{
        print_INF("methode mdf not implemented");
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
    case oth:{
        print_INF("methode oth not implemented");
        break;
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
            if(m == dlt){
                print_WRN("The parameter '--note' is useless for the methode dlt");
                i++;
                continue;
            }
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
            if(m == dlt){
                print_WRN("The parameter '--tags' is useless for the methode dlt");
                for(int j=i+1;j<argc;j++){
                    if((argv[j])[0] == '-'){
                        break;
                    }
                    i ++;
                }
                continue;
            }
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
            e->tags = tags;
        }else{
            // Commande de crt non reconnue
            print_ERR("Argument '%s' does not exist for the command '%s'",argv[i],argv[1]);
            bt_deepFree(numOfTags, (void**)tags);
            return 1;
        }
    }

    // Vérification selon le type de methode
    if(m == crt){
        if(paramAPP == 0 && paramID == 0){
            print_ERR("App and ID parameter missing");
            bt_deepFree(e->nbOfTags,(void**)tags);
            return 1;
        }else if(paramAPP == 0){
            print_ERR("--app parameter missing");
            bt_deepFree(e->nbOfTags,(void**)tags);
            return 1;
        }else if(paramID == 0){
            print_ERR("ID parameter missing");
            bt_deepFree(e->nbOfTags,(void**)tags);
            return 1;
        }
    }if(m == dlt){
        if(paramAPP == 0){
            print_ERR("--app parameter missing");
            return 1;
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
        print_ERR("Wrong password");
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