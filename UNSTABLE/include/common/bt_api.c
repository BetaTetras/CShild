#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>
#include <stdarg.h>
#include <dirent.h>
#include <time.h>

#include "cson.h"
#include "bt_utils.h"

int addEntry(JsonValue *vaultRoot,CShildEntry entry){
    if(vaultRoot == NULL || vaultRoot->type != JSON_OBJECT){
        return 1;
    }
    size_t indexor = 0;
    // Vérification des version 
    int versionCShild = getVersionOfCShild();
    int versionVault = getVersionVault(*vaultRoot);
    if(versionCShild == -1 || versionVault == -1){
        return 1;
    }else if(versionCShild != versionVault){
        return 2;
    }

    indexor = getIndexFromObject(vaultRoot->value.object,"apps");
    if(indexor == (size_t)-1){
        return 3;
    }
    // L'application existe t'il ?
    JsonValue *apps_p = &vaultRoot->value.object->listeOfPair[indexor].value;
    size_t indexApp = getIndexFromObject(vaultRoot->value.object->listeOfPair[indexor].value.value.object,entry.app);
    if(indexApp == (size_t)-1){
        // L'app n'existe pas
        JsonValue newApp = initJsonValue(JSON_OBJECT);
        JsonValue newID = initJsonValue(JSON_OBJECT);
        if(generateNewBlankEntry(newID.value.object)){
            freeValue(newApp);
            freeValue(newID);
            return 4;
        }
        if(fillUpWithEntry(newID.value.object,entry)){
            freeValue(newApp);
            freeValue(newID);
            return 4;
        }
        if(addToObject(newApp.value.object,entry.id,newID,0)){
            freeValue(newApp);
            freeValue(newID);
            return 4;
        }
        if(addToObject(apps_p->value.object,entry.app,newApp,apps_p->value.object->nbOfElement)){
            freeValue(newApp);
            freeValue(newID);
            return 4;
        }
        freeValue(newApp);
        freeValue(newID);
    }else{
        JsonValue *IDs_p = &apps_p->value.object->listeOfPair[indexApp].value;
        size_t indexID = getIndexFromObject(IDs_p->value.object,entry.id);
        if(indexID == (size_t)-1){
            // L'ID n'existe pas
            JsonValue newID = initJsonValue(JSON_OBJECT);
            if(generateNewBlankEntry(newID.value.object)){
                freeValue(newID);
                return 4;
            }
            if(fillUpWithEntry(newID.value.object,entry)){
                freeValue(newID);
                return 4;
            }
            if(addToObject(IDs_p->value.object,entry.id,newID,IDs_p->value.object->nbOfElement)){
                freeValue(newID);
                return 4;
            }
            freeValue(newID);
        }else{
            // L'ID existe deja -> redirigée vers mdf
        }
    }

    return 0;
}

int modPassword(JsonObject *data,char* newPassword){
    int state = 0;
    size_t indexPassword = getIndexFromObject(data,"password");
    if(indexPassword == (size_t)-1){
        return 1;
    }
    size_t indexHistory = getIndexFromObject(data,"password_history");
    if(indexHistory == (size_t)-1){
        return 1;
    }
    JsonArray* arrayHistory_p = data->listeOfPair[indexHistory].value.value.array;

    JsonValue oldPassword_v = initJsonValue(JSON_OBJECT);
    char* password = NULL;
    // get the old password
    state = bt_strcpy(&password,data->listeOfPair[indexPassword].value.value.string);
    if(state == 1){
        return 1;
    }
    JsonValue password_v = initJsonValue(JSON_STRING);
    password_v.value.string = password;
    // get the time
    char* date = NULL;
    state = getTime(&date);
    if(state == 1){
        free(password);
        freeValue(oldPassword_v);
        return 1;
    }

    JsonValue date_v = initJsonValue(JSON_STRING);
    date_v.value.string = date;
    
    state = addToObject(&oldPassword_v,"password",password_v,0);
    if(state == 1){
        free(date);
        free(password);
        freeValue(oldPassword_v);
        return 1;
    }
    state = addToObject(&oldPassword_v,"changed_at",date_v,1);
    if(state == 1){
        free(date);
        freeValue(oldPassword_v);
        return 1;
    }

    size_t numberOfElementHistory  = data->listeOfPair[indexHistory].value.value.array->nbOfElement;
    state = addToArray(arrayHistory_p,oldPassword_v,numberOfElementHistory);
    if(state == 1){
        freeValue(oldPassword_v);
        return 1;
    }

    char* buffer = NULL;
    state = bt_strcpy(&buffer,newPassword);
    if(state == 1){
        return 1;
    }
    char* oldPassword_str = data->listeOfPair[indexPassword].value.value.string;
    stringToZero(oldPassword_str,bt_strlen(oldPassword_str)+1);
    stringToZero(newPassword,bt_strlen(newPassword)+1);
    free(oldPassword_str);

    data->listeOfPair[indexPassword].value.value.string = buffer;

    return 0;
}

//////////////////////////////

int getTime(char** dest){
    if (dest == NULL){
        return 1;
    }
    *dest = calloc(21, sizeof(char));
    if (*dest == NULL){
        return 1;
    }
    time_t now = time(NULL);
    struct tm t;
    #ifdef _WIN32
        if (gmtime_s(&t, &now) != 0) { free(*dest); *dest = NULL; return 1; }
    #else
        if (gmtime_r(&now, &t) == NULL) { free(*dest); *dest = NULL; return 1; }
    #endif
    strftime(*dest, 21, "%Y-%m-%dT%H:%M:%SZ", &t);
    return 0;
}


int getVersionVault(JsonValue vaultRoot){
    size_t indexVersion = getIndexFromObject(vaultRoot.value.object,"version");
    if(indexVersion == (size_t) -1){
        return -1;
    }
    return vaultRoot.value.object->listeOfPair[indexVersion].value.value.integer;
}

static char* emptyString(void);
int getTime(char** dest);
void bt_multiFreeValue(size_t numberToFree, ...);

int generateNewBlankEntry(JsonObject* objDest){
    if(objDest == NULL){
        return 1;
    }

    JsonValue password_v = initJsonValue(JSON_STRING);
    JsonValue note_v = initJsonValue(JSON_STRING);
    JsonValue tags_v = initJsonValue(JSON_ARRAY);
    JsonValue password_history_v = initJsonValue(JSON_ARRAY);
    JsonValue created_at_v = initJsonValue(JSON_STRING);
    JsonValue updated_at_v = initJsonValue(JSON_STRING);

    password_v.value.string = emptyString();
    note_v.value.string = emptyString();
    if(password_v.value.string == NULL || note_v.value.string == NULL){
        bt_multiFreeValue(6,&password_v,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        return 1;
    }

    char* creationTime = NULL;
    if(getTime(&creationTime)){
        bt_multiFreeValue(6,&password_v,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        return 1;
    }
    created_at_v.value.string = creationTime;

    char* updateTime = NULL;
    if(getTime(&updateTime)){
        bt_multiFreeValue(6,&password_v,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        return 1;
    }
    updated_at_v.value.string = updateTime;

    if(addToObject(objDest,"password",password_v,0)){
        bt_multiFreeValue(6,&password_v,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        return 1;
    }
    if(addToObject(objDest,"note",note_v,1)){
        bt_multiFreeValue(5,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        return 1;
    }
    if(addToObject(objDest,"tags",tags_v,2)){
        bt_multiFreeValue(4,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        return 1;
    }
    if(addToObject(objDest,"password_history",password_history_v,3)){
        bt_multiFreeValue(3,&password_history_v,&created_at_v,&updated_at_v);
        return 1;
    }
    if(addToObject(objDest,"created_at",created_at_v,4)){
        bt_multiFreeValue(2,&created_at_v,&updated_at_v);
        return 1;
    }
    if(addToObject(objDest,"updated_at",updated_at_v,5)){
        bt_multiFreeValue(1,&updated_at_v);
        return 1;
    }
    return 0;
}

int fillUpWithEntry(JsonObject* obj,CShildEntry entry){
    if(obj == NULL){
        return 1;
    }

    int state = 0;
    if(entry.pwd != NULL){
        state = modPassword(obj,entry.pwd);
        if(state == 1){
            return 1;
        }
    }

    if(entry.note != NULL){
        size_t indexNote = getIndexFromObject(obj,"note");
        if(indexNote == (size_t)-1){
            return 1;
        }
        char* note = NULL;
        if(bt_strcpy(&note,entry.note)){
            return 1;
        }
        freeValue(obj->listeOfPair[indexNote].value);
        obj->listeOfPair[indexNote].value.value.string = note;
    }

    if(entry.tags != NULL){
        size_t indexTags = getIndexFromObject(obj,"tags");
        if(indexTags == (size_t)-1){
            return 1;
        }

        JsonValue newArray = initJsonValue(JSON_ARRAY);
        for(size_t i=0;i< entry.nbOfTags;i++){
            JsonValue tag_v = initJsonValue(JSON_STRING);
            if(bt_strcpy(&tag_v.value.string,entry.tags[i])){
                freeValue(newArray);
                return 1;
            }
            if(addToArray(newArray.value.array,tag_v,i)){
                freeValue(tag_v);
                freeValue(newArray);
                return 1;
            }
        }
        freeValue(obj->listeOfPair[indexTags].value);
        obj->listeOfPair[indexTags].value = newArray;
    }
    return 0;
}

static char* emptyString(void){
    return calloc(1,sizeof(char));
}
