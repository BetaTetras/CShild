#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>
#include <stdarg.h>
#include <dirent.h>
#include <time.h>

#include "cson.h"
#include "bt_utils.h"
#include "bt_log.h"

int addEntry(JsonValue *vaultRoot,CShildEntry entry){
    if(vaultRoot == NULL || vaultRoot->type != JSON_OBJECT){
        LOG_ERROR("Corrupted pointer (vaultRoot == NULL or not an object)");
        return 1;
    }
    size_t indexor = 0;
    // Vérification des version 
    int versionCShild = getVersionOfCShild();
    if(versionCShild == -1){
        LOG_ERROR("Impossible to fetch the version of CShild");
        return 1;
    }
    int versionVault = getVersionVault(*vaultRoot);
    if(versionVault == -1){
        LOG_ERROR("Impossible to fetch the version of the vault");
        return 1;
    }else if(versionCShild != versionVault){
        LOG_ERROR("Version of CShild and the vault different");
        return 1;
    }

    indexor = getIndexFromObject(vaultRoot->value.object,"apps");
    if(indexor == (size_t)-1){
        LOG_ERROR("JSON of the vault altered - key 'apps' not found");
        return 1;
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
            LOG_ERROR("Generation of a blank entry failed (generateNewBlankEntry)");
            return 1;
        }
        if(fillUpWithEntry(newID.value.object,entry)){
            freeValue(newApp);
            freeValue(newID);
            LOG_ERROR("Filling of an object from an entry failed (fillUpWithEntry)");
            return 1;
        }
        if(addToObject(newApp.value.object,entry.id,newID,0)){
            freeValue(newApp);
            freeValue(newID);
            LOG_ERROR("Adding a new value in a object failed (addToObject)");
            return 1;
        }
        if(addToObject(apps_p->value.object,entry.app,newApp,apps_p->value.object->nbOfElement)){
            freeValue(newApp);
            freeValue(newID);
            LOG_ERROR("Adding a new value in a object failed (addToObject)");
            return 1;
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
                LOG_ERROR("Generation of a blank entry failed (generateNewBlankEntry)");
                return 1;
            }
            if(fillUpWithEntry(newID.value.object,entry)){
                freeValue(newID);
                LOG_ERROR("Filling of an object from an entry failed (fillUpWithEntry)");
                return 1;
            }
            if(addToObject(IDs_p->value.object,entry.id,newID,IDs_p->value.object->nbOfElement)){
                freeValue(newID);
                LOG_ERROR("Adding a new value in a object failed (addToObject)");
                return 1;
            }
            freeValue(newID);
        }else{
            LOG_ERROR("User try to add a similar entry (same app and same ID)");
            // printf ?
            return 1;
        }
    }

    return 0;
}

int modPassword(JsonObject *data,char* newPassword){
    int state = 0;
    size_t indexPassword = getIndexFromObject(data,"password");
    if(indexPassword == (size_t)-1){
        LOG_ERROR("JSON altered or corrupted, key 'password' not found");
        return 1;
    }
    size_t indexHistory = getIndexFromObject(data,"password_history");
    if(indexHistory == (size_t)-1){
        LOG_ERROR("JSON altered or corrupted, key 'password_history' not found");
        return 1;
    }
    JsonArray* arrayHistory_p = data->listeOfPair[indexHistory].value.value.array;

    JsonValue oldPassword_v = initJsonValue(JSON_OBJECT);
    char* password = NULL;
    // get the old password
    state = bt_strcpy(&password,data->listeOfPair[indexPassword].value.value.string);
    if(state == 1){
        LOG_ERROR("copy of an string failed (bt_strcpy)");
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
        LOG_ERROR("Impossible to fetch actual time (getTime)");
        return 1;
    }

    JsonValue date_v = initJsonValue(JSON_STRING);
    date_v.value.string = date;
    
    state = addToObject(&oldPassword_v,"password",password_v,0);
    if(state == 1){
        free(date);
        free(password);
        freeValue(oldPassword_v);
        LOG_ERROR("Adding a new value in a object failed (addToObject)");
        return 1;
    }
    state = addToObject(&oldPassword_v,"changed_at",date_v,1);
    if(state == 1){
        free(date);
        freeValue(oldPassword_v);
        LOG_ERROR("Adding a new value in a object failed (addToObject)");
        return 1;
    }

    size_t numberOfElementHistory  = data->listeOfPair[indexHistory].value.value.array->nbOfElement;
    state = addToArray(arrayHistory_p,oldPassword_v,numberOfElementHistory);
    if(state == 1){
        freeValue(oldPassword_v);
        LOG_ERROR("Adding a new value in a array failed (addToArray)");
        return 1;
    }

    char* buffer = NULL;
    state = bt_strcpy(&buffer,newPassword);
    if(state == 1){
        LOG_ERROR("copy of an string failed (bt_strcpy)");
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
        LOG_ERROR("Corrupted pointer (dest == NULL)");
        return 1;
    }
    *dest = calloc(21, sizeof(char));
    if (*dest == NULL){
        LOG_ERROR("Error while allocating memory (*dest = calloc)");
        return 1;
    }
    time_t now = time(NULL);
    struct tm t;
    #ifdef _WIN32
        if (gmtime_s(&t, &now) != 0) { free(*dest); *dest = NULL; LOG_ERROR("Impossible to convert the time (gmtime_s)"); return 1; }
    #else
        if (gmtime_r(&now, &t) == NULL) { free(*dest); *dest = NULL; LOG_ERROR("Impossible to convert the time (gmtime_r)"); return 1; }
    #endif
    strftime(*dest, 21, "%Y-%m-%dT%H:%M:%SZ", &t);
    return 0;
}


int getVersionVault(JsonValue vaultRoot){
    size_t indexVersion = getIndexFromObject(vaultRoot.value.object,"version");
    if(indexVersion == (size_t) -1){
        LOG_ERROR("JSON of the vault altered - key 'version' not found");
        return -1;
    }
    return vaultRoot.value.object->listeOfPair[indexVersion].value.value.integer;
}

static char* emptyString(void);
int getTime(char** dest);
void bt_multiFreeValue(size_t numberToFree, ...);

int generateNewBlankEntry(JsonObject* objDest){
    if(objDest == NULL){
        LOG_ERROR("Corrupted pointer (objDest == NULL)");
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
        LOG_ERROR("Error while allocating memory (emptyString)");
        return 1;
    }

    char* creationTime = NULL;
    if(getTime(&creationTime)){
        bt_multiFreeValue(6,&password_v,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        LOG_ERROR("Impossible to fetch actual time (getTime)");
        return 1;
    }
    created_at_v.value.string = creationTime;

    char* updateTime = NULL;
    if(getTime(&updateTime)){
        bt_multiFreeValue(6,&password_v,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        LOG_ERROR("Impossible to fetch actual time (getTime)");
        return 1;
    }
    updated_at_v.value.string = updateTime;

    if(addToObject(objDest,"password",password_v,0)){
        bt_multiFreeValue(6,&password_v,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        LOG_ERROR("Adding a new value in a object failed (addToObject)");
        return 1;
    }
    if(addToObject(objDest,"note",note_v,1)){
        bt_multiFreeValue(5,&note_v,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        LOG_ERROR("Adding a new value in a object failed (addToObject)");
        return 1;
    }
    if(addToObject(objDest,"tags",tags_v,2)){
        bt_multiFreeValue(4,&tags_v,&password_history_v,&created_at_v,&updated_at_v);
        LOG_ERROR("Adding a new value in a object failed (addToObject)");
        return 1;
    }
    if(addToObject(objDest,"password_history",password_history_v,3)){
        bt_multiFreeValue(3,&password_history_v,&created_at_v,&updated_at_v);
        LOG_ERROR("Adding a new value in a object failed (addToObject)");
        return 1;
    }
    if(addToObject(objDest,"created_at",created_at_v,4)){
        bt_multiFreeValue(2,&created_at_v,&updated_at_v);
        LOG_ERROR("Adding a new value in a object failed (addToObject)");
        return 1;
    }
    if(addToObject(objDest,"updated_at",updated_at_v,5)){
        bt_multiFreeValue(1,&updated_at_v);
        LOG_ERROR("Adding a new value in a object failed (addToObject)");
        return 1;
    }
    return 0;
}

int fillUpWithEntry(JsonObject* obj,CShildEntry entry){
    if(obj == NULL){
        LOG_ERROR("Corrupted pointer (obj == NULL)");
        return 1;
    }

    int state = 0;
    if(entry.pwd != NULL){
        state = modPassword(obj,entry.pwd);
        if(state == 1){
            LOG_ERROR("Modification of password failed (modPassword)");
            return 1;
        }
    }

    if(entry.note != NULL){
        size_t indexNote = getIndexFromObject(obj,"note");
        if(indexNote == (size_t)-1){
            LOG_ERROR("JSON altered or corrupted, key 'note' not found");
            return 1;
        }
        char* note = NULL;
        if(bt_strcpy(&note,entry.note)){
            LOG_ERROR("copy of an string failed (bt_strcpy)");
            return 1;
        }
        freeValue(obj->listeOfPair[indexNote].value);
        obj->listeOfPair[indexNote].value.value.string = note;
    }

    if(entry.tags != NULL){
        size_t indexTags = getIndexFromObject(obj,"tags");
        if(indexTags == (size_t)-1){
            LOG_ERROR("JSON altered or corrupted, key 'tags' not found");
            return 1;
        }

        JsonValue newArray = initJsonValue(JSON_ARRAY);
        for(size_t i=0;i< entry.nbOfTags;i++){
            JsonValue tag_v = initJsonValue(JSON_STRING);
            if(bt_strcpy(&tag_v.value.string,entry.tags[i])){
                freeValue(newArray);
                LOG_ERROR("copy of an string failed (bt_strcpy)");
                return 1;
            }
            if(addToArray(newArray.value.array,tag_v,i)){
                freeValue(tag_v);
                freeValue(newArray);
                LOG_ERROR("Adding a new value in a array failed (addToArray)");
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
