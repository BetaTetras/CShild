#ifndef BT_API_H
#define BT_API_H

#include <stdint.h>
#include <stddef.h>

#include "cson.h"
#include "bt_utils.h"

// Fonctions qui manipulent le contenu d'un vault (JSON en mémoire).
// Elles ne lisent ni n'écrivent aucun fichier : sauvegarder le vault reste à l'appelant.
// Sauf mention contraire, elles renvoient 0 en cas de succès et 1 en cas d'erreur (détail dans error.log).

// Ajoute entry dans vaultRoot (racine du vault, doit être un objet JSON_OBJECT).
// Crée l'app et/ou l'id s'ils n'existent pas. Renvoie 1 si l'app et l'id existent déjà,
// si les versions de CShild et du vault diffèrent ou si le vault est altéré.
int addEntry(JsonValue *vaultRoot, CShildEntry entry);

// Remplace le mot de passe de data et déplace l'ancien dans "password_history" (avec la date).
// ATTENTION : efface newPassword (stringToZero) une fois copié, il ne doit pas être réutilisé.
int modPassword(JsonObject *data, char* newPassword);

// Date et heure actuelles en UTC au format "2026-11-05T14:32:10Z".
// *dest reçoit une nouvelle chaîne (21 octets), à libérer avec free.
int getTime(char** dest);

// Version enregistrée dans le vault (clé "version"), ou -1 si elle est introuvable.
int getVersionVault(JsonValue vaultRoot);

// Remplit objDest avec une entrée vide : password, note, tags, password_history, created_at et updated_at.
int generateNewBlankEntry(JsonObject* objDest);

// Copie dans obj les champs de entry qui ne sont pas NULL (pwd, note, tags).
// obj doit venir de generateNewBlankEntry.
int fillUpWithEntry(JsonObject* obj, CShildEntry entry);

#endif
