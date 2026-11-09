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
// Crée l'app et/ou l'id s'ils n'existent pas. entry.app et entry.id sont obligatoires.
// Renvoie :
//   0 : entrée ajoutée
//   1 : erreur (paramètre invalide, versions de CShild et du vault différentes, vault altéré, mémoire...)
//   2 : mot de passe de l'entrée vide (entry.pwd non NULL mais "")
//   3 : l'app et l'id existent déjà (rien n'est modifié)
int addEntry(JsonValue *vaultRoot, CShildEntry entry);

// Supprime de vaultRoot l'entrée entry.app / entry.id. Si entry.id est NULL, supprime TOUTE l'app.
// Si le dernier id d'une app est supprimé, l'app elle-même est supprimée aussi.
// *numberOfEntryRemoved reçoit le nombre d'entrées supprimées (0 si rien n'a été supprimé) ; il ne doit pas être NULL.
// Renvoie :
//   0 : suppression faite
//   1 : erreur (paramètre invalide, versions de CShild et du vault différentes, vault altéré...)
//   2 : l'app n'existe pas
//   3 : l'id n'existe pas dans cette app
//   4 : suppression faite ET l'app a été supprimée parce qu'elle n'avait plus aucun id (*numberOfEntryRemoved vaut 1)
// 2 et 3 ne sont pas des erreurs internes (rien n'est écrit dans error.log) : l'appelant doit les signaler à l'utilisateur.
int removeEntry(JsonValue *vaultRoot,CShildEntry entry,int* numberOfEntryRemoved);

// Modifie dans vaultRoot l'entrée entry.app / entry.id. Une seule des trois actions est faite, par ordre de priorité :
//   - entry.newAppName non NULL : renomme l'app entry.app (entry.id et le reste sont ignorés)
//   - entry.newIDName non NULL  : renomme l'id entry.id dans l'app entry.app (le reste est ignoré)
//   - sinon, change le contenu de l'entrée : note (entry.note), mot de passe (entry.newPassword == 1 et entry.pwd non NULL ;
//     entry.pwd est effacé par modPassword), tags (entry.tags + entry.nbOfTags, selon entry.tagsMethode), et met à jour
//     "updated_at". Les champs NULL ne sont pas touchés.
//     entry.tagsMethode (utilisé seulement si entry.tags != NULL, toute autre valeur : les tags sont ignorés) :
//       1 : remplace tous les tags de l'entrée par entry.tags
//       2 : ajoute entry.tags aux tags existants (un tag déjà présent, ou donné deux fois, donne le retour 7)
//       3 : retire entry.tags des tags existants (un tag absent donne le retour 8)
// Les valeurs données sont copiées : l'appelant garde (et libère) les siennes. entry.id est obligatoire sauf pour renommer une app.
// Renvoie :
//   0 : modification faite
//   1 : erreur (paramètre invalide, versions de CShild et du vault différentes, vault altéré, mémoire...)
//   2 : l'app n'existe pas
//   3 : l'id n'existe pas dans cette app
//   4 : renommage d'app impossible : le nouveau nom (entry.newAppName) est déjà pris par une autre app (rien n'est modifié)
//   5 : renommage d'id impossible : le nouveau nom (entry.newIDName) est déjà pris dans cette app (rien n'est modifié)
//   6 : le nouveau mot de passe est vide (la note a pu être modifiée avant : ne pas sauvegarder le vault)
//   7 : tagsMethode 2 : un tag existe déjà (la note, le mot de passe et une partie des tags ont pu être modifiés avant :
//       ne pas sauvegarder le vault). *indexBadTag = index de ce tag dans entry.tags
//   8 : tagsMethode 3 : un tag n'existe pas (même remarque que pour 7). *indexBadTag = index de ce tag dans entry.tags
// 2 à 8 ne sont pas des erreurs internes (rien n'est écrit dans error.log) : l'appelant doit les signaler à l'utilisateur.
// Sur tout retour différent de 0, ne pas écrire le vault.
int modEntry(JsonValue *vaultRoot,CShildEntry entry,size_t* indexBadTag);

// Remplace le mot de passe de data et déplace l'ancien dans "password_history" (avec la date).
// ATTENTION : efface newPassword (stringToZero) une fois copié, il ne doit pas être réutilisé.
// Renvoie 0 si le mot de passe est remplacé, 1 en cas d'erreur, 2 si newPassword est vide (rien n'est modifié).
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
// Renvoie 0 si tout est copié, 1 en cas d'erreur, 2 si entry.pwd est vide (le mot de passe est traité en premier : rien n'est alors modifié).
int fillUpWithEntry(JsonObject* obj, CShildEntry entry);

#endif
