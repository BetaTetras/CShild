#ifndef BT_LOG_H
#define BT_LOG_H

// Écrit une ligne dans CShild/UNSTABLE/log/error.log. Ne jamais y mettre de secret (pwd, id, note).
void bt_logError(const char* file, int line, const char* func, const char* reason);

// Sans ';' final : file, line et func sont ceux de l'endroit où la macro est utilisée.
#define LOG_ERROR(reason) bt_logError(__FILE__, __LINE__, __func__, reason)

// Écrit une ligne dans le fichier log_action_path de conf.json, seulement si log_action vaut true (sinon ne fait rien).
// methode : '+' ajout, '-' suppression, '*' modification, '!' mot de passe du vault changé, '@' mauvais mot de passe, 'v' vault créé (écrit [+]).
// numberOfModif n'est utilisé que pour '-' (nombre d'entrées supprimées). Ne jamais y mettre de secret (pwd, app, id, note).
void bt_logAction(char methode,char* vault,int numberOfModif);

#endif
