#ifndef BT_LOG_H
#define BT_LOG_H

// Écrit une ligne dans CShild/UNSTABLE/log/error.log. Ne jamais y mettre de secret (pwd, id, note).
void bt_logError(const char* file, int line, const char* func, const char* reason);

// Sans ';' final : file, line et func sont ceux de l'endroit où la macro est utilisée.
#define LOG_ERROR(reason) bt_logError(__FILE__, __LINE__, __func__, reason)

#endif
