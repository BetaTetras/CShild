#ifndef BT_PRINTF_H
#define BT_PRINTF_H

// Affichage en couleur (codes ANSI 24 bits) et messages à niveaux. Tout est écrit en UTF-8.
// Sous Windows, la console est passée en UTF-8 avec les codes ANSI activés au premier affichage,
// puis remise comme avant à la fin du programme. Rien à appeler pour ça.
// Les messages ne doivent jamais contenir de secret (mot de passe, note).

// Fait vérifier le format par gcc comme pour printf (types et nombre des arguments) : fmt = n° du paramètre format, args = n° du premier argument
#if defined(__MINGW32__) && !defined(__clang__)
    // MinGW : "printf" suivrait les règles de l'ancien printf de Microsoft (faux warning sur %zu, %lld...)
    #define BT_PRINTF_CHECK(fmt,args) __attribute__((format(gnu_printf,fmt,args)))
#elif defined(__GNUC__)
    #define BT_PRINTF_CHECK(fmt,args) __attribute__((format(printf,fmt,args)))
#else
    #define BT_PRINTF_CHECK(fmt,args)
#endif
void initConsole(void);
void printf_RGB(int r, int g, int b, const char* format, ...) BT_PRINTF_CHECK(4,5);                                // texte en couleur r,g,b (0..255)
void printf_RGB_BG(int fr, int fg, int fb, int br, int bg, int bb, const char* format, ...) BT_PRINTF_CHECK(7,8);  // texte f* sur fond b*
void char_RGB(int r, int g, int b, char c);

// Les messages sont des formats printf : print_ERR("Entrée %s/%s existe déjà", app, id).
// Une donnée de l'utilisateur va TOUJOURS dans un argument (%s), jamais comme format : print_ERR(texte) est une faille.
void print_ERR(const char* format, ...) BT_PRINTF_CHECK(1,2);   // ✗  ERROR    en rouge
void print_INF(const char* format, ...) BT_PRINTF_CHECK(1,2);   // ⓘ  INFO     en violet
void print_WRN(const char* format, ...) BT_PRINTF_CHECK(1,2);   // ⚑  WARNING  en orange
void print_SUC(const char* format, ...) BT_PRINTF_CHECK(1,2);   // ✓  SUCCESS  en vert

#endif
