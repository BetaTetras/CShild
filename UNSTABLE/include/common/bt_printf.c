#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef _WIN32
    #include <windows.h>
#endif

#include "bt_printf.h"

#ifdef _WIN32
    // Réglages d'origine de la console, pour les remettre à la fin du programme
    static UINT oldOutputCP = 0;
    static DWORD oldConsoleMode = 0;
    static int oldModeSaved = 0;

    static void restoreConsole(void){
        if(oldOutputCP != 0){
            SetConsoleOutputCP(oldOutputCP);
        }
        if(oldModeSaved){
            SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE),oldConsoleMode);
        }
    }
#endif

// Prépare la console au tout premier affichage : UTF-8 et codes couleur ANSI. Sans effet hors Windows.
static void initConsole(void){
    static int done = 0;
    if(done){
        return;
    }
    done = 1;
    #ifdef _WIN32
        oldOutputCP = GetConsoleOutputCP();
        SetConsoleOutputCP(CP_UTF8);
        HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
        if(GetConsoleMode(out,&oldConsoleMode)){
            oldModeSaved = 1;
            SetConsoleMode(out,oldConsoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
        atexit(restoreConsole);
    #endif
}

void printf_RGB(int r, int g, int b, const char* format, ...) {
    initConsole();
    va_list args;
    va_start(args, format);
    printf("\033[38;2;%d;%d;%dm", r, g, b);
    vprintf(format, args);
    printf("\033[0m");
    va_end(args);
}

void printf_RGB_BG(int fr, int fg, int fb, int br, int bg, int bb, const char* format, ...) {
    initConsole();
    va_list args;
    va_start(args, format);
    printf("\033[38;2;%d;%d;%dm\033[48;2;%d;%d;%dm", fr, fg, fb, br, bg, bb);
    vprintf(format, args);
    printf("\033[0m");
    va_end(args);
}

void char_RGB(int r, int g, int b, char c) {
    initConsole();
    printf("\033[38;2;%d;%d;%dm", r, g, b);
    printf("%c", c);
    printf("\033[0m");
}

static void printLevel(int r, int g, int b, const char* symbol, const char* label, const char* format, va_list args) BT_PRINTF_CHECK(6,0);

static void printLevel(int r, int g, int b, const char* symbol, const char* label, const char* format, va_list args){
    printf_RGB(r,g,b," %s  ",symbol);
    printf_RGB_BG(0,0,0,r,g,b," %s ",label);
    printf("\033[38;2;%d;%d;%dm ",r,g,b);
    vprintf(format,args);
    printf(" \n\033[0m");
}

void print_ERR(const char* format, ...){
    va_list args;
    va_start(args,format);
    printLevel(255,0,0,"✗","ERR",format,args);
    va_end(args);
}

void print_INF(const char* format, ...){
    va_list args;
    va_start(args,format);
    printLevel(127,0,255,"ℹ","INF",format,args);
    va_end(args);
}

void print_WRN(const char* format, ...){
    va_list args;
    va_start(args,format);
    printLevel(255,165,0,"⚑","WRN",format,args);
    va_end(args);
}

void print_SUC(const char* format, ...){
    va_list args;
    va_start(args,format);
    printLevel(0,255,0,"✓","SUC",format,args);
    va_end(args);
}
