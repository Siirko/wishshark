#include "../include/cprintf.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>

bool _debug = true;

void deprintf(const char *format, ...)
{
    if (_debug)
    {
        va_list args;
        va_start(args, format);
        printf(ANSI_COLOR_YELLOW "\nDEBUG: ");
        vprintf(format, args);
        va_end(args);
        printf(ANSI_RESET);
    }
}

void eprintf(const char *msg, const char *file, int line)
{
    fprintf(stderr, ANSI_BOLD ANSI_COLOR_RED "ERROR: " ANSI_RESET ANSI_BOLD);
    fprintf(stderr, "at %s:%d: " ANSI_RESET, file, line);
    fprintf(stderr, "%s", msg);
    fprintf(stderr, ANSI_RESET);
}

noreturn void chprintf(int syserr, const char *file, int line, const char *info, const char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    eprintf("", file, line);
    fprintf(stderr, "%s\n", info);
    fprintf(stderr, "\t| " ANSI_COLOR_CYAN ANSI_BOLD);
    vfprintf(stderr, msg, ap);
    fprintf(stderr, ANSI_RESET "\n");
    va_end(ap);
    if (syserr == 1)
    {
        fprintf(stderr, "\t| " ANSI_BOLD ANSI_COLOR_RED "PERROR: " ANSI_RESET);
        perror("");
        fprintf(stderr, ANSI_RESET);
    }
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}

void spprintf(bool start, bool end, const char *format, int spaces, int wtab, ...)
{
    va_list args;
    va_start(args, wtab);
    if (start)
        for (int i = 0; i < spaces * wtab; i++)
            printf(" ");
    for (int i = 0; i < spaces * wtab; i++)
    {
        if (i == 0)
            if (end)
                printf("└─");
            else
                printf("├─");
        else
            printf("─");
    }
    vprintf(format, args);
    va_end(args);
}