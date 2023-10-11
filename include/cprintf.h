#pragma once
#include <stdarg.h>
#include <stdbool.h>

#define CHK(op)                                                                \
    do                                                                         \
    {                                                                          \
        if ((op) == -1)                                                        \
            chprintf(1, #op);                                                  \
    } while (0)

// eprintf can only be called through this macro
#define ERR_MSG(msg)                                                           \
    do                                                                         \
    {                                                                          \
        eprintf(msg, __FILE__, __LINE__);                                      \
    } while (0)

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_WHITE "\x1b[97m"

#define ANSI_BOLD "\x1b[1m"
#define ANSI_UNDERLINE "\x1b[4m"
#define ANSI_RESET "\x1b[0m"

/**
 * Print a debug message
 * @param format The format string
 * @param ... The arguments
 */
void deprintf(const char *format, ...);

extern bool debug;

/**
 * Print an error message
 * @param msg The format string
 * @param file The file where the error occured
 * @param line The line where the error occured
 * @note use ERR_MSG(msg) macro to call this function
 */
void eprintf(const char *msg, const char *file, int line);

/**
 * Print a critical error message and exit
 * @param syserr If 1, print the system error
 * @param file The file where the error occured
 * @param line The line where the error occured
 * @param info Additional information
 * @param msg The format string
 * @param ... The arguments
 *  @note use CHK(op), CHK_ALLOC(op, info), CHK_FREAD(op, fp, info) or
 * CHK_FWRITE(op, size_to_write, info) macros to call this function
 */
void chprintf(int syserr, const char *file, int line, const char *info,
              const char *msg, ...);