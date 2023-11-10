#pragma once
#include "../include/cprintf.h"
#include <argp.h>
#include <stdbool.h>
#include <stdlib.h>

/**
 * @defgroup ParsingModule
 * @{
 * @brief Parse argments from command line using argp
 * @note Reference:
 * https://www.gnu.org/software/libc/manual/html_node/Argp-Example-3.html
 */

const char *argp_program_version = "1.0";

/* Program documentation. */
static char doc[] = "Cheap version of Wireshark.";

/* The options we understand. */
static struct argp_option options[] = {
    {"interface", 'i', "INTERFACE", 0, "Interface for live analysis", 0},
    {"file", 'o', "PCAP_FILE", 0, "PCAP file for offline analysis", 0},
    {"verbosity", 'v', "<1..3>", 0, "Verbosity : 1 = Concise, 2 = Verbose, 3 = Complete", 0},
    {0}};

enum VerboseLevel
{
    CONCISE = 1,
    VERBOSE = 2,
    COMPLETE = 3
};

/* Used by main to communicate with parse_opt. */
typedef struct arguments
{
    // char *args[2];                /* arg1 & arg2 */
    char *interface;
    char *input_file;
    enum VerboseLevel verbose_level;
} arguments_t;

/* Parse a single option. */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    /* Get the input argument from argp_parse, which we
       know is a pointer to our arguments structure. */
    arguments_t *arguments = state->input;
    switch (key)
    {
    case ARGP_KEY_END:
        // weird
        if (state->argc != 5)
        {
            // ARGP_HELP_BUG_ADDR
            // argp_usage(state);
        }
        break;
    case 'i':
        arguments->interface = arg;
        break;
    case 'o':
        arguments->input_file = arg;
        break;
    case 'v':
        arguments->verbose_level = atoi(arg);
        if (arguments->verbose_level < 1 || arguments->verbose_level > 3)
        {
            deprintf("Invalid verbose level: %d\n", arguments->verbose_level);
            argp_usage(state);
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

/* Our argp parser. */
static struct argp argp = {options, parse_opt, NULL, doc, NULL, NULL, NULL};
/** @} */
