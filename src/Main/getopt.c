/*
 * Windows getopt implementation for truecrack
 * A simple implementation supporting getopt and getopt_long
 */
#ifdef _WIN32

#include <stdio.h>
#include <string.h>
#include "getopt.h"

char *optarg = NULL;
int optind = 1;
int opterr = 1;
int optopt = '?';

static int sp = 1;

int getopt(int argc, char * const argv[], const char *optstring) {
    int c;
    const char *cp;

    if (sp == 1) {
        if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0') {
            return -1;
        } else if (strcmp(argv[optind], "--") == 0) {
            optind++;
            return -1;
        }
    }
    optopt = c = argv[optind][sp];
    if (c == ':' || (cp = strchr(optstring, c)) == NULL) {
        if (opterr)
            fprintf(stderr, "%s: illegal option -- %c\n", argv[0], c);
        if (argv[optind][++sp] == '\0') {
            optind++;
            sp = 1;
        }
        return '?';
    }
    if (*++cp == ':') {
        if (argv[optind][sp + 1] != '\0') {
            optarg = &argv[optind++][sp + 1];
        } else if (++optind >= argc) {
            if (opterr)
                fprintf(stderr, "%s: option requires an argument -- %c\n", argv[0], c);
            sp = 1;
            return '?';
        } else {
            optarg = argv[optind++];
        }
        sp = 1;
    } else {
        if (argv[optind][++sp] == '\0') {
            sp = 1;
            optind++;
        }
        optarg = NULL;
    }
    return c;
}

int getopt_long(int argc, char * const argv[], const char *optstring,
                const struct option *longopts, int *longindex) {
    int i;

    if (optind >= argc)
        return -1;

    if (argv[optind][0] != '-')
        return -1;

    if (argv[optind][1] == '-' && argv[optind][2] != '\0') {
        /* Long option */
        const char *arg = &argv[optind][2];
        const char *eq = strchr(arg, '=');
        size_t len = eq ? (size_t)(eq - arg) : strlen(arg);

        for (i = 0; longopts[i].name != NULL; i++) {
            if (strncmp(arg, longopts[i].name, len) == 0 && longopts[i].name[len] == '\0') {
                if (longindex)
                    *longindex = i;

                if (longopts[i].has_arg) {
                    if (eq) {
                        optarg = (char *)(eq + 1);
                    } else if (optind + 1 < argc) {
                        optarg = argv[++optind];
                    } else {
                        if (opterr)
                            fprintf(stderr, "%s: option '--%s' requires an argument\n", argv[0], longopts[i].name);
                        optind++;
                        return '?';
                    }
                }

                optind++;

                if (longopts[i].flag) {
                    *longopts[i].flag = longopts[i].val;
                    return 0;
                }
                return longopts[i].val;
            }
        }

        if (opterr)
            fprintf(stderr, "%s: unrecognized option '--%.*s'\n", argv[0], (int)len, arg);
        optind++;
        return '?';
    }

    /* Short option */
    return getopt(argc, argv, optstring);
}

#endif /* _WIN32 */
