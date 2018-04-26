#include <errno.h>
#include <fcntl.h>
#include <isolario/io.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

static char *prog;

static void setprogramname(char *argv0)
{
    prog = basename(argv0);
}

static void usage(void)
{
    fprintf(stderr, "%s: The Isolario MRT data reader utility\n", prog);
    exit(EXIT_FAILURE);
}

static void evprintf(const char *fmt, va_list va)
{
    vfprintf(stderr, fmt, va);
    if (fmt[strlen(fmt) - 1] == ':') {
        fputc(' ', stderr);
        fputs(strerror(errno), stderr);
    }

    fputc('\n', stderr);
}

static void eprintf(const char *fmt, ...)
{
    va_list va;

    va_start(va, fmt);
    evprintf(fmt, va);
    va_end(va);
}

static void exvprintf(const char *fmt, va_list va)
{
    evprintf(fmt, va);
    exit(EXIT_FAILURE);
}

static void exprintf(const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    exvprintf(fmt, va);
    va_end(va);
}

static char *extension(const char *name)
{
    const char *ext = NULL;

    int c;
    while ((c = *name) != '\0') {
       if (c == '/')
           ext = NULL;
       if (c == '.')
           ext = name;

        name++;
    }
    if (!ext)
        ext = name;

    return (char *) ext;
}

int main(int argc, char **argv)
{
    int c;

    setprogramname(argv[0]);

    while ((c = getopt(argc, argv, "")) != '\0') {
        switch (c) {
        case '?':
        default:
            usage();
            break;
        }
    }

    for (int i = optind; i < argc; i++) {
        io_rw_t *iop;
        io_rw_t io;
        int fd;

        char *ext = extension(argv[i]);
        if (strcasecmp(ext, ".gz") == 0 || strcasecmp(ext, ".z") == 0) {
            fd = open(argv[i], O_RDONLY);
            if (fd == -1) {
                eprintf("cannot open '%s':", argv[i]);
                continue;
            }

            iop = io_zopen(fd, BUFSIZ, "r");
        } else if (strcasecmp(ext, "bz2") == 0) {
            fd = open(argv[i], O_RDONLY);
            if (fd == -1) {
                eprintf("cannot open '%s':", argv[i]);
                continue;
            }

            iop = io_bz2open(fd, BUFSIZ, "r");
        } else {
            FILE *file = fopen(argv[i], "r");
            if (!file) {
                eprintf("cannot open '%s':", argv[i]);
                continue;
            }

            io.file  = file;
            io.read  = io_fread;
            io.write = io_fwrite;
            io.error = io_ferror;
            io.close = io_fclose;

            iop = &io;
        }

        if (!iop) {
            eprintf("bad file format '%s':", argv[i]);
            continue;
        }

        iop->close(iop);
    }

    return EXIT_SUCCESS;
}

