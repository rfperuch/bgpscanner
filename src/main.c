//
// Copyright (c) 2018, Enrico Gregori, Alessandro Improta, Luca Sani, Institute
// of Informatics and Telematics of the Italian National Research Council
// (IIT-CNR). All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE IIT-CNR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#include <fcntl.h>
#include <libgen.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mrtdataread.h"

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

    while ((c = getopt(argc, argv, "")) != -1) {
        switch (c) {
        case '?':
        default:
            usage();
            break;
        }
    }

    if (optind == argc)
        usage();

    int nerrors = 0;
    for (int i = optind; i < argc; i++) {
        io_rw_t *iop;
        io_rw_t io;
        int fd;

        char *ext = extension(argv[i]);
        if (strcasecmp(ext, ".gz") == 0 || strcasecmp(ext, ".z") == 0) {
            fd = open(argv[i], O_RDONLY);
            if (fd == -1) {
                eprintf("cannot open '%s':", argv[i]);
                nerrors++;
                continue;
            }

            iop = io_zopen(fd, BUFSIZ, "r");
        } else if (strcasecmp(ext, ".bz2") == 0) {
            fd = open(argv[i], O_RDONLY);
            if (fd == -1) {
                eprintf("cannot open '%s':", argv[i]);
                nerrors++;
                continue;
            }

            iop = io_bz2open(fd, BUFSIZ, "r");
        } else {
            FILE *file = fopen(argv[i], "r");
            if (!file) {
                eprintf("cannot open '%s':", argv[i]);
                nerrors++;
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
            nerrors++;
            continue;
        }

        if (mrtprocess(iop) != 0)
            nerrors++;

        if (iop->close(iop)) {
            eprintf("I/O error while processing file '%s'", argv[i]);
            nerrors++;
            continue;
        }
    }

    return (nerrors == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

