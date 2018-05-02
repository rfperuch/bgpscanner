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

#include <errno.h>
#include <inttypes.h>
#include <isolario/bgp.h>
#include <isolario/mrt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mrtdataread.h"

void evprintf(const char *fmt, va_list va)
{
    vfprintf(stderr, fmt, va);
    if (fmt[strlen(fmt) - 1] == ':') {
        fputc(' ', stderr);
        fputs(strerror(errno), stderr);
    }

    fputc('\n', stderr);
}

void eprintf(const char *fmt, ...)
{
    va_list va;

    va_start(va, fmt);
    evprintf(fmt, va);
    va_end(va);
}

noreturn void exvprintf(const char *fmt, va_list va)
{
    evprintf(fmt, va);
    exit(EXIT_FAILURE);
}

noreturn void exprintf(const char *fmt, ...)
{
    va_list va;

    va_start(va, fmt);
    exvprintf(fmt, va);
    va_end(va);
}

int mrtprocess(io_rw_t *io)
{
    if (setmrtreadfrom(io) != MRT_ENOERR) {
        eprintf("Bad packet"); // FIXME
        return -1;
    }

    mrt_header_t *hdr = getmrtheader();
    printf("type: %d subtype: %d\n", hdr->type, hdr->subtype);
    peer_entry_t *i;
    char buf[256];
    size_t n = getpiviewname(buf, sizeof(buf));
    printf("view name: %s (actual length %zu)\n", buf, n);

    size_t count;
    startpeerents(&count);
    printf("reading %zu peer entries\n", count);

    int idx = 0;
    while ((i = nextpeerent()) != NULL) {
        inet_ntop(i->afi == AFI_IPV4 ? AF_INET : AF_INET6, &i->in, buf, sizeof(buf));
        printf("peer entry %d: AS (%zu bytes): %" PRIu32 " AFI: %s - %s\n", idx, i->as_size, i->as, i->afi == AFI_IPV4 ? "v4" : "v6", buf);
        idx++;
    }

    endpeerents();
    mrtclose();
    return 0;
}

