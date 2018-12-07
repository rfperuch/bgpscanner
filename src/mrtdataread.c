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
#include <isolario/cache.h>
#include <isolario/dumppacket.h>
#include <isolario/filterintrin.h>
#include <isolario/hexdump.h>
#include <isolario/mrt.h>
#include <isolario/progutil.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mrtdataread.h"

enum {
    MAX_PEERREF_BITSET_SIZE = UINT16_MAX / (sizeof(uint32_t) * CHAR_BIT)
};

static bool seen_ribpi;
static unsigned long long pkgseq;

static uint32_t peerrefs[MAX_PEERREF_BITSET_SIZE];
enum {
    PEERREF_SHIFT = 5,
    PEERREF_MASK  = 0x1f
};

static int close_bgp_packet(const char *filename)
{
    int err = bgperror();
    if (err != BGP_ENOERR) {
        eprintf("%s: bad packet detected (%s)", filename, bgpstrerror(err));
        fprintf(stderr, "binary packet dump follows:\n");
        fprintf(stderr, "ASN32BIT: %s ADDPATH: %s\n", isbgpasn32bit() ? "yes" : "no", isbgpaddpath() ? "yes" : "no");

        size_t n;
        const void *data = getbgpdata(&n);

        hexdump(stderr, data, n, "x#|1|80");
        fputc('\n', stderr);
    }

    bgpclose();
    return err;
}

static void report_bad_rib(const char *filename, int err, const rib_entry_t *rib)
{
    eprintf("%s: bad RIB entry for NLRI %s (%s)", filename, naddrtos(&rib->nlri, NADDR_CIDR), bgpstrerror(err));
    fprintf(stderr, "attributes segment dump follows:\n");
    hexdump(stderr, rib->attrs, rib->attr_length, "x#|1|80");
    fputc('\n', stderr);
}

typedef enum {
    PROCESS_SUCCESS = 0,  // all good
    PROCESS_BAD,          // bad record, but keep going
    PROCESS_CORRUPTED,    // bad dump, skip the entire dump
} process_result_t;

static process_result_t processbgp4mp(const char *filename, const mrt_header_t *hdr, filter_vm_t *vm, mrt_dump_fmt_t format)
{
    size_t n;
    void *data;

    const bgp4mp_header_t *bgphdr = getbgp4mpheader();
    if (unlikely(!bgphdr)) {
        eprintf("%s: corrupted BGP4MP header (%s)", filename, mrtstrerror(mrterror()));
        return PROCESS_CORRUPTED;
    }

    vm->kp[K_PEER_AS].as = bgphdr->peer_as;
    memcpy(&vm->kp[K_PEER_ADDR].addr, &bgphdr->peer_addr, sizeof(vm->kp[K_PEER_ADDR].addr));

    int res, err;

    int flags = BGPF_NOCOPY;
    size_t as_size = sizeof(uint16_t); // for state changes

    err = BGP_ENOERR;
    switch (hdr->subtype) {
    case BGP4MP_STATE_CHANGE_AS4:
        as_size = sizeof(uint32_t);
        // fallthrough
    case BGP4MP_STATE_CHANGE:
        printstatechange(stdout, bgphdr, "A*F*T", as_size, &vm->kp[K_PEER_ADDR].addr, vm->kp[K_PEER_AS].as, &hdr->stamp);
        break;

    case BGP4MP_MESSAGE_AS4_ADDPATH:
    case BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH:
        flags |= BGPF_ADDPATH;
        // fallthrough
    case BGP4MP_MESSAGE_AS4:
    case BGP4MP_MESSAGE_AS4_LOCAL:
        flags |= BGPF_ASN32BIT;
        // fallthrough
    case BGP4MP_MESSAGE_ADDPATH:
    case BGP4MP_MESSAGE_LOCAL_ADDPATH:
        // if BGPF_ASN32BIT is on, then we're arriving here through the case above,
        // so don't modify the flags
        flags |= (flags & BGPF_ASN32BIT) == 0 ? BGPF_ADDPATH : 0;
        // fallthrough
    case BGP4MP_MESSAGE:
    case BGP4MP_MESSAGE_LOCAL:
        data = unwrapbgp4mp(&n);
        if (unlikely(!data)) {
            eprintf("%s: corrupted BGP4MP message (%s)", filename, mrtstrerror(mrterror()));
            return false;
        }

        err = setbgpread(data, n, flags);
        if (unlikely(err != BGP_ENOERR))
            break;

        res = true; // assume packet passes, we will only filter BGP updates
        if (getbgptype() == BGP_UPDATE) {
            res = bgp_filter(vm);
            if (res < 0 && res != VM_BAD_PACKET)
                exprintf(EXIT_FAILURE, "%s: unexpected filter failure (%s)", filename, filter_strerror(res));
        }
        if (res > 0) {
            const char *fmt = (format == MRT_DUMP_CHEX) ? "xF*T" : "rF*T";

            printbgp(stdout, fmt, &vm->kp[K_PEER_ADDR].addr, vm->kp[K_PEER_AS].as, &hdr->stamp);
        }

        err = close_bgp_packet(filename);
        break;

    default:
        eprintf("%s: unhandled BGP4MP packet of subtype: %#x", filename, (unsigned int) hdr->subtype);
        break;
    }

    if (unlikely(err != BGP_ENOERR))
        return PROCESS_BAD;

    return PROCESS_SUCCESS;
}

static process_result_t processzebra(const char *filename, const mrt_header_t *hdr, filter_vm_t *vm, mrt_dump_fmt_t format)
{
    size_t n;
    void *data;

    const zebra_header_t *zhdr = getzebraheader();
    if (unlikely(!zhdr)) {
        eprintf("%s: corrupted Zebra BGP header (%s)", filename, mrtstrerror(mrterror()));
        return PROCESS_CORRUPTED;
    }

    vm->kp[K_PEER_AS].as = zhdr->peer_as;
    memcpy(&vm->kp[K_PEER_ADDR].addr, &zhdr->peer_addr, sizeof(vm->kp[K_PEER_ADDR].addr));

    int res, err;

    err = BGP_ENOERR;
    switch (hdr->subtype) {
    case MRT_BGP_STATE_CHANGE:
        // FIXME printstatechange(stdout, bgphdr, "A*F*T", sizeof(uint16_t), &vm->kp[K_PEER_ADDR].addr, vm->kp[K_PEER_AS].as, &hdr->stamp);
        break;


    case MRT_BGP_NULL:
    case MRT_BGP_PREF_UPDATE:
    case MRT_BGP_SYNC:
    case MRT_BGP_OPEN:
    case MRT_BGP_NOTIFY:
    case MRT_BGP_KEEPALIVE:
        break;
    
    case MRT_BGP_UPDATE:
        data = unwrapzebra(&n);
        if (unlikely(!data)) {
            eprintf("%s: corrupted Zebra BGP message (%s)", filename, mrtstrerror(mrterror()));
            return false;
        }

        setbgpwrite(BGP_UPDATE, BGPF_DEFAULT);
        setbgpdata(data, n);
        if (unlikely(!bgpfinish(NULL)))
            break;

        res = bgp_filter(vm);
        if (res < 0 && res != VM_BAD_PACKET)
            exprintf(EXIT_FAILURE, "%s: unexpected filter failure (%s)", filename, filter_strerror(res));

        if (res > 0) {
            const char *fmt = (format == MRT_DUMP_CHEX) ? "xF*T" : "rF*T";

            printbgp(stdout, fmt, &vm->kp[K_PEER_ADDR].addr, vm->kp[K_PEER_AS].as, &hdr->stamp);
        }

        err = close_bgp_packet(filename);
        break;

    default:
        eprintf("%s: unhandled Zebra BGP packet of subtype: %#x", filename, (unsigned int) hdr->subtype);
        break;
    }

    if (unlikely(err != BGP_ENOERR))
        return PROCESS_BAD;

    return PROCESS_SUCCESS;
}

static int istrivialfilter(filter_vm_t *vm)
{
    return vm->codesiz == 1 && vm->code[0] == vm_makeop(FOPC_LOAD, true);
}

enum {
    DONT_DUMP_RIBS,
    DUMP_RIBS
};

enum {
    TABLE_DUMP_SUBTYPE_MARKER = -1  // a marker subtype, see processtabledump()
};

static void refpeeridx(uint16_t idx)
{
    peerrefs[idx >> PEERREF_SHIFT] |= 1 << (idx & PEERREF_MASK);
}

static int ispeeridxref(uint16_t idx)
{
    return peerrefs[idx >> PEERREF_SHIFT] & (1 << (idx & PEERREF_MASK));
}

static process_result_t processtabledump(const char *filename, const mrt_header_t *hdr, filter_vm_t *vm, mrt_dump_fmt_t format)
{
    const rib_entry_t *rib;

    int ribflags = BGPF_GUESSMRT | BGPF_STRIPUNREACH;
    int subtype  = hdr->subtype;
    if (hdr->type == MRT_TABLE_DUMP) {
        // expect attribute lists to be encoded in the appropriate format (disables BGPF_GUESSMRT)
        ribflags |= BGPF_LEGACYMRT;
        // we are dealing with the deprecated TABLE_DUMP format, remap
        // subtype to a spoecial value so we can deal with them in an
        // uniform way without any code duplication
        subtype = TABLE_DUMP_SUBTYPE_MARKER;
    }

    switch (subtype) {
    case MRT_TABLE_DUMPV2_PEER_INDEX_TABLE:
        if (unlikely(seen_ribpi)) {
            eprintf("%s: bad RIB dump, duplicated PEER_INDEX_TABLE, skipping rest of file", filename);
            return PROCESS_CORRUPTED;
        }
        if (unlikely(pkgseq != 0))
            eprintf("%s: warning, PEER_INDEX_TABLE is not the first record in file", filename);

        setribpi();

        seen_ribpi = true;
        break;

    case MRT_TABLE_DUMPV2_RIB_IPV4_MULTICAST_ADDPATH:
    case MRT_TABLE_DUMPV2_RIB_IPV4_UNICAST_ADDPATH:
    case MRT_TABLE_DUMPV2_RIB_IPV6_MULTICAST_ADDPATH:
    case MRT_TABLE_DUMPV2_RIB_IPV6_UNICAST_ADDPATH:
    case MRT_TABLE_DUMPV2_RIB_GENERIC_ADDPATH:
        ribflags |= BGPF_ADDPATH;
        // fallthrough
    case MRT_TABLE_DUMPV2_RIB_IPV4_MULTICAST:
    case MRT_TABLE_DUMPV2_RIB_IPV4_UNICAST:
    case MRT_TABLE_DUMPV2_RIB_IPV6_MULTICAST:
    case MRT_TABLE_DUMPV2_RIB_IPV6_UNICAST:
    case MRT_TABLE_DUMPV2_RIB_GENERIC:
        // every TABLE_DUMPV2 subtype need a peer index
        if (unlikely(!seen_ribpi)) {
            eprintf("%s: warning, TABLE_DUMPV2 RIB with no PEER_INDEX_TABLE, skipping record", filename);
            return PROCESS_BAD;
        }

    case TABLE_DUMP_SUBTYPE_MARKER:
        startribents(NULL);
        while ((rib = nextribent()) != NULL) {
            int res = true;  // assume packet passes
            int must_close_bgp = false;

            // we want to avoid rebuilding a BGP packet in case we don't want to dump it
            // or we don't want to filter it (think about a peer-index dump without any filtering)
            if (format != MRT_NO_DUMP || !istrivialfilter(vm)) {
                vm->kp[K_PEER_AS].as = rib->peer->as;
                memcpy(&vm->kp[K_PEER_ADDR].addr, &rib->peer->addr, sizeof(vm->kp[K_PEER_ADDR].addr));

                if (rib->peer->as_size == sizeof(uint32_t))
                    ribflags |= BGPF_ASN32BIT;

                int err;
                if (ribflags & BGPF_ADDPATH) {
                    netaddrap_t addrap;
                    addrap.pfx    = rib->nlri;
                    addrap.pathid = rib->pathid;

                    err = rebuildbgpfrommrt(&addrap, rib->attrs, rib->attr_length, ribflags);
                } else {
                    err = rebuildbgpfrommrt(&rib->nlri, rib->attrs, rib->attr_length, ribflags);
                }
                if (err != BGP_ENOERR) {
                    report_bad_rib(filename, err, rib);
                    continue;
                }

                must_close_bgp = true;
                res = bgp_filter(vm);
                if (res < 0 && res != VM_BAD_PACKET)
                    exprintf(EXIT_FAILURE, "%s: unexpected filter failure (%s)", filename, filter_strerror(res));
            }

            if (res > 0) {
                refpeeridx(rib->peer_idx);
                if (format != MRT_NO_DUMP) {
                    const char *fmt = (format == MRT_DUMP_ROW) ? "#rF*t" : "#xF*t";

                    printbgp(stdout, fmt, &vm->kp[K_PEER_ADDR].addr, vm->kp[K_PEER_AS].as, rib->originated);
                }
            }

            if (must_close_bgp)
                close_bgp_packet(filename);
        }

        endribents();
        break;

    default:
        // we can only encounter this fot TABLE_DUMPV2 subtypes
        eprintf("%s: unhandled TABLE_DUMPV2 packet of subtype: %#x", filename, (unsigned int) hdr->subtype);
        break;
    }

    return PROCESS_SUCCESS;
}

int mrtprintpeeridx(const char* filename, io_rw_t* rw, filter_vm_t *vm)
{
    int retval = 0;

    seen_ribpi = false;
    pkgseq     = 0;
    memset(peerrefs, 0, sizeof(peerrefs));

    while (true) {
        int err = setmrtreadfrom(rw);
        if (err == MRT_EIO)
            break;

        const mrt_header_t *hdr = getmrtheader();
        if (hdr != NULL && hdr->type == MRT_TABLE_DUMPV2) {
            if (!processtabledump(filename, hdr, vm, MRT_NO_DUMP)) {
                retval = -1;
                goto done;
            }
        }

        err = mrtclose();
        if (unlikely(err != MRT_ENOERR))
            eprintf("%s: corrupted packet: %s", filename, mrtstrerror(err));  // FIXME better reporting
    }

    if (seen_ribpi) {
        mrt_msg_t *peer_index = getmrtpi();
        startpeerents_r(peer_index, NULL);

        peer_entry_t *pe;
        uint16_t idx = 0;
        while ((pe = nextpeerent_r(peer_index))) {
            if (ispeeridxref(idx))
                printpeerent(stdout, pe, "r");

            idx++;
        }

        endpeerents_r(peer_index);
    }

done:

    if (seen_ribpi)
        mrtclosepi();

    if (rw->error(rw)) {
        eprintf("%s: read error or corrupted data, skipping rest of file", filename);
        retval = -1;
    }

    return retval;
}

int mrtprocess(const char *filename, io_rw_t *rw, filter_vm_t *vm, mrt_dump_fmt_t format)
{
    seen_ribpi = false;
    pkgseq     = 0;
    // don't care about peerrefs

    int retval = 0;
    while (true) {
        int err = setmrtreadfrom(rw);
        if (err == MRT_EIO)
            break;

        const mrt_header_t *hdr = getmrtheader();

        process_result_t result = PROCESS_BAD;  // assume bad record unless stated otherwise
        if (hdr != NULL) {
            switch (hdr->type) {
            case MRT_BGP:
                result = processzebra(filename, hdr, vm, format);
                break;

            case MRT_TABLE_DUMP:
            case MRT_TABLE_DUMPV2:
                result = processtabledump(filename, hdr, vm, format);
                break;

            case MRT_BGP4MP:
            case MRT_BGP4MP_ET:
                result = processbgp4mp(filename, hdr, vm, format);
                break;

            default:
                // skip packet, but not necessarily wrong
                eprintf("%s: unhandled MRT packet of type: %#x", filename, (unsigned int) hdr->type);
                result = PROCESS_SUCCESS;
                break;
            }
        }

        err = mrtclose();
        if (unlikely(err != MRT_ENOERR)) {
            eprintf("%s: corrupted packet: %s", filename, mrtstrerror(err));  // FIXME better reporting
            retval = -1;  // propagate this error to the caller
        }
        if (result != PROCESS_SUCCESS)
            retval = -1;  // packet is not well formed, so propagate error to the caller
        if (unlikely(result == PROCESS_CORRUPTED))
            break;        // we must skip the whole packet
    }

    if (seen_ribpi)
        mrtclosepi();

    if (rw->error(rw)) {
        eprintf("%s: read error or corrupted data, skipping rest of file", filename);
        retval = -1;
    }

    return retval;
}
