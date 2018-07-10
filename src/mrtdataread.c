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
    MAX_PEERREF_BITSET_SIZE = UINT16_MAX / (sizeof(unsigned int) * CHAR_BIT)
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

        size_t n;
        const void *data = getbgpdata(&n);

        hexdump(stderr, data, n, "x#|1|80");
        fputc('\n', stderr);
    }

    bgpclose();
    return err;
}

static void report_bad_rib(const char *filename, int err, const rib_header_t *ribhdr, const rib_entry_t *rib)
{
    eprintf("%s: bad RIB entry for NLRI %s (%s)", filename, naddrtos(&ribhdr->nlri, NADDR_CIDR), bgpstrerror(err));
    fprintf(stderr, "attributes segment dump follows:\n");
    hexdump(stderr, rib->attrs, rib->attr_length, "x#|1|80");
    fputc('\n', stderr);
}

static int processbgp4mp(const char *filename, const mrt_header_t *hdr, filter_vm_t *vm)
{
    size_t n;
    void *data;

    const bgp4mp_header_t *bgphdr = getbgp4mpheader();
    if (unlikely(!bgphdr)) {
        eprintf("%s: corrupted BGP4MP header (%s)", filename, mrtstrerror(mrterror()));
        return false;
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
        if (res > 0)
            printbgp(stdout, "F*T", &vm->kp[K_PEER_ADDR].addr, vm->kp[K_PEER_AS].as, &hdr->stamp);

        err = close_bgp_packet(filename);
        break;

    default:
        eprintf("%s: unhandled BGP4MP packet of subtype: %#x", filename, (unsigned int) hdr->subtype);
        break;
    }

    if (unlikely(err != BGP_ENOERR))
        return false;

    return true;
}

static int istrivialfilter(filter_vm_t *vm)
{
    return vm->codesiz == 1 && vm->code[0] == vm_makeop(FOPC_LOAD, true);
}

enum {
    DONT_DUMP_RIBS,
    DUMP_RIBS
};

static void refpeeridx(uint16_t idx)
{
    peerrefs[idx >> PEERREF_SHIFT] |= 1 << (idx & PEERREF_MASK);
}

static int ispeeridxref(uint16_t idx)
{
    return peerrefs[idx >> PEERREF_SHIFT] & (1 << (idx & PEERREF_MASK));
}

static int processtabledumpv2(const char *filename, const mrt_header_t *hdr, filter_vm_t *vm, int mode)
{
    const rib_header_t *ribhdr;
    const rib_entry_t *rib;

    int ribflags = BGPF_GUESSMRT | BGPF_STRIPUNREACH;
    switch (hdr->subtype) {
    case MRT_TABLE_DUMPV2_PEER_INDEX_TABLE:
        if (unlikely(seen_ribpi)) {
            eprintf("%s: bad RIB dump, duplicated TABLE_DUMPV2_PEER_INDEX_TABLE, skipping rest of file", filename);
            return false;
        }
        if (unlikely(pkgseq != 0))
            eprintf("%s: warning, TABLE_DUMPV2_PEER_INDEX_TABLE is not the first record in file", filename);

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
        ribhdr = startribents(NULL);
        while ((rib = nextribent()) != NULL) {
            int res = true;  // assume packet passes
            int must_close_bgp = false;

            // we want to avoid rebuilding a BGP packet in case we don't want to dump it
            // or we don't want to filter it (think about a peer-index dump without any filtering)
            if (mode == DUMP_RIBS || !istrivialfilter(vm)) {
                vm->kp[K_PEER_AS].as = rib->peer->as;
                memcpy(&vm->kp[K_PEER_ADDR].addr, &rib->peer->addr, sizeof(vm->kp[K_PEER_ADDR].addr));

                if (rib->peer->as_size == sizeof(uint32_t))
                    ribflags |= BGPF_ASN32BIT;

                int err;
                if (ribflags & BGPF_ADDPATH) {
                    netaddrap_t addrap;
                    addrap.pfx    = ribhdr->nlri;
                    addrap.pathid = rib->pathid;

                    err = rebuildbgpfrommrt(&addrap, rib->attrs, rib->attr_length, ribflags);
                } else {
                    err = rebuildbgpfrommrt(&ribhdr->nlri, rib->attrs, rib->attr_length, ribflags);
                }
                if (err != BGP_ENOERR) {
                    report_bad_rib(filename, err, ribhdr, rib);
                    continue;
                }

                must_close_bgp = true;
                res = bgp_filter(vm);
                if (res < 0 && res != VM_BAD_PACKET)
                    exprintf(EXIT_FAILURE, "%s: unexpected filter failure (%s)", filename, filter_strerror(res));
            }

            if (res > 0) {
                refpeeridx(rib->peer_idx);
                if (mode == DUMP_RIBS)
                    printbgp(stdout, "#F*t", &vm->kp[K_PEER_ADDR].addr, vm->kp[K_PEER_AS].as, rib->originated);
            }

            if (must_close_bgp)
                close_bgp_packet(filename);
        }

        endribents();
        break;

    default:
        eprintf("%s: unhandled TABLE_DUMPV2 packet of subtype: %#x", filename, (unsigned int) hdr->subtype);
        break;
    }

    return true;
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
            if (!processtabledumpv2(filename, hdr, vm, DONT_DUMP_RIBS)) {
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

int mrtprocess(const char *filename, io_rw_t *rw, filter_vm_t *vm)
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
        if (hdr != NULL) {
            switch (hdr->type) {
            case MRT_TABLE_DUMPV2:
                if (!processtabledumpv2(filename, hdr, vm, DUMP_RIBS)) {
                    retval = -1;
                    goto done;
                }

                break;

            case MRT_BGP4MP:
            case MRT_BGP4MP_ET:
                if (!processbgp4mp(filename, hdr, vm)) {
                    retval = -1;
                    goto done;
                }

                break;

            default:
                // skip packet
                break;
            }
        }


        err = mrtclose();
        if (unlikely(err != MRT_ENOERR))
            eprintf("%s: corrupted packet: %s", filename, mrtstrerror(err));  // FIXME better reporting
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
