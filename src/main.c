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
#include <fcntl.h>
#include <isolario/bits.h>
#include <isolario/filterintrin.h>
#include <isolario/filterpacket.h>
#include <isolario/branch.h>
#include <isolario/netaddr.h>
#include <isolario/parse.h>
#include <isolario/patriciatrie.h>
#include <isolario/progutil.h>
#include <isolario/strutil.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mrtdataread.h"

static void usage(void)
{
    fprintf(stderr, "%s: The Isolario MRT data reader utility\n", programnam);
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "\t%s [-d] [-p PATHEXPR] [-i ADDR] [-I FILE] [-a AS] [-A FILE] [-e PREFIX] [-E FILE] [-o FILE] [FILE...]\n", programnam);
    fprintf(stderr, "\t%s [-d] [-p PATHEXPR] [-i ADDR] [-I FILE] [-a AS] [-A FILE] [-s PREFIX] [-S FILE] [-o FILE] [FILE...]\n", programnam);
    fprintf(stderr, "\t%s [-d] [-p PATHEXPR] [-i ADDR] [-I FILE] [-a AS] [-A FILE] [-u PREFIX] [-U FILE] [-o FILE] [FILE...]\n", programnam);
    fprintf(stderr, "\t%s [-d] [-p PATHEXPR] [-i ADDR] [-I FILE] [-a AS] [-A FILE] [-r PREFIX] [-R FILE] [-o FILE] [FILE...]\n", programnam);
    fprintf(stderr, "\n");
    fprintf(stderr, "Available options:\n");
    fprintf(stderr, "\t-a <feeder AS>\n");
    fprintf(stderr, "\t\tPrint only entries coming from the given feeder AS\n");
    fprintf(stderr, "\t-A <file>\n");
    fprintf(stderr, "\t\tPrint only entries coming from the feeder ASes contained in file\n");
    fprintf(stderr, "\t-d\n");
    fprintf(stderr, "\t\tDump packet filter bytecode to stderr (debug option)\n");
    fprintf(stderr, "\t-e <subnet>\n");
    fprintf(stderr, "\t\tPrint only entries containing the exact given subnet of interest\n");
    fprintf(stderr, "\t-E <file>\n");
    fprintf(stderr, "\t\tPrint only entries containing the exact subnets of interest contained in file\n");
    fprintf(stderr, "\t-f\n");
    fprintf(stderr, "\t\tPrint only every feeder IP in the RIB provided\n");
    fprintf(stderr, "\t-i <feeder IP>\n");
    fprintf(stderr, "\t\tPrint only entries coming from a given feeder IP\n");
    fprintf(stderr, "\t-I <file>\n");
    fprintf(stderr, "\t\tPrint only entries coming from the feeder IP contained in file\n");
    fprintf(stderr, "\t-l\n");
    fprintf(stderr, "\t\tPrint only entries with a loop in its AS PATH\n");
    fprintf(stderr, "\t-L\n");
    fprintf(stderr, "\t\tPrint only entries without a loop in its AS PATH\n");
    fprintf(stderr, "\t-o <file>\n");
    fprintf(stderr, "\t\tDefine the output file to store information (defaults to stdout)\n");
    fprintf(stderr, "\t-p <path expression>\n");
    fprintf(stderr, "\t\tPrint only entries which AS PATH matches the expression\n");
    fprintf(stderr, "\t-P <path expression>\n");
    fprintf(stderr, "\t\tPrint only entries which AS PATH does not match the expression\n");
    fprintf(stderr, "\t-r <subnet>\n");
    fprintf(stderr, "\t\tPrint only entries containing subnets related to the given subnet of interest\n");
    fprintf(stderr, "\t-R <file>\n");
    fprintf(stderr, "\t\tPrint only entries containing subnets related to the subnets of interest contained in file\n");
    fprintf(stderr, "\t-s <subnet>\n");
    fprintf(stderr, "\t\tPrint only entries containing subnets included to the given subnet of interest\n");
    fprintf(stderr, "\t-S <file>\n");
    fprintf(stderr, "\t\tPrint only entries containing subnets included to the subnets of interest contained in file\n");
    fprintf(stderr, "\t-u <subnet>\n");
    fprintf(stderr, "\t\tPrint only entries containing subnets including (or equal) to the given subnet of interest\n");
    fprintf(stderr, "\t-U <file>\n");
    fprintf(stderr, "\t\tPrint only entries containing subnets including (or equal) to the subnets of interest contained in file\n");
    exit(EXIT_FAILURE);
}

enum {
    DBG_DUMP            = 1 << 0,
    ONLY_PEERS          = 1 << 1,
    MATCH_AS_PATH       = 1 << 2,
    FILTER_BY_PEER_ADDR = 1 << 3,
    FILTER_BY_PEER_AS   = 1 << 4,
    FILTER_EXACT        = 1 << 5,
    FILTER_RELATED      = 1 << 6,
    FILTER_BY_SUBNET    = 1 << 7,
    FILTER_BY_SUPERNET  = 1 << 8,
    KEEP_AS_LOOPS       = 1 << 9,
    DISCARD_AS_LOOPS    = 1 << 10,

    FILTER_MASK  = (FILTER_EXACT | FILTER_RELATED | FILTER_BY_SUBNET | FILTER_BY_SUPERNET),
    AS_LOOP_MASK = KEEP_AS_LOOPS | DISCARD_AS_LOOPS
};

enum {
    ADDRS_GROWSTEP = 128,
    ASES_GROWSTEP  = 256
};

static filter_vm_t vm;
static int flags             = 0;
static int trie_idx          = -1;
static int trie6_idx         = -1;
static uint32_t *peer_ases   = NULL;
static int ases_count        = 0;
static int ases_siz          = 0;
static netaddr_t *peer_addrs = NULL;
static int addrs_count       = 0;
static int addrs_siz         = 0;

typedef struct as_path_match_s {
    struct as_path_match_s *or_next;  // next match in OR-ed chain
    struct as_path_match_s *and_next; // next match in AND chain

    bytecode_t opcode;
    int kidx;
    bool neg;
} as_path_match_t;

static as_path_match_t *path_match_head = NULL;
static as_path_match_t *path_match_tail = NULL;

static noreturn void naddr_parse_error(const char *name, unsigned int lineno, const char *msg, void *data)
{
    (void) data;

    exprintf(EXIT_FAILURE, "%s:%u: %s", name, lineno, msg);
}

static int add_trie_address(const char *s)
{
    netaddr_t addr;

    if (stonaddr(&addr, s) != 0)
        return false;

    void *node;
    if (addr.family == AF_INET)
        node = patinsertn(&vm.tries[trie_idx], &addr, NULL);
    else
        node = patinsertn(&vm.tries[trie6_idx], &addr, NULL);

    if (!node)
        exprintf(EXIT_FAILURE, "out of memory");

    return true;
}

static int add_peer_as(const char *s)
{
    char *end;

    long long as = strtoll(s, &end, 10);
    if (*end != '\0' || s == end)
        return false;
    if (as < 0 || as > UINT32_MAX)
        return false;

    if (unlikely(ases_count == ases_siz)) {
        ases_siz += ASES_GROWSTEP;

        peer_ases = realloc(peer_ases, ases_siz * sizeof(*peer_ases));
        if (unlikely(!peer_ases))
            exprintf(EXIT_FAILURE, "out of memory");
    }

    peer_ases[ases_count++] = (uint32_t) as;
    return true;
}

static int add_peer_address(const char *s)
{
    netaddr_t addr;
    if (inet_pton(AF_INET6, s, &addr.sin6) > 0) {
        addr.family = AF_INET6;
        addr.bitlen = 128;
    } else if (inet_pton(AF_INET, s, &addr.sin) > 0) {
        addr.family = AF_INET;
        addr.bitlen = 32;
    } else {
        return false;
    }

    if (unlikely(addrs_count == addrs_siz)) {
        addrs_siz += ADDRS_GROWSTEP;

        peer_addrs = realloc(peer_addrs, addrs_siz * sizeof(*peer_addrs));
        if (unlikely(!peer_addrs))
            exprintf(EXIT_FAILURE, "out of memory");
    }

    peer_addrs[addrs_count++] = addr;
    return true;
}

static void parse_file(const char *filename, int (*read_callback)(const char *))
{
    FILE *f = fopen(filename, "r");
    if (!f)
        exprintf(EXIT_FAILURE, "cannot open '%s':", filename);

    setperrcallback(naddr_parse_error);
    startparsing(filename, 1, NULL);

    char *tok;
    while ((tok = parse(f)) != NULL) {
        if (!read_callback(tok))
            parsingerr("bad address: %s", tok);
    }

    setperrcallback(NULL);

    if (fclose(f) != 0)
        exprintf(EXIT_FAILURE, "read error while parsing: %s:", filename);
}

static void mrt_accumulate_addrs(filter_vm_t *vm)
{
    for (int i = 0; i < addrs_count; i++)
        vm_pushaddr(vm, &peer_addrs[i]);
}

static void mrt_accumulate_ases(filter_vm_t *vm)
{
    for (int i = 0; i < ases_count; i++)
        vm_pushas(vm, peer_ases[i]);
}

enum {
    ASPATHSIZ = 32
};

static void mrt_find_as_loops(filter_vm_t *vm)
{

    vm_exec_settle(vm);  // force iterators settle (not really necessary... but whatever)

    int max        = 0;
    int n          = 0;
    intptr_t vaddr = 0;
    uint32_t *path = NULL;

    startrealaspath_r(vm->bgp);

    as_pathent_t *ent;
    while ((ent = nextaspath_r(vm->bgp)) != NULL) {
        if (unlikely(n == max)) {
            max += ASPATHSIZ;

            vaddr = vm_heap_grow(vm, vaddr, max * sizeof(*path));
            if (unlikely(vaddr == VM_BAD_HEAP_PTR))
                vm_abort(vm, VM_OUT_OF_MEMORY);

            path = vm_heap_ptr(vm, vaddr);  // update pointer
        }
        path[n++] = ent->as;
    }

    if (endaspath_r(vm->bgp) != BGP_ENOERR)
        vm_abort(vm, VM_BAD_PACKET);

    int has_loop = false;
    for (int i = 2; i < n - 1 && !has_loop; i++) {
        if (path[i] == path[i - 1])
            continue;  // prepending
        if (path[i] == AS_TRANS)
            continue;

        for (int j = 0; j < i - 2; j++) {
            if (path[j] == path[i] && path[j] != AS_TRANS) {
                has_loop = true;
                break;
            }
        }
    }

    vm_heap_return(vm, max * sizeof(*path));  // don't need temporary memory anymore

    vm_pushvalue(vm, has_loop);
}

static void setup_filter(void)
{
    if (flags & FILTER_BY_PEER_AS) {
        vm_emit(&vm, vm_makeop(FOPC_CALL, MRT_ACCUMULATE_ASES_FN));
        vm_emit(&vm, vm_makeop(FOPC_ASCONTAINS, K_PEER_AS));
        vm_emit(&vm, FOPC_NOT);
        vm_emit(&vm, FOPC_CFAIL);
    }
    if (flags & FILTER_BY_PEER_ADDR) {
        vm_emit(&vm, vm_makeop(FOPC_CALL, MRT_ACCUMULATE_ADDRS_FN));
        vm_emit(&vm, vm_makeop(FOPC_ADDRCONTAINS, K_PEER_ADDR));
        vm_emit(&vm, FOPC_NOT);
        vm_emit(&vm, FOPC_CFAIL);
    }

    if (path_match_head) {
        // include the AS PATH filtering logic
        vm_emit(&vm, FOPC_BLK);
        for (as_path_match_t *i = path_match_head; i; i = i->or_next) {
            // compile the AND chain
            vm_emit(&vm, FOPC_BLK);
            for (as_path_match_t *j = i; j; j = j->and_next) {
                int access = FOPC_ACCESS_REAL_AS_PATH;
                if (j == i)
                    access |= FOPC_ACCESS_SETTLE; // rewind the AS PATH on first test

                vm_emit(&vm, vm_makeop(FOPC_LOADK, j->kidx));
                vm_emit(&vm, FOPC_UNPACK);
                vm_emit(&vm, vm_makeop(j->opcode, access));
                if (j->and_next) {  // omit the last AND term for optimization
                    vm_emit(&vm, FOPC_NOT);
                    vm_emit(&vm, FOPC_CFAIL);
                }
            }
            vm_emit(&vm, FOPC_ENDBLK);
            if (i->neg)
                vm_emit(&vm, FOPC_NOT);

            if (i->or_next)
                vm_emit(&vm, FOPC_CPASS);
            /*
            if (i->or_next) {                // omit the conditional on last OR term
                vm_emit(&vm, FOPC_CPASS);  // if the block was successful, the entire OR succeeded
            }*/
        }

        vm_emit(&vm, FOPC_ENDBLK);
        // must fail if none of the OR clauses was satisfied
        vm_emit(&vm, FOPC_NOT);
        vm_emit(&vm, FOPC_CFAIL);
    }

    if (flags & FILTER_MASK) {
        // only one filter may be set (otherwise it's an option conflict)
        vm_emit(&vm, vm_makeop(FOPC_SETTRIE,  trie_idx));
        vm_emit(&vm, vm_makeop(FOPC_SETTRIE6, trie6_idx));

        bytecode_t opcode;
        if (flags & FILTER_EXACT)
            opcode = FOPC_EXACT;
        if (flags & FILTER_RELATED)
            opcode = FOPC_RELATED;
        if (flags & FILTER_BY_SUBNET)
            opcode = FOPC_SUBNET;
        if (flags & FILTER_BY_SUPERNET)
            opcode = FOPC_SUPERNET;

        vm_emit(&vm, FOPC_BLK);
        vm_emit(&vm, vm_makeop(opcode, FOPC_ACCESS_SETTLE | FOPC_ACCESS_ALL | FOPC_ACCESS_NLRI));
        vm_emit(&vm, FOPC_CPASS);
        vm_emit(&vm, vm_makeop(opcode, FOPC_ACCESS_SETTLE | FOPC_ACCESS_ALL | FOPC_ACCESS_WITHDRAWN));
        vm_emit(&vm, FOPC_ENDBLK);
        vm_emit(&vm, FOPC_NOT);
        vm_emit(&vm, FOPC_CFAIL);
    }
    if (flags & AS_LOOP_MASK) {
        // also call the AS loop filtering logic...
        vm_emit(&vm, vm_makeop(FOPC_CALL, MRT_FIND_AS_LOOPS_FN));
        if (flags & KEEP_AS_LOOPS)
            vm_emit(&vm, FOPC_NOT);

        vm_emit(&vm, FOPC_CFAIL);
    }
    vm_emit(&vm, vm_makeop(FOPC_LOAD, true));
}

static int iswildcard(char c)
{
    return c == '*' || c == '?';
}

static int isdelim(char c)
{
    return isspace((unsigned char) c) || c == '$' || c == '\0' || c == '^';
}

static char *skip_spaces(const char* ptr)
{
    while (isspace((unsigned char) *ptr)) ptr++;

    return (char*) ptr;
}

static void parse_as_match_expr(const char *expr, bool negate)
{
    int opcode = FOPC_ASPMATCH;

    wide_as_t buf[strlen(expr) / 2 + 1];  // wild upperbound

    const char *ptr = skip_spaces(expr);
    if (*ptr == '^') {
        opcode = FOPC_ASPSTARTS;
        ptr = skip_spaces(ptr + 1);
    }

    as_path_match_t *expr_head = NULL;
    as_path_match_t *expr_tail = NULL;
    while (true) {
        // parse an AS match expressions, expressions are ANDed such as "^1 2 3 * 4 ? ? 5 6 * 7$"

        int count = 0;
        while (true) {
            // this splits the full expressions into subexpressions
            // ptr *DOES NOT* reference a space here!
            errno = 0;

            if (*ptr == '\0')
                break;  // we're done
            if (iswildcard(*ptr) && !isdelim(*(ptr + 1)))
                exprintf(EXIT_FAILURE, "%s: wildcard '%c' must be delimiter separated", expr, *ptr);

            if (*ptr == '*') {
                // flush operations at this point
                ptr = skip_spaces(ptr + 1);
                break;
            }

            long long as;
            if (*ptr == '?') {
                as = AS_ANY;
                ptr++;
            } else {
                char* eptr;

                as = strtoll(ptr, &eptr, 10);
                if (ptr == eptr) {
                    int len = ptr - expr;
                    const char *at = expr;
                    if (len == 0) {
                        at = "[expression start]";
                        len = strlen(at);
                    }

                    exprintf(EXIT_FAILURE, "%s: expecting AS number after: '%.*s'", expr, len, at);
                }
                if (as < 0 || as > UINT32_MAX)
                    errno = ERANGE;
                if (errno != 0)
                    exprintf(EXIT_FAILURE, "%s: AS number '%lld':", expr, as);

                ptr = eptr;
            }

            // buffer the AS
            buf[count++] = as;
            // ... and position to the next token
            ptr = skip_spaces(ptr);

            if (*ptr == '$') {
                opcode = (opcode == FOPC_ASPSTARTS) ? FOPC_ASPEXACT : FOPC_ASPENDS;
                ptr = skip_spaces(ptr + 1);
                if (*ptr != '\0')
                    exprintf(EXIT_FAILURE, "%s: expecting expression end after '$'", expr);
            }
        }

        if (count == 0) {
            if (*ptr == '$')
                break; // expression with a terminating ?

            exprintf(EXIT_FAILURE, "empty AS match expression");
        }

        // parsed one match, add it to the AND chain of the current expression
        // we'll compile it to bytecode later
        as_path_match_t *match = malloc(sizeof(*match));
        if (unlikely(!match))
            exprintf(EXIT_FAILURE, "out of memory");

        // populate AS match subexpression
        match->opcode = opcode;
        // add the AS path segment to VM heap
        intptr_t heapptr = vm_heap_alloc(&vm, count * sizeof(*buf), VM_HEAP_PERM);
        if (unlikely(heapptr == VM_BAD_HEAP_PTR))
            exprintf(EXIT_FAILURE, "out of memory");

        memcpy(vm_heap_ptr(&vm, heapptr), buf, count * sizeof(*buf));

        // generate a K constant with the heap array address
        int kidx = vm_newk(&vm);

        vm.kp[kidx].base  = heapptr;
        vm.kp[kidx].elsiz = sizeof(*buf);
        vm.kp[kidx].nels  = count;

        match->kidx = kidx;
        match->neg = negate;
        
        match->or_next = NULL;
        if (expr_tail)
            expr_tail->and_next = match;
        else
            expr_head = match;

        expr_tail = match;

        if (*ptr == '\0')
            break;  // done parsing the entire OR-chain

        // reset match semantics:
        opcode = FOPC_ASPMATCH;
    }

    // add to the global OR chain, in case more expressions are provided
    if (path_match_tail)
        path_match_tail->or_next = expr_head;
    else
        path_match_head = expr_head;

    path_match_tail = expr_head;
}

int main(int argc, char **argv)
{
    int c;
    setprogramnam(argv[0]);

    // setup VM environment
    filter_init(&vm);

    trie_idx  = vm_newtrie(&vm, AF_INET);
    trie6_idx = vm_newtrie(&vm, AF_INET6);

    vm.funcs[MRT_ACCUMULATE_ADDRS_FN] = mrt_accumulate_addrs;
    vm.funcs[MRT_ACCUMULATE_ASES_FN]  = mrt_accumulate_ases;
    vm.funcs[MRT_FIND_AS_LOOPS_FN] = mrt_find_as_loops;

    // parse command line
    while ((c = getopt(argc, argv, "A:a:dE:e:fi:I:lLo:p:P:R:r:S:s:U:u:")) != -1) {
        switch (c) {
        case 'a':
            if (!add_peer_as(optarg))
                exprintf(EXIT_FAILURE, "'%s': bad AS number", optarg);

            flags |= FILTER_BY_PEER_AS;
            break;

        case 'A':
            parse_file(optarg, add_peer_as);
            flags |= FILTER_BY_PEER_AS;
            break;

        case 'd':
            flags |= DBG_DUMP;
            break;

        case 'o':
            if (!freopen(optarg, "w", stdout))
                exprintf(EXIT_FAILURE, "cannot open '%s':", optarg);

            break;

        case 'f':
            flags |= ONLY_PEERS;
            break;

        case 'E':
        case 'U':
        case 'R':
        case 'S':
            if (c == 'E')
                flags |= FILTER_EXACT;
            if (c == 'U')
                flags |= FILTER_BY_SUPERNET;
            if (c == 'R')
                flags |= FILTER_RELATED;
            if (c == 'S')
                flags |= FILTER_BY_SUBNET;

            if (bitpopcnt(flags & FILTER_MASK) != 1)
                exprintf(EXIT_FAILURE, "conflicting options in filter");

            parse_file(optarg, add_trie_address);
            break;

        case 'e':
        case 'u':
        case 'r':
        case 's':
            if (c == 'e')
                flags |= FILTER_EXACT;
            if (c == 'u')
                flags |= FILTER_BY_SUPERNET;
            if (c == 'r')
                flags |= FILTER_RELATED;
            if (c == 's')
                flags |= FILTER_BY_SUBNET;

            if (bitpopcnt(flags & FILTER_MASK) != 1)
                exprintf(EXIT_FAILURE, "conflicting options in filter");

            if (!add_trie_address(optarg))
                exprintf(EXIT_FAILURE, "bad address: %s", optarg);

            break;

        case 'p':
            parse_as_match_expr(optarg, false);
            break;

        case 'P':
            parse_as_match_expr(optarg, true);
            break;

        case 'i':
            if (!add_peer_address(optarg))
                exprintf(EXIT_FAILURE, "'%s': bad peer address", optarg);

            flags |= FILTER_BY_PEER_ADDR;
            break;

        case 'I':
            parse_file(optarg, add_peer_address);
            flags |= FILTER_BY_PEER_ADDR;
            break;

        case 'l':
            flags &= ~DISCARD_AS_LOOPS;
            flags |= KEEP_AS_LOOPS;
            break;

        case 'L':
            flags &= ~KEEP_AS_LOOPS;
            flags |= DISCARD_AS_LOOPS;
            break;

        case '?':
        default:
            usage();
            break;
        }
    }

    setup_filter();
    if (flags & DBG_DUMP)
        filter_dump(stderr, &vm);

    if (optind == argc) {
        // no file arguments, process stdin
        // we apply an innocent trick to simulate a "-" argument
        // NOTE argv will *NOT* be NULL terminated anymore
        argv[argc] = "-";
        argc++;
    }

    // apply to required files
    int nerrors = 0;
    for (int i = optind; i < argc; i++) {
        io_rw_t io;
        int fd;

        io_rw_t *iop = NULL;

        char *ext = strpathext(argv[i]);
        if (strcasecmp(ext, ".gz") == 0 || strcasecmp(ext, ".z") == 0) {
            fd = open(argv[i], O_RDONLY);
            if (fd >= 0)
                iop = io_zopen(fd, BUFSIZ, "r");

        } else if (strcasecmp(ext, ".bz2") == 0) {
            fd = open(argv[i], O_RDONLY);
            if (fd >= 0)
                iop = io_bz2open(fd, BUFSIZ, "r");

        } else if (strcasecmp(ext, ".xz") == 0) {
            fd = open(argv[i], O_RDONLY);
            if (fd >= 0)
                iop = io_xzopen(fd, BUFSIZ, "r");

        } else if (strcmp(argv[i], "-") == 0) {
            io_file_init(&io, stdin);
            iop = &io;
            fd = STDIN_FILENO;

            // rename argument to (stdin) to improve logging quality
            argv[i] = "(stdin)";
        } else {
            FILE *file = fopen(argv[i], "rb");

            fd = -1;
            if (file) {
                io_file_init(&io, file);
                iop = &io;

                fd = fileno(file);
            }
        }

        if (fd == -1) {
            eprintf("cannot open '%s':", argv[i]);
            nerrors++;
            continue;
        }
        if (!iop) {
            eprintf("'%s': not a valid %s file", argv[i], ext);
            nerrors++;
            continue;
        }

        if (fd != STDIN_FILENO)
            posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);

        int res;
        if (flags & ONLY_PEERS)
            res = mrtprintpeeridx(argv[i], iop, &vm);
        else
            res = mrtprocess(argv[i], iop, &vm);

        if (res != 0)
            nerrors++;

        if (fd != STDIN_FILENO)
            iop->close(iop);
    }

    // cleanup and exit
    filter_destroy(&vm);
    free(peer_ases);
    free(peer_addrs);
    while (path_match_head) {
        as_path_match_t *t = path_match_head;
        while (t->and_next) {
            as_path_match_t *tn = t->and_next;

            t->and_next = tn->and_next;
            free(tn);
        }

        path_match_head = t->or_next;

        free(t);
    }

    if (fflush(stdout) != 0)
        exprintf(EXIT_FAILURE, "could not write to output file:");

    return (nerrors == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
