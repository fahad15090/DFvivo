/*
 * DFvivo stage-2 libc++ hook blob (GPL-2.0, derived from DFRoot libcxx.S).
 *
 * This initial build is the phase-1 TRIGGER PROBE: it proves the vivo init
 * adoption trigger works. Semantics:
 *
 *   The patcher rewrites the first instruction of the hooked libc++ function
 *   (std::ostream::sentry ctor for basic_ostream<char>) to branch here. The
 *   trampoline we overwrite preserves everything, so the hooked caller
 *   (init's main thread, uid 0 / tid 1) runs this blob synchronously inside
 *   its own context.
 *
 *   The blob:
 *     1. saves volatile regs + x30
 *     2. exits unless uid == 0
 *     3. exits unless tid == 1   (init's main thread only)
 *     4. one-shot guard: openat(AT_FDCWD, "/dev/dfd",
 *                              O_CREAT|O_EXCL|O_CLOEXEC, 0)
 *        - success  => close(fd) and fall through (proves the trigger fired)
 *        - EEXIST   => we already ran; fall through to restore (no-ops)
 *        - negative => return
 *     5. restores regs, executes the stolen first instruction, jumps back to
 *        hook_off + 4 — the caller's execution is undisturbed.
 */
    .arch armv8-a

    .include "include.inc"

    .global libcxx_start
    .global libcxx_data
    .global libcxx_len
    .global libcxx_first_inst_copy

    .data

libcxx_data:

marker_path:
    .asciz "/dev/dfd"
    .balign 4

    .align 4

libcxx_start:
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!
    stp x4, x5, [sp, #-16]!
    stp x6, x7, [sp, #-16]!
    stp x8, x9, [sp, #-16]!
    stp x26, x27, [sp, #-16]!
    stp x28, x29, [sp, #-16]!
    str x30, [sp, #-16]!

    // guard: must be running in uid 0 context (init main thread)
    mov     x8, SYS_getuid
    svc     0
    cbnz    w0, return

    // guard: main thread of init (tid == 1)
    mov     x8, SYS_gettid
    svc     0
    cmp     w0, 1
    bne     return

    // create marker file /dev/dfd — one-shot evidence the trigger fired
    // with uid 0 / tid 1. Also acts as the "already patched" mutex so
    // subsequent calls are cheap no-ops.
    mov     x0, -100
    adr     x1, marker_path
    movl    x2, (O_CREAT|O_EXCL|O_CLOEXEC)
    mov     x3, xzr
    mov     x8, #SYS_openat
    svc     0

    tbnz    w0, #31, return          // open failed — already there or denied

    // success: close the marker
    mov     x8, #SYS_close
    svc     0

return:
    ldr x30, [sp], #16
    ldp x28, x29, [sp], #16
    ldp x26, x27, [sp], #16
    ldp x8, x9, [sp], #16
    ldp x6, x7, [sp], #16
    ldp x4, x5, [sp], #16
    ldp x2, x3, [sp], #16
    ldp x0, x1, [sp], #16

libcxx_first_inst_copy:
    nop
    b       end

end:

libcxx_end:

libcxx_len:
    .word libcxx_end - libcxx_data
