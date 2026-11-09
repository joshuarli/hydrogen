#include <unix_internal.h>
#include <seccomp.h>
#define BPF_LD_C 0x00
#define BPF_LDX_C 0x01
#define BPF_ST_C 0x02
#define BPF_STX_C 0x03
#define BPF_ALU_C 0x04
#define BPF_JMP_C 0x05
#define BPF_RET_C 0x06
#define BPF_MISC_C 0x07
#define BPF_W_C 0x00
#define BPF_H_C 0x08
#define BPF_B_C 0x10
#define BPF_IMM_C 0x00
#define BPF_ABS_C 0x20
#define BPF_IND_C 0x40
#define BPF_MEM_C 0x60
#define BPF_LEN_C 0x80
#define BPF_MSH_C 0xa0
#define BPF_ADD_OP 0x00
#define BPF_SUB_OP 0x10
#define BPF_MUL_OP 0x20
#define BPF_DIV_OP 0x30
#define BPF_OR_OP 0x40
#define BPF_AND_OP 0x50
#define BPF_LSH_OP 0x60
#define BPF_RSH_OP 0x70
#define BPF_NEG_OP 0x80
#define BPF_MOD_OP 0x90
#define BPF_XOR_OP 0xa0
#define BPF_JA_OP 0x00
#define BPF_JEQ_OP 0x10
#define BPF_JGT_OP 0x20
#define BPF_JGE_OP 0x30
#define BPF_JSET_OP 0x40
#define BPF_K_C 0x00
#define BPF_X_C 0x08
#define BPF_A_C 0x10
#define BPF_TAX_C 0x00
#define BPF_TXA_C 0x80
#define BPF_CODE(c, s, m) ((c) | (s) | (m))
#define CODE_LD_W_ABS BPF_CODE(BPF_LD_C, BPF_W_C, BPF_ABS_C)
#define CODE_LD_W_LEN BPF_CODE(BPF_LD_C, BPF_W_C, BPF_LEN_C)
#define CODE_LDX_W_LEN BPF_CODE(BPF_LDX_C, BPF_W_C, BPF_LEN_C)
#define CODE_LD_IMM BPF_CODE(BPF_LD_C, BPF_W_C, BPF_IMM_C)
#define CODE_LDX_IMM BPF_CODE(BPF_LDX_C, BPF_W_C, BPF_IMM_C)
#define CODE_LD_MEM BPF_CODE(BPF_LD_C, BPF_W_C, BPF_MEM_C)
#define CODE_LDX_MEM BPF_CODE(BPF_LDX_C, BPF_W_C, BPF_MEM_C)
#define CODE_ST BPF_ST_C
#define CODE_STX BPF_STX_C
#define CODE_MISC_TAX BPF_CODE(BPF_MISC_C, 0, BPF_TAX_C)
#define CODE_MISC_TXA BPF_CODE(BPF_MISC_C, 0, BPF_TXA_C)
#define CODE_RET_K BPF_CODE(BPF_RET_C, 0, BPF_K_C)
#define CODE_RET_A BPF_CODE(BPF_RET_C, 0, BPF_A_C)
#define CODE_JA BPF_CODE(BPF_JMP_C, 0, BPF_JA_OP)
#define CODE_JEQ_K BPF_CODE(BPF_JMP_C, BPF_K_C, BPF_JEQ_OP)
#define CODE_JEQ_X BPF_CODE(BPF_JMP_C, BPF_X_C, BPF_JEQ_OP)
#define CODE_JGT_K BPF_CODE(BPF_JMP_C, BPF_K_C, BPF_JGT_OP)
#define CODE_JGT_X BPF_CODE(BPF_JMP_C, BPF_X_C, BPF_JGT_OP)
#define CODE_JGE_K BPF_CODE(BPF_JMP_C, BPF_K_C, BPF_JGE_OP)
#define CODE_JGE_X BPF_CODE(BPF_JMP_C, BPF_X_C, BPF_JGE_OP)
#define CODE_JSET_K BPF_CODE(BPF_JMP_C, BPF_K_C, BPF_JSET_OP)
#define CODE_JSET_X BPF_CODE(BPF_JMP_C, BPF_X_C, BPF_JSET_OP)
#define CODE_ALU_NEG BPF_CODE(BPF_ALU_C, 0, BPF_NEG_OP)
closure_func_basic(thunk, void, seccomp_filter_free_cfn)
{
    seccomp_filter f = struct_from_closure(seccomp_filter, free);
    heap h = heap_locked(get_kernel_heaps());
    u64 size = sizeof(*f) + (u64)f->len * sizeof(struct sock_filter);
    seccomp_filter prev = f->prev;
    deallocate(h, f, size);
    if (prev)
        seccomp_release(prev);
}
void seccomp_reserve(seccomp_filter f)
{
    if (f)
        refcount_reserve(&f->refcount);
}
void seccomp_release(seccomp_filter f)
{
    if (f)
        refcount_release(&f->refcount);
}
u32 seccomp_filter_count(seccomp_filter f)
{
    u32 n = 0;
    while (f) {
        n++;
        f = f->prev;
    }
    return n;
}
static boolean seccomp_action_known(u32 action)
{
    switch (action) {
    case SECCOMP_RET_KILL_PROCESS:
    case SECCOMP_RET_KILL_THREAD:
    case SECCOMP_RET_TRAP:
    case SECCOMP_RET_ERRNO:
    case SECCOMP_RET_USER_NOTIF:
    case SECCOMP_RET_TRACE:
    case SECCOMP_RET_LOG:
    case SECCOMP_RET_ALLOW:
        return true;
    default:
        return false;
    }
}
static boolean seccomp_op_allowed(u16 code)
{
    switch (code) {
    case CODE_LD_W_ABS:
    case CODE_LD_W_LEN:
    case CODE_LDX_W_LEN:
    case CODE_LD_IMM:
    case CODE_LDX_IMM:
    case CODE_LD_MEM:
    case CODE_LDX_MEM:
    case CODE_ST:
    case CODE_STX:
    case CODE_MISC_TAX:
    case CODE_MISC_TXA:
    case CODE_RET_K:
    case CODE_RET_A:
    case CODE_JA:
    case CODE_JEQ_K:
    case CODE_JEQ_X:
    case CODE_JGT_K:
    case CODE_JGT_X:
    case CODE_JGE_K:
    case CODE_JGE_X:
    case CODE_JSET_K:
    case CODE_JSET_X:
        return true;
    default:
        break;
    }
    if ((code & 0x07) != BPF_ALU_C)
        return false;
    if (code == CODE_ALU_NEG)
        return true;
    u8 op = code & 0xf0;
    if (op == BPF_ADD_OP || op == BPF_SUB_OP || op == BPF_MUL_OP || op == BPF_DIV_OP ||
        op == BPF_OR_OP || op == BPF_AND_OP || op == BPF_LSH_OP || op == BPF_RSH_OP ||
        op == BPF_XOR_OP)
        return true;
    return false;
}
static boolean is_alu_k(u16 code)
{
    if ((code & 0x07) != BPF_ALU_C)
        return false;
    if (code == CODE_ALU_NEG)
        return false;
    return (code & 0x08) == 0;
}
sysreturn seccomp_validate(struct sock_filter *insns, u16 len)
{
    if (len == 0 || len > BPF_MAXINSNS)
        return -EINVAL;
    u16 last = insns[len - 1].code;
    if (last != CODE_RET_K && last != CODE_RET_A)
        return -EINVAL;
    boolean *reached = allocate(heap_locked(get_kernel_heaps()), len * sizeof(boolean));
    u16 *masks = allocate(heap_locked(get_kernel_heaps()), len * sizeof(u16));
    if (reached == INVALID_ADDRESS || masks == INVALID_ADDRESS) {
        if (reached != INVALID_ADDRESS)
            deallocate(heap_locked(get_kernel_heaps()), reached, len * sizeof(boolean));
        if (masks != INVALID_ADDRESS)
            deallocate(heap_locked(get_kernel_heaps()), masks, len * sizeof(u16));
        return -ENOMEM;
    }
    for (u16 i = 0; i < len; i++) {
        reached[i] = false;
        masks[i] = 0;
    }
    sysreturn rv = 0;
    reached[0] = true;
    masks[0] = 0;
    for (u16 pc = 0; pc < len; pc++) {
        struct sock_filter *in = &insns[pc];
        if (!seccomp_op_allowed(in->code)) {
            rv = -EINVAL;
            goto out;
        }
        if (in->code == CODE_LD_W_ABS) {
            if (in->k >= sizeof(struct seccomp_data) || (in->k % 4) != 0) {
                rv = -EINVAL;
                goto out;
            }
        }
        if (in->code == CODE_LD_MEM || in->code == CODE_LDX_MEM || in->code == CODE_ST || in->code == CODE_STX) {
            if (in->k >= BPF_MEMWORDS) {
                rv = -EINVAL;
                goto out;
            }
        }
        if (is_alu_k(in->code)) {
            u8 op = in->code & 0xf0;
            if (op == BPF_DIV_OP && in->k == 0) {
                rv = -EINVAL;
                goto out;
            }
            if ((op == BPF_LSH_OP || op == BPF_RSH_OP) && in->k >= 32) {
                rv = -EINVAL;
                goto out;
            }
        }
        if (in->code == CODE_JA) {
            if (in->k >= (u32)(len - pc - 1)) {
                rv = -EINVAL;
                goto out;
            }
        } else if ((in->code & 0x07) == BPF_JMP_C && in->code != CODE_JA) {
            if ((u32)pc + 1 + in->jt >= (u32)len || (u32)pc + 1 + in->jf >= (u32)len) {
                rv = -EINVAL;
                goto out;
            }
        }
    }
    for (u16 pc = 0; pc < len; pc++) {
        if (!reached[pc])
            continue;
        struct sock_filter *in = &insns[pc];
        u16 mask = masks[pc];
        boolean is_read_mem = (in->code == CODE_LD_MEM || in->code == CODE_LDX_MEM);
        if (is_read_mem && !(mask & (1u << in->k))) {
            rv = -EINVAL;
            goto out;
        }
        u16 out_mask = mask;
        if (in->code == CODE_ST || in->code == CODE_STX)
            out_mask |= (u16)(1u << in->k);
        u16 succ[2];
        int nsucc = 0;
        if (in->code == CODE_RET_K || in->code == CODE_RET_A) {
            nsucc = 0;
        } else if (in->code == CODE_JA) {
            succ[nsucc++] = (u16)(pc + 1 + in->k);
        } else if ((in->code & 0x07) == BPF_JMP_C) {
            succ[nsucc++] = (u16)(pc + 1 + in->jt);
            succ[nsucc++] = (u16)(pc + 1 + in->jf);
        } else {
            succ[nsucc++] = (u16)(pc + 1);
        }
        for (int i = 0; i < nsucc; i++) {
            u16 s = succ[i];
            if (s >= len) {
                rv = -EINVAL;
                goto out;
            }
            if (!reached[s]) {
                reached[s] = true;
                masks[s] = out_mask;
            } else {
                masks[s] &= out_mask;
            }
        }
    }
  out:
    deallocate(heap_locked(get_kernel_heaps()), reached, len * sizeof(boolean));
    deallocate(heap_locked(get_kernel_heaps()), masks, len * sizeof(u16));
    return rv;
}
static u32 seccomp_run_one(seccomp_filter f, const struct seccomp_data *sd)
{
    u32 a = 0, x = 0, m[BPF_MEMWORDS];
    for (int i = 0; i < BPF_MEMWORDS; i++)
        m[i] = 0;
    u16 pc = 0;
    while (pc < f->len) {
        struct sock_filter *in = &f->insns[pc];
        u16 code = in->code;
        u32 k = in->k;
        u8 op = code & 0xf0;
        boolean src_x = (code & 0x08) != 0;
        if ((code & 0x07) == BPF_RET_C) {
            return (code == CODE_RET_K) ? k : a;
        }
        if (code == CODE_JA) {
            pc = (u16)(pc + 1 + k);
            continue;
        }
        if ((code & 0x07) == BPF_JMP_C) {
            u32 v = src_x ? x : k;
            boolean cond = false;
            if (op == BPF_JEQ_OP)
                cond = (a == v);
            else if (op == BPF_JGT_OP)
                cond = (a > v);
            else if (op == BPF_JGE_OP)
                cond = (a >= v);
            else if (op == BPF_JSET_OP)
                cond = ((a & v) != 0);
            pc = (u16)(pc + 1 + (cond ? in->jt : in->jf));
            continue;
        }
        if ((code & 0x07) == BPF_ALU_C) {
            if (code == CODE_ALU_NEG) {
                a = (u32)(0 - a);
                pc++;
                continue;
            }
            u32 v = src_x ? x : k;
            if (op == BPF_ADD_OP)
                a = (u32)(a + v);
            else if (op == BPF_SUB_OP)
                a = (u32)(a - v);
            else if (op == BPF_MUL_OP)
                a = (u32)(a * v);
            else if (op == BPF_DIV_OP)
                a = (v == 0) ? 0 : (a / v);
            else if (op == BPF_OR_OP)
                a = (a | v);
            else if (op == BPF_AND_OP)
                a = (a & v);
            else if (op == BPF_LSH_OP)
                a = (v >= 32) ? 0 : (a << v);
            else if (op == BPF_RSH_OP)
                a = (v >= 32) ? 0 : (a >> v);
            else if (op == BPF_XOR_OP)
                a = (a ^ v);
            pc++;
            continue;
        }
        if (code == CODE_LD_W_ABS) {
            u32 v = 0;
            runtime_memcpy(&v, (u8 *)sd + k, sizeof(v));
            a = v;
        } else if (code == CODE_LD_W_LEN) {
            a = (u32)sizeof(struct seccomp_data);
        } else if (code == CODE_LDX_W_LEN) {
            x = (u32)sizeof(struct seccomp_data);
        } else if (code == CODE_LD_IMM) {
            a = k;
        } else if (code == CODE_LDX_IMM) {
            x = k;
        } else if (code == CODE_LD_MEM) {
            a = m[k];
        } else if (code == CODE_LDX_MEM) {
            x = m[k];
        } else if (code == CODE_ST) {
            m[k] = a;
        } else if (code == CODE_STX) {
            m[k] = x;
        } else if (code == CODE_MISC_TAX) {
            x = a;
        } else if (code == CODE_MISC_TXA) {
            a = x;
        }
        pc++;
    }
    return SECCOMP_RET_KILL_PROCESS;
}
u32 seccomp_run(seccomp_filter chain, const struct seccomp_data *sd, u16 *data)
{
    u32 best = SECCOMP_RET_ALLOW;
    s32 best_signed = (s32)best;
    seccomp_filter cur = chain;
    while (cur) {
        u32 ret = seccomp_run_one(cur, sd);
        u32 action = ret & SECCOMP_RET_ACTION_FULL;
        if (!seccomp_action_known(action))
            action = SECCOMP_RET_KILL_PROCESS;
        ret = action | (ret & SECCOMP_RET_DATA);
        s32 signed_action = (s32)action;
        if (signed_action < best_signed) {
            best_signed = signed_action;
            best = ret;
        }
        cur = cur->prev;
    }
    if (data)
        *data = (u16)(best & SECCOMP_RET_DATA);
    return best;
}
static boolean seccomp_strict_allowed(int nr)
{
    return nr == SYS_read || nr == SYS_write || nr == SYS_exit || nr == SYS_rt_sigreturn;
}
boolean seccomp_check(thread t, context_frame f, sysreturn *rv)
{
    if (t->seccomp_mode == 0)
        return false;
    int nr = (int)f[FRAME_VECTOR];
    if (t->seccomp_mode == SECCOMP_MODE_STRICT) {
        if (seccomp_strict_allowed(nr))
            return false;
        process_kill(t->p, wait_status_signaled(SIGKILL));
        *rv = -ENOSYS;
        return true;
    }
    if (!t->seccomp)
        return false;
    struct seccomp_data sd;
    sd.nr = nr;
    sd.arch = AUDIT_ARCH_X86_64;
    sd.instruction_pointer = f[FRAME_RIP];
    sd.args[0] = f[SYSCALL_FRAME_ARG0];
    sd.args[1] = f[SYSCALL_FRAME_ARG1];
    sd.args[2] = f[SYSCALL_FRAME_ARG2];
    sd.args[3] = f[SYSCALL_FRAME_ARG3];
    sd.args[4] = f[SYSCALL_FRAME_ARG4];
    sd.args[5] = f[SYSCALL_FRAME_ARG5];
    u16 data = 0;
    u32 ret = seccomp_run(t->seccomp, &sd, &data);
    u32 action = ret & SECCOMP_RET_ACTION_FULL;
    if (action == SECCOMP_RET_ALLOW || action == SECCOMP_RET_LOG)
        return false;
    if (action == SECCOMP_RET_ERRNO) {
        u64 v = data;
        if (v > 4095)
            v = 4095;
        *rv = -(sysreturn)v;
        return true;
    }
    if (action == SECCOMP_RET_TRAP) {
        f[FRAME_RAX] = (u64)(s64)nr;
        struct siginfo si;
        zero(&si, sizeof(si));
        si.si_signo = SIGSYS;
        si.si_errno = data;
        si.si_code = SYS_SECCOMP_SI_CODE;
        si.sifields.sigsys.call_addr = f[FRAME_RIP];
        si.sifields.sigsys.syscall = nr;
        si.sifields.sigsys.arch = AUDIT_ARCH_X86_64;
        force_signal(t, &si);
        *rv = nr;
        return true;
    }
    if (action == SECCOMP_RET_TRACE || action == SECCOMP_RET_USER_NOTIF) {
        *rv = -ENOSYS;
        return true;
    }
    if (action == SECCOMP_RET_KILL_THREAD) {
        process p = t->p;
        spin_lock(&p->threads_lock);
        u64 remaining = rbtree_get_count(p->threads);
        spin_unlock(&p->threads_lock);
        if (remaining <= 1) {
            process_kill(p, wait_status_signaled(SIGSYS));
            *rv = -ENOSYS;
            return true;
        }
        {
            syscall_context cur_sc = (syscall_context)get_current_context(current_cpu());
            context_reserve_refcount(&cur_sc->uc.kc.context);
        }
        exit_thread(t);
        syscall_finish(true);
        *rv = -ENOSYS;
        return true;
    }
    process_kill(t->p, wait_status_signaled(SIGSYS));
    *rv = -ENOSYS;
    return true;
}
sysreturn seccomp_prctl(u64 mode, void *prog)
{
    if (mode == SECCOMP_MODE_STRICT)
        return seccomp(SECCOMP_SET_MODE_STRICT, 0, 0);
    if (mode == SECCOMP_MODE_FILTER)
        return seccomp(SECCOMP_SET_MODE_FILTER, 0, prog);
    return -EINVAL;
}
static boolean seccomp_is_ancestor(seccomp_filter anc, seccomp_filter f)
{
    if (!anc)
        return f == 0;
    while (f) {
        if (f == anc)
            return true;
        f = f->prev;
    }
    return false;
}
static boolean seccomp_is_ancestor_or_eq(seccomp_filter anc, seccomp_filter f)
{
    if (anc == f)
        return true;
    if (!anc)
        return f == 0;
    return seccomp_is_ancestor(anc, f);
}
sysreturn seccomp(u32 op, u32 flags, void *uargs)
{
    thread t = current;
    if (op == SECCOMP_SET_MODE_STRICT) {
        if (flags != 0 || uargs != 0)
            return -EINVAL;
        if (t->seccomp_mode == SECCOMP_MODE_FILTER) {
            seccomp_filter old = t->seccomp;
            t->seccomp = 0;
            t->seccomp_mode = SECCOMP_MODE_STRICT;
            seccomp_release(old);
        } else {
            t->seccomp_mode = SECCOMP_MODE_STRICT;
        }
        return 0;
    }
    if (op == SECCOMP_GET_ACTION_AVAIL) {
        u32 action = 0;
        if (!copy_from_user(uargs, &action, sizeof(action)))
            return -EFAULT;
        u32 masked = action & SECCOMP_RET_ACTION_FULL;
        if (masked == SECCOMP_RET_USER_NOTIF)
            return -EOPNOTSUPP;
        if (seccomp_action_known(masked))
            return 0;
        return -EINVAL;
    }
    if (op != SECCOMP_SET_MODE_FILTER)
        return -EINVAL;
    if (flags & ~(SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_SPEC_ALLOW | SECCOMP_FILTER_FLAG_TSYNC_ESRCH))
        return -EINVAL;
    if (!uargs)
        return -EFAULT;
    struct sock_fprog prog;
    if (!copy_from_user(uargs, &prog, sizeof(prog)))
        return -EFAULT;
    if (prog.len == 0 || prog.len > BPF_MAXINSNS)
        return -EINVAL;
    process p = t->p;
    if (!t->no_new_privs && !capable(p, CAP_SYS_ADMIN))
        return -EACCES;
    heap h = heap_locked(get_kernel_heaps());
    u64 byte_len = (u64)prog.len * sizeof(struct sock_filter);
    struct sock_filter *insns = allocate(h, byte_len);
    if (insns == INVALID_ADDRESS)
        return -ENOMEM;
    if (!copy_from_user(prog.filter, insns, byte_len)) {
        deallocate(h, insns, byte_len);
        return -EFAULT;
    }
    sysreturn rv = seccomp_validate(insns, prog.len);
    if (rv != 0) {
        deallocate(h, insns, byte_len);
        return rv;
    }
    if (t->seccomp_mode == SECCOMP_MODE_STRICT) {
        deallocate(h, insns, byte_len);
        return -EINVAL;
    }
    seccomp_filter old = t->seccomp;
    u32 path = (u32)prog.len + 4 + (old ? old->path_insns : 0);
    if (path > 32768) {
        deallocate(h, insns, byte_len);
        return -ENOMEM;
    }
    seccomp_filter nf = allocate(h, sizeof(*nf) + byte_len);
    if (nf == INVALID_ADDRESS) {
        deallocate(h, insns, byte_len);
        return -ENOMEM;
    }
    nf->prev = old;
    nf->path_insns = path;
    nf->len = prog.len;
    init_refcount(&nf->refcount, 1, init_closure_func(&nf->free, thunk, seccomp_filter_free_cfn));
    seccomp_reserve(old);
    runtime_memcpy(nf->insns, insns, byte_len);
    deallocate(h, insns, byte_len);
    if (flags & SECCOMP_FILTER_FLAG_TSYNC) {
        spin_lock(&p->threads_lock);
        thread bad = 0;
        for (rbnode n = rbtree_find_first(p->threads); n != INVALID_ADDRESS; n = rbnode_get_next(n)) {
            thread ot = struct_from_field(n, thread, n);
            if (ot == t)
                continue;
            if (!seccomp_is_ancestor_or_eq(ot->seccomp, old)) {
                bad = ot;
                thread_reserve(bad);
                break;
            }
        }
        if (bad) {
            int bad_tid = bad->tid;
            spin_unlock(&p->threads_lock);
            thread_release(bad);
            seccomp_release(nf);
            if (flags & SECCOMP_FILTER_FLAG_TSYNC_ESRCH)
                return -ESRCH;
            return bad_tid;
        }
        u64 nthreads = rbtree_get_count(p->threads);
        for (u64 i = 1; i < nthreads; i++)
            seccomp_reserve(nf);
        for (rbnode n = rbtree_find_first(p->threads); n != INVALID_ADDRESS; n = rbnode_get_next(n)) {
            thread ot = struct_from_field(n, thread, n);
            seccomp_filter prev_old = ot->seccomp;
            ot->seccomp = nf;
            ot->seccomp_mode = SECCOMP_MODE_FILTER;
            if (t->no_new_privs)
                ot->no_new_privs = true;
            if (prev_old)
                seccomp_release(prev_old);
        }
        spin_unlock(&p->threads_lock);
        return 0;
    }
    t->seccomp = nf;
    t->seccomp_mode = SECCOMP_MODE_FILTER;
    seccomp_release(old);
    return 0;
}
void seccomp_fork(thread child, thread parent)
{
    child->seccomp_mode = parent->seccomp_mode;
    child->seccomp = parent->seccomp;
    child->no_new_privs = parent->no_new_privs;
    seccomp_reserve(child->seccomp);
}
void seccomp_thread_exit(thread t)
{
    seccomp_filter f = t->seccomp;
    t->seccomp = 0;
    t->seccomp_mode = 0;
    seccomp_release(f);
}
