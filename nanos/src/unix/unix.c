#include <unix_internal.h>
#include <seccomp.h>
#include <ftrace.h>
#include <gdb.h>
#include <filesystem.h>
#include <drivers/console.h>
#include <ltrace.h>

//#define PF_DEBUG
#ifdef PF_DEBUG
#define pf_debug(x, ...) do {tprintf(sym(fault), 0, ss("tid %02d " x "\n"), \
                                     current ? current->tid : -1, ##__VA_ARGS__);} while(0)
#else
#define pf_debug(x, ...) thread_trace(current, TRACE_PAGE_FAULT, x, ##__VA_ARGS__);
#endif

static struct list processes;
static struct spinlock processes_lock;
static process init_process;

static timestamp oom_last_time;
static u64 oom_count;
static struct spinlock oom_lock;

BSS_RO_AFTER_INIT static unix_heaps u_heap;

unix_heaps get_unix_heaps()
{
    return u_heap;
}

static void fdtable_install_locked(fdtable fdt, u64 fd, u32 fd_flags)
{
    bitmap_set(fdt->cloexec, fd, (fd_flags & FD_CLOEXEC) != 0);
}

u64 allocate_fd(process p, void *f, u32 fd_flags)
{
    fdtable fdt = p->fdtable;
    spin_lock(&fdt->lock);
    u64 fd = allocate_u64((heap)fdt->fdallocator, 1);
    if (fd == INVALID_PHYSICAL) {
        msg_err("fd allocation failed");
        goto out;
    }
    if (p->rlimit_nofile_cur && fd >= p->rlimit_nofile_cur) {
        deallocate_u64((heap)fdt->fdallocator, fd, 1);
        fd = INVALID_PHYSICAL;
        goto out;
    }
    if (!vector_set(fdt->files, fd, f)) {
        deallocate_u64((heap)fdt->fdallocator, fd, 1);
        fd = INVALID_PHYSICAL;
    } else {
        fdtable_install_locked(fdt, fd, fd_flags);
    }
  out:
    spin_unlock(&fdt->lock);
    return fd;
}

u64 allocate_fd_gte(process p, u64 min, void *f, u32 fd_flags)
{
    fdtable fdt = p->fdtable;
    spin_lock(&fdt->lock);
    u64 fd = id_heap_alloc_gte(fdt->fdallocator, 1, min);
    if (fd != INVALID_PHYSICAL && p->rlimit_nofile_cur && fd >= p->rlimit_nofile_cur) {
        deallocate_u64((heap)fdt->fdallocator, fd, 1);
        fd = INVALID_PHYSICAL;
    }
    if (fd == INVALID_PHYSICAL) {
        msg_err("fd allocation failed");
    }
    else {
        if (!vector_set(fdt->files, fd, f)) {
            deallocate_u64((heap)fdt->fdallocator, fd, 1);
            fd = INVALID_PHYSICAL;
        } else {
            fdtable_install_locked(fdt, fd, fd_flags);
        }
    }
    spin_unlock(&fdt->lock);
    return fd;
}

fdesc fdtable_replace(fdtable fdt, int fd, fdesc f, u32 fd_flags)
{
    spin_lock(&fdt->lock);
    fdesc old = vector_get(fdt->files, fd);
    if (old) {
        assert(vector_set(fdt->files, fd, f));
        fdtable_install_locked(fdt, fd, fd_flags);
    }
    spin_unlock(&fdt->lock);
    return old;
}

int fdtable_get_fd_flags(fdtable fdt, int fd)
{
    spin_lock(&fdt->lock);
    int flags = !vector_get(fdt->files, fd) ? -EBADF :
                (bitmap_get(fdt->cloexec, fd) ? FD_CLOEXEC : 0);
    spin_unlock(&fdt->lock);
    return flags;
}

int fdtable_set_fd_flags(fdtable fdt, int fd, u32 fd_flags)
{
    spin_lock(&fdt->lock);
    int rv = 0;
    if (vector_get(fdt->files, fd))
        fdtable_install_locked(fdt, fd, fd_flags);
    else
        rv = -EBADF;
    spin_unlock(&fdt->lock);
    return rv;
}

void deallocate_fd(process p, int fd)
{
    fdtable fdt = p->fdtable;
    spin_lock(&fdt->lock);
    assert(vector_set(fdt->files, fd, 0));
    bitmap_set(fdt->cloexec, fd, 0);
    deallocate_u64((heap)fdt->fdallocator, fd, 1);
    spin_unlock(&fdt->lock);
}

void fdtable_close_on_exec(fdtable fdt)
{
    for (int fd = 0; fd < vector_length(fdt->files); fd++) {
        spin_lock(&fdt->lock);
        fdesc f = bitmap_get(fdt->cloexec, fd) ? vector_get(fdt->files, fd) : 0;
        if (f) {
            assert(vector_set(fdt->files, fd, 0));
            bitmap_set(fdt->cloexec, fd, 0);
            deallocate_u64((heap)fdt->fdallocator, fd, 1);
        }
        spin_unlock(&fdt->lock);
        if (f)
            fdesc_put(f);
    }
}

closure_func_basic(thunk, void, fdtable_free)
{
    fdtable fdt = struct_from_closure(fdtable, free);
    for (int fd = 0; fd < vector_length(fdt->files); fd++) {
        spin_lock(&fdt->lock);
        fdesc f = vector_get(fdt->files, fd);
        if (f) {
            assert(vector_set(fdt->files, fd, 0));
            deallocate_u64((heap)fdt->fdallocator, fd, 1);
        }
        spin_unlock(&fdt->lock);
        if (f)
            fdesc_put(f);
    }
    heap locked = heap_locked(get_kernel_heaps());
    destroy_heap((heap)fdt->fdallocator);
    deallocate_vector(fdt->files);
    deallocate_bitmap(fdt->cloexec);
    deallocate(locked, fdt, sizeof(*fdt));
}

fdtable fdtable_alloc(void)
{
    heap locked = heap_locked(get_kernel_heaps());
    fdtable fdt = allocate(locked, sizeof(*fdt));
    if (fdt == INVALID_ADDRESS)
        return fdt;
    fdt->fdallocator = create_id_heap(locked, locked, 0, infinity, 1, false);
    if (fdt->fdallocator == INVALID_ADDRESS)
        goto fail;
    fdt->files = allocate_vector(locked, 64);
    if (fdt->files == INVALID_ADDRESS) {
        destroy_heap((heap)fdt->fdallocator);
        goto fail;
    }
    fdt->cloexec = allocate_bitmap(locked, locked, infinity);
    if (fdt->cloexec == INVALID_ADDRESS) {
        deallocate_vector(fdt->files);
        destroy_heap((heap)fdt->fdallocator);
        goto fail;
    }
    spin_lock_init(&fdt->lock);
    init_refcount(&fdt->refcount, 1, init_closure_func(&fdt->free, thunk, fdtable_free));
    return fdt;
  fail:
    deallocate(locked, fdt, sizeof(*fdt));
    return INVALID_ADDRESS;
}

fdtable fdtable_copy(fdtable parent)
{
    fdtable fdt = fdtable_alloc();
    if (fdt == INVALID_ADDRESS)
        return fdt;
    spin_lock(&parent->lock);
    for (int fd = 0; fd < vector_length(parent->files); fd++) {
        fdesc f = vector_get(parent->files, fd);
        if (!f)
            continue;
        if (!id_heap_set_area(fdt->fdallocator, fd, 1, true, true) ||
            !vector_set(fdt->files, fd, f)) {
            spin_unlock(&parent->lock);
            fdtable_release(fdt);
            return INVALID_ADDRESS;
        }
        fdtable_install_locked(fdt, fd, bitmap_get(parent->cloexec, fd) ? FD_CLOEXEC : 0);
        fetch_and_add(&f->refcnt, 1);
    }
    spin_unlock(&parent->lock);
    return fdt;
}

closure_func_basic(io_completion, void, fdesc_io_complete,
                   sysreturn rv)
{
    fdesc_put(struct_from_closure(fdesc, io_complete));
    apply(syscall_io_complete, rv);
}

void init_fdesc(heap h, fdesc f, int type)
{
    zero(f, sizeof(*f));
    init_closure_func(&f->io_complete, io_completion, fdesc_io_complete);
    f->refcnt = 1;
    f->type = type;
    f->ns = allocate_notify_set(h);
    spin_lock_init(&f->lock);
}

void release_fdesc(fdesc f)
{
    deallocate_notify_set(f->ns);
}

sysreturn user_timeval_get(const struct timeval *tv, timestamp *t)
{
    if (!memory_is_user(tv, sizeof(*tv)))
        return -EFAULT;
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx)) {
        return -EFAULT;
    }
    *t = time_from_timeval(tv);
    context_clear_err(ctx);
    return 0;
}

sysreturn user_timespec_get(const struct timespec *ts, timestamp *t)
{
    if (!memory_is_user(ts, sizeof(*ts)))
        return -EFAULT;
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx)) {
        return -EFAULT;
    }
    *t = time_from_timespec(ts);
    context_clear_err(ctx);
    return 0;
}

boolean copy_from_user(const void *uaddr, void *kaddr, u64 len)
{
    if (!memory_is_user(uaddr, len))
        return false;
    context ctx = get_current_context(current_cpu());
    if (!context_set_err(ctx)) {
        runtime_memcpy(kaddr, uaddr, len);
        context_clear_err(ctx);
        return true;
    }
    return false;
}

boolean copy_to_user(void *uaddr, const void *kaddr, u64 len)
{
    if (!memory_is_user(uaddr, len))
        return false;
    context ctx = get_current_context(current_cpu());
    if (!context_set_err(ctx)) {
        runtime_memcpy(uaddr, kaddr, len);
        context_clear_err(ctx);
        return true;
    }
    return false;
}

void demand_page_done(context ctx, u64 vaddr, status s)
{
    /* In order to prevent the user program from getting stuck in a page fault
     * oom loop, this code terminates the user program if a emough faults fail
     * for oom in a short time */
    if (is_ok(s)) {
        spin_lock(&oom_lock);
        oom_last_time = 0;
        oom_count = 0;
        spin_unlock(&oom_lock);
    } else if (is_thread_context(ctx)) {
        pf_debug("demand page failed user mode, reason: %v", s);
        thread t = (thread)ctx;
        if (s == timm_oom) {
            spin_lock(&oom_lock);
            timestamp here = now(CLOCK_ID_MONOTONIC);
            if (here - oom_last_time > seconds(5)) {
                oom_last_time = 0;
                oom_count = 0;
            }
            oom_count++;
            timestamp last = oom_last_time;
            oom_last_time = here;
            spin_unlock(&oom_lock);
            if (here - last < seconds(1) && oom_count >= 10) {
                msg_err("page fault: out of memory, program killed");
                deliver_fault_signal(SIGKILL, t, vaddr, 0);
            } else {
                deliver_fault_signal(SIGBUS, t, vaddr, BUS_ADRERR);
            }
        } else {
            deliver_fault_signal(SIGBUS, t, vaddr, BUS_ADRERR);
        }
    } else if (context_err_is_set(ctx)) {
        kernel_context kc = (kernel_context)ctx;
        err_frame_apply(kc->err_frame, ctx->frame);
        context_clear_err(ctx);
    } else {
        halt("unhandled demand page failure for context type %d\n", ctx->type);
    }
    timm_dealloc(s);
}

void deliver_fault_signal(u32 signo, thread t, u64 vaddr, s32 si_code)
{
    struct siginfo s = {
        .si_signo = signo,
         /* man sigaction: "si_errno is generally unused on Linux" */
        .si_errno = 0,
        .si_code = si_code,
        .sifields.sigfault = {
            .addr = vaddr,
        }
    };

    sstring signame;
    switch (signo) {
    case SIGSEGV:
        signame = ss("SIGSEGV");
        break;
    case SIGBUS:
        signame = ss("SIGBUS");
        break;
    case SIGFPE:
        signame = ss("SIGFPE");
        break;
    case SIGILL:
        signame = ss("SIGILL");
        break;
    case SIGTRAP:
        signame = ss("SIGTRAP");
        break;
    case SIGKILL:       /* for terminating out-of-memory */
        signame = ss("SIGKILL");
        break;
    default:
        halt("%s: unexpected signal number %d\n", func_ss, signo);
    }
    pf_debug("delivering %s to thread %d; vaddr 0x%lx si_code %d", signame,
        t->tid, vaddr, si_code);
    deliver_signal_to_thread(t, &s);
}

sstring string_from_mmap_type(int type)
{
    return type == VMAP_MMAP_TYPE_ANONYMOUS ? ss("anonymous") :
           (type == VMAP_MMAP_TYPE_FILEBACKED ? ss("filebacked") :
            ss("unknown"));
}

#define pf_debug_protection_violation(vaddr, ctx, vm)           \
    pf_debug(                                                   \
    "page_protection_violation\naddr 0x%lx, pc 0x%lx, "         \
    "error %c%c%c vm->flags (%s%s %s%s%s)\n",                   \
        vaddr, frame_fault_pc(ctx->frame),                      \
        is_write_fault(ctx->frame) ? 'W' : 'R',                 \
        is_usermode_fault(ctx->frame) ? 'U' : 'S',              \
        is_instruction_fault(ctx->frame) ? 'I' : 'D',           \
        (vm->flags & VMAP_FLAG_MMAP) ? ss("mmap ") : sstring_empty(),           \
        string_from_mmap_type(vm->flags & VMAP_MMAP_TYPE_MASK), \
        (vm->flags & VMAP_FLAG_READABLE) ? ss("readable ") : sstring_empty(),   \
        (vm->flags & VMAP_FLAG_WRITABLE) ? ss("writable ") : sstring_empty(),   \
        (vm->flags & VMAP_FLAG_EXEC) ? ss("executable ") : sstring_empty()      \
    )

static boolean handle_protection_fault(process p, context ctx, u64 vaddr, vmap vm)
{
    int mmap_type = (vm->flags & VMAP_FLAG_MMAP) ? (vm->flags & VMAP_MMAP_TYPE_MASK) : 0;
    if (is_write_fault(ctx->frame) && (vm->flags & VMAP_FLAG_WRITABLE) &&
        !(vm->flags & VMAP_FLAG_SHARED) && (mmap_type != VMAP_MMAP_TYPE_CUSTOM)) {
        u64 vaddr_aligned = vaddr & ~MASK(PAGELOG);
        if (mmap_type == VMAP_MMAP_TYPE_FILEBACKED) {
            u64 node_offset = vm->node_offset + (vaddr_aligned - vm->node.r.start);
            physical phys = address_space_physical(p->vm->as, vaddr_aligned);
            if ((phys != INVALID_PHYSICAL) &&
                pagecache_node_page_is_cached(vm->cache_node, node_offset, phys)) {
                pf_debug("copy-on-write for private map: vaddr 0x%lx, node %p, node_offset 0x%lx\n",
                         vaddr, vm->cache_node, node_offset);
                if (!pagecache_node_do_page_cow(vm->cache_node, p->vm->as, node_offset,
                                                vaddr_aligned, pageflags_from_vmflags(vm->flags)))
                    halt("cannot get physical page for vaddr 0x%lx, ctx %p; OOM\n", vaddr, ctx);
                return true;
            }
        }
        if (mmap_cow_page(p->vm, vm, vaddr))
            return true;
        if (is_thread_context(ctx)) {
            deliver_fault_signal(SIGKILL, (thread)ctx, vaddr, 0);
            return true;
        }
        return false;
    }

    if (is_thread_context(ctx)) {
        pf_debug_protection_violation(vaddr, ctx, vm);
        deliver_fault_signal(SIGSEGV, (thread)ctx, vaddr, SEGV_ACCERR);
        return true;
    }
    return false;
}

closure_func_basic(fault_handler, context, unix_fault_handler,
                   context ctx)
{
    sstring errmsg = sstring_empty();
    context_frame f = ctx->frame;
    u64 fault_pc = frame_fault_pc(f);
    boolean user = (current_cpu()->state == cpu_user);
    process p = struct_from_field(closure_self(), process, fault_handler);
    thread t = user ? (thread)ctx : 0;

    if (is_div_by_zero(f)) {
        if (user) {
            deliver_fault_signal(SIGFPE, t, fault_pc, FPE_INTDIV);
            schedule_thread(t);
            return 0;
        } else {
            errmsg = ss("Divide by zero occurs in kernel mode");
            goto bug;
        }
    } else if (is_illegal_instruction(f)) {
        if (user) {
            pf_debug("invalid opcode fault in user mode, rip 0x%lx", fault_pc);
            if (!insn_emulate(f))
                deliver_fault_signal(SIGILL, t, fault_pc, ILL_ILLOPC);
            schedule_thread(t);
            return 0;
        } else {
            errmsg = ss("Illegal instruction in kernel mode");
            goto bug;
        }
    } else if (is_trap(f)) {
        if (user) {
            pf_debug("trap in user mode, rip 0x%lx", fault_pc);
            if (!ltrace_handle_trap(f))
                deliver_fault_signal(SIGTRAP, t, fault_pc,
                                     is_breakpoint(f) ? TRAP_BRKPT : TRAP_TRACE);
            schedule_thread(t);
            return 0;
        } else {
            errmsg = ss("Breakpoint in kernel mode");
            goto bug;
        }
    } else if (is_page_fault(f)) {
        u64 vaddr = frame_fault_address(f);
        if (vaddr < USER_LIMIT && current_cpu()->current_as != p->vm->as) {
            errmsg = ss("fault on a user address with another process's address space loaded");
            goto bug;
        }
        vmap_lock(p);
        vmap vm;
        if (vaddr >= MIN(p->vm->mmap_min_addr, PAGESIZE) && vaddr < USER_LIMIT)
            vm = vmap_from_vaddr(p, vaddr);
        else
            vm = INVALID_ADDRESS;
        pf_debug("page fault, vaddr 0x%lx, vmap %p, ctx %p, type %d, pc 0x%lx, user %d",
                 vaddr, vm, ctx, ctx->type, fault_pc, user);
        if (vm == INVALID_ADDRESS) {
            vmap_unlock(p);
            /* We're assuming here that an unhandled fault on a user page from
               within a syscall context is actually a program bug - though
               there's a chance that a true kernel bug might materialize as a
               SEGV rather than a panic. */
            pf_debug("no vmap found");
            if (!user)
                goto error;
            deliver_fault_signal(SIGSEGV, t, vaddr, SEGV_MAPERR);

            /* schedule this thread to either run signal handler or terminate */
            schedule_thread(t);
            return 0;
        }

        if (is_pte_error(f)) {
            vmap_unlock(p);
            /* no SEGV on reserved PTEs */
            errmsg = ss("bug: pte entries reserved or corrupt");
            dump_page_tables(vaddr, 8);
            goto bug;
        }

        if (is_instruction_fault(f) && !user) {
            vmap_unlock(p);
            msg_err("%s: kernel instruction fault", func_ss);
            goto bug;
        }

        /* If the address is mapped with PROT_NONE and there is no page backing it (or the relevant
         * PTE has been marked as non-present), do not page it in, and treat the fault as a
         * protection fault. */
        if (is_protection_fault(f) || !(vm->flags & VMAP_FLAG_PROT_MASK)) {
            if (handle_protection_fault(p, ctx, vaddr, vm)) {
                vmap_unlock(p);
                if (!is_thread_context(ctx))
                    return ctx;   /* direct return */
                schedule_thread(t);
                return 0;
            }
            vmap_unlock(p);
            goto error;
        }

        boolean paging_done;
        status s = do_demand_page(p, ctx, vaddr, vm, &paging_done);
        vmap_unlock(p);
        if (!paging_done)
            return 0;
        demand_page_done(ctx, vaddr, s);
        if (!is_ok(s) && user) {
            schedule_thread(t);
            return 0;
        } else {
            return ctx;   /* direct return */
        }
    }
    /* XXX arch dep */
#ifdef __x86_64__
    else if (f[FRAME_VECTOR] == 13) {
        if (user) {
            pf_debug("general protection fault in user mode, rip 0x%lx", fault_pc);
            deliver_fault_signal(SIGSEGV, t, 0, SI_KERNEL);
            schedule_thread(t);
            return 0;
        }
    }
#endif

error:
    if (context_err_is_set(ctx)) {
        kernel_context kc = (kernel_context)ctx;
        err_frame_apply(kc->err_frame, f);
        context_clear_err(ctx);
        return ctx;
    }
bug:
    // panic handling in a more central location?
    console_force_unlock();
    rprintf("\n%s\n", errmsg);
    rprintf("cpu: %d, context type: %d\n", current_cpu()->id, ctx->type);
    dump_context(ctx);
    f[FRAME_FULL] = false;

    if (get(p->process_root, sym(fault))) {
        rputs("TODO: in-kernel gdb needs revisiting\n");
//        init_tcp_gdb(heap_locked(get_kernel_heaps()), p, 9090);
//        thread_sleep_uninterruptible();
    }
    /* XXX need a safe, polling storage driver to try to save crash dump here */
    vm_exit(VM_EXIT_FAULT);
}

void init_thread_fault_handler(thread t)
{
    t->context.fault_handler = (fault_handler)&t->p->fault_handler;
}

closure_func_basic(file_io, sysreturn, dummy_read,
                   void *dest, u64 length, u64 offset_arg, context ctx, boolean bh, io_completion completion)
{
    if (completion)
        apply(completion, 0);
    return 0;
}

closure_func_basic(fdesc_close, sysreturn, std_close,
                   context ctx, io_completion completion)
{
    unix_cache_free(get_unix_heaps(), file, struct_from_closure(file, close));
    return io_complete(completion, 0);
}

closure_func_basic(file_io, sysreturn, stdout,
                   void *d, u64 length, u64 offset, context ctx, boolean bh, io_completion completion)
{
    sysreturn rv;
    if (fault_in_user_memory(d, length, false)) {
        console_write(d, length);
        klog_write(d, length);
        rv = length;
    } else {
        rv = -EFAULT;
    }
    if (completion)
        apply(completion, rv);
    return rv;
}

closure_func_basic(fdesc_events, u32, std_output_events,
                   thread t)
{
    return EPOLLOUT;
}

closure_func_basic(fdesc_events, u32, std_input_events,
                   thread t)
{
    return 0;
}

static boolean create_stdfiles(unix_heaps uh, process p)
{
    heap h = heap_locked(get_kernel_heaps());
    file in = unix_cache_alloc(uh, file);
    file out = unix_cache_alloc(uh, file);
    file err = unix_cache_alloc(uh, file);
    if ((in == INVALID_ADDRESS) || (out == INVALID_ADDRESS) || (err == INVALID_ADDRESS)) {
        msg_err("Unix: failed to allocate standard files");
        return false;
    }
    assert(allocate_fd(p, in, 0) == 0);
    assert(allocate_fd(p, out, 0) == 1);
    assert(allocate_fd(p, err, 0) == 2);

    /* Writes to in, reads from out and err act as if handled by the
       out and in files respectively. */
    init_fdesc(h, &in->f, FDESC_TYPE_STDIO);
    in->f.close = init_closure_func(&in->close, fdesc_close, std_close);
    init_fdesc(h, &out->f, FDESC_TYPE_STDIO);
    out->f.close = init_closure_func(&out->close, fdesc_close, std_close);
    init_fdesc(h, &err->f, FDESC_TYPE_STDIO);
    err->f.close = init_closure_func(&err->close, fdesc_close, std_close);
    in->f.write = init_closure_func(&in->write, file_io, stdout);
    out->f.write = init_closure_func(&out->write, file_io, stdout);
    err->f.write = init_closure_func(&err->write, file_io, stdout);
    in->f.read = init_closure_func(&in->read, file_io, dummy_read);
    out->f.read = init_closure_func(&out->read, file_io, dummy_read);
    err->f.read = init_closure_func(&err->read, file_io, dummy_read);
    in->f.flags = out->f.flags = err->f.flags = O_RDWR;
    out->f.events = init_closure_func(&out->events, fdesc_events, std_output_events);
    err->f.events = init_closure_func(&err->events, fdesc_events, std_output_events);
    in->f.events = init_closure_func(&in->events, fdesc_events, std_input_events);
    return true;
}

boolean init_unix_context(unix_context uc, int type, int size, queue free_ctx_q, u32 alloc_flags)
{
    if (!init_kernel_context(&uc->kc, type, size, free_ctx_q, alloc_flags))
        return false;
    blockq_thread_init(uc);
    return true;
}

static void process_context_pause(context ctx)
{
    process_context pc = (process_context)ctx;
    process p = pc->p;
    fetch_and_add(&p->stime, now(CLOCK_ID_MONOTONIC_RAW) - pc->start_time);
    timer_service(p->cpu_timers, proc_cputime(p));
    context_release_refcount(ctx);
}

static void process_context_resume(context ctx)
{
    process_context pc = (process_context)ctx;
    pc->start_time = now(CLOCK_ID_MONOTONIC_RAW);
    context_reserve_refcount(ctx);
}

process_context get_process_context(void)
{
    thread t = current;
    if (!t)
        return INVALID_ADDRESS;
    cpuinfo ci = current_cpu();
    process_context pc = dequeue_single(ci->free_process_contexts);
    if (pc != INVALID_ADDRESS) {
        refcount_set_count(&pc->uc.kc.context.refcount, 1);
        goto bind_process;
    }
    heap h = heap_locked(get_kernel_heaps());
    u32 alloc_flags = 0;
    pc = mem_alloc(h, PROCESS_CONTEXT_SIZE, alloc_flags);
    if (pc == INVALID_ADDRESS)
        return pc;
    if (!init_unix_context(&pc->uc, CONTEXT_TYPE_PROCESS, PROCESS_CONTEXT_SIZE,
                           ci->free_process_contexts, alloc_flags)) {
        deallocate(h, pc, PROCESS_CONTEXT_SIZE);
        return INVALID_ADDRESS;
    }
    context c = &pc->uc.kc.context;
    c->pause = process_context_pause;
    c->resume = process_context_resume;
  bind_process:
    pc->p = t->p;
    c = &pc->uc.kc.context;
    c->fault_handler = (fault_handler)&pc->p->fault_handler;
    c->as = pc->p->vm->as;
    return pc;
}

closure_func_basic(clock_now, timestamp, process_now)
{
    process p = struct_from_field(closure_self(), process, now);
    return proc_cputime(p);
}

closure_func_basic(thunk, void, process_free)
{
    process p = struct_from_closure(process, free);
    heap locked = heap_locked(get_kernel_heaps());
    spin_lock(&processes_lock);
    list_delete(&p->l);
    spin_unlock(&processes_lock);
    if (p->vm)
        process_vm_release(p->vm);
    if (p->fdtable)
        fdtable_release(p->fdtable);
    filesystem_release(p->cwd_fs);
    deallocate_rbtree(p->threads, 0);
    deallocate_notify_set(p->signalfds);
    destroy_heap((heap)p->posix_timer_ids);
    deallocate_vector(p->posix_timers);
    deallocate_vector(p->itimers);
    deallocate_timerqueue(p->cpu_timers);
    destroy_heap((heap)p->aio_ids);
    deallocate_vector(p->aio);
    deallocate_blockq(p->child_bq);
    if (p->cmdline)
        deallocate_buffer(p->cmdline);
    if (p->exe)
        deallocate_buffer(p->exe);
    creds_free(&p->creds);
    if (p->pid)
        deallocate_u64((heap)p->uh->processes, p->pid, 1);
    deallocate(locked, p, sizeof(struct process));
}

static u64 default_rlimit_nproc(void)
{
    u64 n = (heap_total((heap)heap_physical(get_kernel_heaps())) >> PAGELOG) / 64;
    return MAX(n, 20);
}

static process process_alloc(unix_heaps uh, tuple root, filesystem fs, int pid)
{
    kernel_heaps kh = get_kernel_heaps();
    heap locked = heap_locked(kh);
    process p = allocate_zero(locked, sizeof(struct process));
    if (p == INVALID_ADDRESS)
        return p;
    p->child_bq = allocate_blockq(locked, ss("wait"));
    if (p->child_bq == INVALID_ADDRESS) {
        deallocate(locked, p, sizeof(struct process));
        return INVALID_ADDRESS;
    }

    spin_lock_init(&p->lock);
    p->uh = uh;
    p->pid = pid;
    p->pgid = pid;
    list_init(&p->l);
    list_init(&p->children);
    list_init(&p->sibling);
    p->parent = 0;
    p->state = PROCESS_RUNNING;
    p->exit_signal = SIGCHLD;
    p->wait_status = 0;
    p->cutime = p->cstime = 0;
    p->rlimit_nproc_cur = p->rlimit_nproc_max = default_rlimit_nproc();
    p->rlimit_nofile_cur = p->rlimit_nofile_max = 65536;
    p->vfork_waiter = 0;
    p->exec_thread = 0;
    p->exec_waiter = 0;
    p->cmdline = p->exe = 0;
    p->exiting = false;
    p->dumpable = true;
    init_refcount(&p->refcount, 1, init_closure_func(&p->free, thunk, process_free));
    p->vm = 0;
    p->fdtable = 0;
    filesystem_reserve(fs); /* because it hosts the current working directory */
    p->root_fs = p->cwd_fs = fs;
    p->cwd = fs->get_inode(fs, filesystem_getroot(fs));
    p->process_root = root;

    u64 id;
    u32 uid = get_u64(root, sym(uid), &id) ? id : 0;
    u32 gid = get_u64(root, sym(gid), &id) ? id : 0;
    creds_init(&p->creds, uid, gid);
    init_threads(p);
    init_closure_func(&p->fault_handler, fault_handler, unix_fault_handler);
    p->syscalls = linux_syscalls;
    init_sigstate(&p->signals);
    zero(p->sigactions, sizeof(p->sigactions));
    p->signalfds = allocate_notify_set(locked);
    assert(p->signalfds != INVALID_ADDRESS);
    p->posix_timer_ids = create_id_heap(locked, locked, 0, U32_MAX, 1, false);
    p->posix_timers = allocate_vector(locked, 8);
    p->itimers = allocate_vector(locked, 3);
    p->utime = p->stime = 0;
    p->cpu_timers = allocate_timerqueue(locked, init_closure_func(&p->now, clock_now, process_now),
                                        ss("cpu time"));
    assert(p->cpu_timers != INVALID_ADDRESS);
    p->aio_ids = create_id_heap(locked, locked, 0, S32_MAX, 1, false);
    p->aio = allocate_vector(locked, 8);
    p->rlimit_stack = PROCESS_STACK_SIZE;
    p->trace = 0;
    p->trap = 0;
    return p;
}

process create_process(unix_heaps uh, tuple root, filesystem fs)
{
    spin_lock(&processes_lock);
    boolean kernel = list_empty(&processes);
    spin_unlock(&processes_lock);
    int pid = kernel ? 0 : allocate_u64((heap)uh->processes, 1);
    assert(pid != INVALID_PHYSICAL);
    process p = process_alloc(uh, root, fs, pid);
    assert(p != INVALID_ADDRESS);
    p->fdtable = fdtable_alloc();
    assert(p->fdtable != INVALID_ADDRESS);
    if (!kernel) {
        p->vm = mmap_process_init(root);
        init_vdso(p);
        if (!init_process)
            init_process = p;
    }
    spin_lock(&processes_lock);
    list_insert_before(&processes, &p->l);
    spin_unlock(&processes_lock);
    create_stdfiles(uh, p);
    return p;
}

process unix_process(void)
{
    return init_process;
}

boolean process_is_init(process p)
{
    return p == init_process;
}

static boolean process_is_kernel(process p)
{
    return p->pid == 0;
}

process process_get(int pid)
{
    process found = 0;
    if (pid <= 0)
        return found;
    spin_lock(&processes_lock);
    list_foreach(&processes, l) {
        process p = struct_from_list(l, process, l);
        if (p->pid == pid) {
            process_reserve(p);
            found = p;
            break;
        }
    }
    spin_unlock(&processes_lock);
    return found;
}

void process_list_pids(vector pids)
{
    spin_lock(&processes_lock);
    list_foreach(&processes, l) {
        process p = struct_from_list(l, process, l);
        if (!process_is_kernel(p))
            vector_push(pids, pointer_from_u64((u64)p->pid));
    }
    spin_unlock(&processes_lock);
}

int process_getppid(process p)
{
    spin_lock(&processes_lock);
    int ppid = p->parent ? p->parent->pid : 0;
    spin_unlock(&processes_lock);
    return ppid;
}

static u64 processes_of_uid_locked(u32 uid)
{
    u64 n = 0;
    list_foreach(&processes, l) {
        process p = struct_from_list(l, process, l);
        if (!process_is_kernel(p) && (p->creds.uid == uid))
            n++;
    }
    return n;
}

static void process_unlink_child_locked(process c)
{
    list_delete(&c->sibling);
    list_init(&c->sibling);
    c->parent = 0;
}

void process_vfork_release(process c)
{
    process_lock(c);
    thread waiter = c->vfork_waiter;
    c->vfork_waiter = 0;
    process_unlock(c);
    if (waiter) {
        syscall_return(waiter, c->pid);
        thread_release(waiter);
    }
}

sysreturn fork_process(thread t, struct clone_args_internal *args)
{
#ifdef __x86_64__
    u64 flags = args->flags;
    process parent = t->p;
    u64 pid = allocate_u64((heap)parent->uh->processes, 1);
    if (pid == INVALID_PHYSICAL)
        return -EAGAIN;
    process c = process_alloc(parent->uh, parent->process_root, parent->root_fs, pid);
    if (c == INVALID_ADDRESS) {
        deallocate_u64((heap)parent->uh->processes, pid, 1);
        return -ENOMEM;
    }
    filesystem_release(c->cwd_fs);
    process_get_cwd(parent, &c->cwd_fs, &c->cwd);
    c->pgid = parent->pgid;
    c->dumpable = parent->dumpable;
    c->syscalls = parent->syscalls;
    c->rlimit_stack = parent->rlimit_stack;
    c->rlimit_nproc_cur = parent->rlimit_nproc_cur;
    c->rlimit_nproc_max = parent->rlimit_nproc_max;
    c->rlimit_nofile_cur = parent->rlimit_nofile_cur;
    c->rlimit_nofile_max = parent->rlimit_nofile_max;
    c->trace = parent->trace;
    runtime_memcpy(c->sigactions, parent->sigactions, sizeof(c->sigactions));
    runtime_memcpy(c->saved_aux, parent->saved_aux, sizeof(c->saved_aux));
    heap locked = heap_locked(get_kernel_heaps());
    process_lock(parent);
    buffer cmdline = parent->cmdline ? clone_buffer(locked, parent->cmdline) : 0;
    buffer exe = parent->exe ? clone_buffer(locked, parent->exe) : 0;
    boolean creds_ok = creds_copy(&c->creds, &parent->creds);
    c->no_new_privs = parent->no_new_privs;
    process_unlock(parent);
    if ((cmdline == INVALID_ADDRESS) || (exe == INVALID_ADDRESS) || !creds_ok) {
        if (cmdline && (cmdline != INVALID_ADDRESS))
            deallocate_buffer(cmdline);
        if (exe && (exe != INVALID_ADDRESS))
            deallocate_buffer(exe);
        process_release(c);
        return -ENOMEM;
    }
    c->cmdline = cmdline;
    c->exe = exe;

    spin_lock(&processes_lock);
    if (processes_of_uid_locked(c->creds.uid) >= parent->rlimit_nproc_cur) {
        spin_unlock(&processes_lock);
        process_release(c);
        return -EAGAIN;
    }
    process new_parent = (flags & CLONE_PARENT) ? parent->parent : parent;
    c->exit_signal = (flags & CLONE_PARENT) ? parent->exit_signal :
                     ((args->exit_signal <= NSIG) ? args->exit_signal : 0);
    list_insert_before(&processes, &c->l);
    c->parent = new_parent;
    list_insert_before(&new_parent->children, &c->sibling);
    spin_unlock(&processes_lock);

    sysreturn rv;
    if (flags & CLONE_VM) {
        c->vm = parent->vm;
        process_vm_reserve(c->vm);
    } else {
        c->vm = mmap_process_fork(parent->vm, &rv);
        if (c->vm == INVALID_ADDRESS) {
            c->vm = 0;
            goto fail;
        }
        init_vdso(c);
    }
    if (flags & CLONE_FILES) {
        c->fdtable = parent->fdtable;
        fdtable_reserve(c->fdtable);
    } else {
        c->fdtable = fdtable_copy(parent->fdtable);
        if (c->fdtable == INVALID_ADDRESS) {
            c->fdtable = 0;
            rv = -ENOMEM;
            goto fail;
        }
    }

    thread ct = create_thread(c, c->pid);
    if (ct == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto fail;
    }
    context_frame f = thread_frame(ct);
    clone_frame_pstate(f, thread_frame(t));
    thread_clone_sigmask(ct, t);
    seccomp_fork(ct, t);
    runtime_memcpy(ct->name, t->name, sizeof(ct->name));
    ct->signal_stack = t->signal_stack;
    ct->signal_stack_length = t->signal_stack_length;
    set_syscall_return(ct, 0);
    if (args->stack_size)
        f[SYSCALL_FRAME_SP] = u64_from_pointer(args->stack) + args->stack_size;
    if (flags & CLONE_SETTLS)
        set_tls(f, args->tls);
    if (flags & CLONE_CHILD_CLEARTID)
        ct->clear_tid = args->child_tid;
    if (flags & CLONE_CHILD_SETTID)
        ct->set_child_tid = args->child_tid;
    if (flags & CLONE_PARENT_SETTID) {
        int child_pid = c->pid;
        if (!set_user_value(args->parent_tid, child_pid)) {
            exit_thread(ct);
            rv = -EFAULT;
            goto fail;
        }
    }
    if (flags & CLONE_VFORK) {
        thread_reserve(t);
        c->vfork_waiter = t;
    }
    ct->syscall = 0;
    f[FRAME_FULL] = true;
    thread_reserve(ct);
    schedule_thread(ct);
    if (flags & CLONE_VFORK)
        return thread_maybe_sleep_uninterruptible(t);
    return c->pid;
  fail:
    spin_lock(&processes_lock);
    process_unlink_child_locked(c);
    spin_unlock(&processes_lock);
    blockq_wake_all(new_parent->child_bq);
    process_release(c);
    return rv;
#else
    return -ENOSYS;
#endif
}

static boolean process_autoreaps(process parent, int exit_signal)
{
    struct sigaction *sa = &parent->sigactions[SIGCHLD - 1];
    return (exit_signal == SIGCHLD) &&
           ((sa->sa_handler == SIG_IGN) || (sa->sa_flags & SA_NOCLDWAIT));
}

closure_function(2, 1, boolean, thread_blocks_signal,
                 u64, sigword, boolean *, blocked,
                 rbnode n)
{
    if (struct_from_field(n, thread, n)->signal_mask & bound(sigword)) {
        *bound(blocked) = true;
        return false;
    }
    return true;
}

static boolean process_discards_signal(process p, int sig)
{
    void *handler = p->sigactions[sig - 1].sa_handler;
    if (handler == SIG_IGN)
        return true;
    if (handler != SIG_DFL)
        return false;
    boolean blocked = false;
    spin_lock(&p->threads_lock);
    rbtree_traverse(p->threads, RB_INORDER,
                    stack_closure(thread_blocks_signal, mask_from_sig(sig), &blocked));
    spin_unlock(&p->threads_lock);
    return !blocked;
}

static void process_send_exit_signal(process parent, process child)
{
    int sig = child->exit_signal;
    if (!sig || process_discards_signal(parent, sig))
        return;
    int status = child->wait_status;
    struct siginfo si = {
        .si_signo = sig,
        .si_code = wait_status_is_exit(status) ? CLD_EXITED : CLD_KILLED,
    };
    si.sifields.sigchld.pid = child->pid;
    si.sifields.sigchld.uid = child->creds.uid;
    si.sifields.sigchld.status = wait_status_is_exit(status) ? (status >> 8) & 0xff : status & 0x7f;
    si.sifields.sigchld.utime = proc_utime(child) / (TIMESTAMP_SECOND / CLOCKS_PER_SEC);
    si.sifields.sigchld.stime = proc_stime(child) / (TIMESTAMP_SECOND / CLOCKS_PER_SEC);
    deliver_signal_to_process(parent, &si);
}

/* Runs once the last thread of a non-init process is gone. */
void process_teardown(process p)
{
    assert(!process_is_init(p));
    p->exiting = true;
    unix_timers_process_exit(p);
    aio_process_exit(p);
    process_lock(p);
    fdtable fdt = p->fdtable;
    p->fdtable = 0;
    process_vm vm = p->vm;
    p->vm = 0;
    process_unlock(p);
    fdtable_release(fdt);
    process_vm_release(vm);
    process_vfork_release(p);

    process init = init_process;
    vector orphaned_zombies = allocate_vector(heap_locked(get_kernel_heaps()), 4);
    assert(orphaned_zombies != INVALID_ADDRESS);
    vector parent_death_notified = allocate_vector(heap_locked(get_kernel_heaps()), 4);
    assert(parent_death_notified != INVALID_ADDRESS);
    spin_lock(&processes_lock);
    list l, next;
    for (l = p->children.next; l != &p->children; l = next) {
        next = l->next;
        process c = struct_from_list(l, process, sibling);
        list_delete(&c->sibling);
        c->parent = init;
        list_insert_before(&init->children, &c->sibling);
        if (c->state == PROCESS_ZOMBIE) {
            process_reserve(c);
            vector_push(orphaned_zombies, c);
        } else if (c->pdeathsig) {
            process_reserve(c);
            vector_push(parent_death_notified, c);
        }
    }
    process parent = p->parent;
    boolean reaped = !parent || process_autoreaps(parent, p->exit_signal);
    if (reaped) {
        if (parent)
            process_unlink_child_locked(p);
    } else {
        p->state = PROCESS_ZOMBIE;
        process_reserve(parent);
    }
    spin_unlock(&processes_lock);
    process c;
    vector_foreach(orphaned_zombies, c) {
        if (process_autoreaps(init, c->exit_signal)) {
            spin_lock(&processes_lock);
            boolean still_ours = c->parent == init;
            if (still_ours) {
                process_unlink_child_locked(c);
                list_delete(&c->l);
                list_init(&c->l);
            }
            spin_unlock(&processes_lock);
            if (still_ours)
                process_release(c);
        } else {
            process_send_exit_signal(init, c);
        }
        process_release(c);
    }
    if (vector_length(orphaned_zombies))
        blockq_wake_all(init->child_bq);
    deallocate_vector(orphaned_zombies);
    vector_foreach(parent_death_notified, c) {
        struct siginfo si = { .si_signo = c->pdeathsig, .si_code = SI_USER };
        si.sifields.kill.pid = p->pid;
        si.sifields.kill.uid = p->creds.uid;
        deliver_signal_to_process(c, &si);
        process_release(c);
    }
    deallocate_vector(parent_death_notified);
    if (reaped) {
        if (parent)
            blockq_wake_all(parent->child_bq);
        process_release(p);
        return;
    }
    process_send_exit_signal(parent, p);
    blockq_wake_all(parent->child_bq);
    process_release(parent);
}

static process wait_find_child_locked(process p, int idtype, int id, int options,
                                      boolean *eligible)
{
    *eligible = false;
    list_foreach(&p->children, l) {
        process c = struct_from_list(l, process, sibling);
        if ((idtype == P_PID) && (c->pid != id))
            continue;
        if ((idtype == P_PGID) && (c->pgid != id))
            continue;
        if (!(options & __WALL) && ((c->exit_signal != SIGCHLD) != !!(options & __WCLONE)))
            continue;
        *eligible = true;
        if ((options & WEXITED) && (c->state == PROCESS_ZOMBIE))
            return c;
    }
    return 0;
}

static sysreturn wait_report(process c, int *wstatus, struct siginfo *infop, struct rusage *ru)
{
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx))
        return -EFAULT;
    int status = c->wait_status;
    if (wstatus)
        *wstatus = status;
    if (infop) {
        infop->si_signo = SIGCHLD;
        infop->si_errno = 0;
        infop->si_code = wait_status_is_exit(status) ? CLD_EXITED : CLD_KILLED;
        infop->sifields.sigchld.pid = c->pid;
        infop->sifields.sigchld.uid = c->creds.uid;
        infop->sifields.sigchld.status = wait_status_is_exit(status) ? (status >> 8) & 0xff :
                                                                       status & 0x7f;
    }
    if (ru) {
        zero(ru, sizeof(*ru));
        timeval_from_time(&ru->ru_utime, proc_utime(c) + c->cutime);
        timeval_from_time(&ru->ru_stime, proc_stime(c) + c->cstime);
    }
    context_clear_err(ctx);
    return c->pid;
}

static sysreturn wait_report_none(struct siginfo *infop)
{
    if (!infop)
        return 0;
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx))
        return -EFAULT;
    infop->si_signo = 0;
    infop->si_errno = 0;
    infop->si_code = 0;
    infop->sifields.sigchld.pid = 0;
    infop->sifields.sigchld.uid = 0;
    infop->sifields.sigchld.status = 0;
    context_clear_err(ctx);
    return 0;
}

closure_function(8, 1, sysreturn, wait_bh,
                 thread, t, int, idtype, int, id, int, options, int *, wstatus, struct siginfo *, infop,
                 struct rusage *, ru, boolean, report_pid,
                 u64 flags)
{
    thread t = bound(t);
    process p = t->p;
    int options = bound(options);
    sysreturn rv;
    if (flags & BLOCKQ_ACTION_NULLIFY) {
        rv = -ERESTARTSYS;
        goto out;
    }
    boolean eligible;
    spin_lock(&processes_lock);
    process c = wait_find_child_locked(p, bound(idtype), bound(id), options, &eligible);
    if (c) {
        if (options & WNOWAIT) {
            process_reserve(c);
        } else {
            process_unlink_child_locked(c);
            list_delete(&c->l);
            list_init(&c->l);
            p->cutime += proc_utime(c) + c->cutime;
            p->cstime += proc_stime(c) + c->cstime;
        }
    } else if (eligible && !(options & WNOHANG)) {
        rv = blockq_block_required(&t->syscall->uc, flags);
        spin_unlock(&processes_lock);
        return rv;
    }
    spin_unlock(&processes_lock);
    if (c) {
        rv = wait_report(c, bound(wstatus), bound(infop), bound(ru));
        if (!bound(report_pid) && (rv > 0))
            rv = 0;
        process_release(c);
    } else if (!eligible) {
        rv = -ECHILD;
    } else {
        rv = wait_report_none(bound(infop));
    }
  out:
    closure_finish();
    return syscall_return(t, rv);
}

sysreturn process_wait(int idtype, int id, int options, int *wstatus, struct siginfo *infop,
                       struct rusage *ru, boolean report_pid)
{
    thread t = current;
    blockq_action ba = contextual_closure(wait_bh, t, idtype, id, options, wstatus, infop, ru,
                                          report_pid);
    if (ba == INVALID_ADDRESS)
        return -ENOMEM;
    return blockq_check(t->p->child_bq, ba, false);
}

closure_function(1, 1, boolean, process_kill_thread,
                 struct siginfo *, si,
                 rbnode n)
{
    deliver_signal_to_thread(struct_from_field(n, thread, n), bound(si));
    return true;
}

/* Every thread of the process exits at its next return to user mode. */
void process_kill(process p, int wait_status)
{
    assert(!process_is_init(p));
    struct siginfo si = { .si_signo = SIGKILL };
    process_lock(p);
    if (!p->exiting) {
        p->exiting = true;
        p->wait_status = wait_status;
    }
    process_unlock(p);
    spin_lock(&p->threads_lock);
    rbtree_traverse(p->threads, RB_INORDER, stack_closure(process_kill_thread, &si));
    spin_unlock(&p->threads_lock);
}

static boolean process_may_signal(process sender, process target, int sig)
{
    if (process_is_kernel(target))
        return false;
    if (process_is_init(target) && (sender != target)) {
        if ((sig == SIGKILL) || (sig == SIGSTOP) ||
            (target->sigactions[sig - 1].sa_handler == SIG_DFL))
            return false;
    }
    return true;
}

static boolean process_signal_permitted(process sender, process target)
{
    struct creds s, t;
    creds_snapshot(sender, &s);
    creds_snapshot(target, &t);
    return (s.cap_effective & (1ull << CAP_KILL)) || (s.euid == t.suid) || (s.euid == t.uid) ||
           (s.uid == t.suid) || (s.uid == t.uid);
}

sysreturn process_signal(process sender, int pid, struct siginfo *si)
{
    int sig = si->si_signo;
    if (pid > 0) {
        process target = process_get(pid);
        if (!target)
            return -ESRCH;
        sysreturn rv = 0;
        if (!process_signal_permitted(sender, target))
            rv = -EPERM;
        else if (sig && (target->state == PROCESS_RUNNING) &&
                 process_may_signal(sender, target, sig))
            deliver_signal_to_process(target, si);
        process_release(target);
        return rv;
    }
    int pgid = (pid == 0) ? sender->pgid : -pid;
    boolean all = (pid == -1);
    int found = 0, permitted = 0;
    vector targets = allocate_vector(heap_locked(get_kernel_heaps()), 8);
    if (targets == INVALID_ADDRESS)
        return -ENOMEM;
    spin_lock(&processes_lock);
    list_foreach(&processes, l) {
        process p = struct_from_list(l, process, l);
        if (process_is_kernel(p))
            continue;
        if (all ? (process_is_init(p) || (p == sender)) : (p->pgid != pgid))
            continue;
        found++;
        if (!process_signal_permitted(sender, p))
            continue;
        permitted++;
        if (sig && (p->state == PROCESS_RUNNING) && process_may_signal(sender, p, sig)) {
            process_reserve(p);
            vector_push(targets, p);
        }
    }
    spin_unlock(&processes_lock);
    process p;
    vector_foreach(targets, p) {
        deliver_signal_to_process(p, si);
        process_release(p);
    }
    deallocate_vector(targets);
    if (!found)
        return -ESRCH;
    return permitted ? 0 : -EPERM;
}

void process_get_cwd(process p, filesystem *cwd_fs, inode *cwd)
{
    process_lock(p);
    *cwd_fs = p->cwd_fs;
    filesystem_reserve(*cwd_fs);
    *cwd = p->cwd;
    process_unlock(p);
}

timestamp proc_utime(process p)
{
    return p->utime;
}

timestamp proc_stime(process p)
{
    return p->stime;
}

timestamp thread_utime(thread t)
{
    return t->utime;
}

timestamp thread_stime(thread t)
{
    return t->stime;
}

void cputime_update(thread t, timestamp delta, boolean is_utime)
{
    if (t->cpu_timers)
        timer_service(t->cpu_timers, thread_cputime(t));
    process p = t->p;
    fetch_and_add(is_utime ? &p->utime : &p->stime, delta);
    timer_service(p->cpu_timers, proc_cputime(p));
}

closure_func_basic(mem_cleaner, u64, unix_mem_cleaner,
                   u64 clean_bytes)
{
    unix_heaps uh = struct_from_field(closure_self(), unix_heaps, mem_cleaner);
    u64 cleaned = cache_drain(uh->file_cache, clean_bytes, 0);
    if (cleaned < clean_bytes)
        cleaned += cache_drain(uh->pipe_cache, clean_bytes - cleaned, 0);
    if (cleaned < clean_bytes)
        cleaned += cache_drain(uh->socket_cache, clean_bytes - cleaned, 0);
    return cleaned;
}

process init_unix(kernel_heaps kh, tuple root, filesystem fs)
{
    heap h = heap_locked(kh);
    unix_heaps uh = allocate(h, sizeof(struct unix_heaps));

    /* a failure here means termination; just leak */
    if (uh == INVALID_ADDRESS)
	return INVALID_ADDRESS;

    u_heap = uh;
    list_init(&processes);
    spin_lock_init(&processes_lock);
    init_address_spaces(h);
    init_shared_pages(h);
    mmap_init(root);
#ifdef __x86_64__
    init_vsyscall();
#endif
    uh->processes = locking_heap_wrapper(h, (heap)create_id_heap(h, h, 1, 65535, 1, false));
    uh->file_cache = allocate_objcache(h, (heap)heap_page_backed(kh), sizeof(struct file),
                                       PAGESIZE, true);
    if (uh->file_cache == INVALID_ADDRESS)
	goto alloc_fail;
    if (!poll_init(uh))
	goto alloc_fail;
    if (!pipe_init(uh))
	goto alloc_fail;
    if (!unix_timers_init(uh))
        goto alloc_fail;
    if (ftrace_init(uh, fs))
	goto alloc_fail;
#ifdef LOCK_STATS
    lockstats_init(kh);
#endif
#ifdef NET
    if (!netsyscall_init(uh, root))
        goto alloc_fail;
#endif
    process kernel_process = create_process(uh, root, fs);
    dummy_thread = create_thread(kernel_process, kernel_process->pid);
    runtime_memcpy(dummy_thread->name, "dummy_thread",
        sizeof(dummy_thread->name));

    cpuinfo ci;
    vector_foreach(cpuinfos, ci) {
        syscall_context sc = allocate_syscall_context(ci);
        assert(sc != INVALID_ADDRESS);
        ci->m.syscall_context = &sc->uc.kc.context;
    }

    /* XXX remove once we have http PUT support */
    ftrace_enable();

    register_special_files(kernel_process);
    init_syscalls(kernel_process);
    register_file_syscalls(linux_syscalls);
#ifdef NET
    register_net_syscalls(linux_syscalls);
#endif

    register_signal_syscalls(linux_syscalls);
    register_mmap_syscalls(linux_syscalls);
    register_thread_syscalls(linux_syscalls);
    register_poll_syscalls(linux_syscalls);
    register_clock_syscalls(linux_syscalls);
    register_timer_syscalls(linux_syscalls);
    register_other_syscalls(linux_syscalls);

    tuple coredumplimit = get(root, sym(coredumplimit));
    if (coredumplimit && is_string(coredumplimit)) {
        buffer b = alloca_wrap((buffer)coredumplimit);
        u64 size;
        if (!parse_int(b, 10, &size))
            goto out;
        char suffix = (char)pop_u8(b);
        if ((suffix == 'k') || (suffix == 'K'))
            size *= KB;
        else if ((suffix == 'm') || (suffix == 'M'))
            size *= MB;
        else if ((suffix == 'g') || (suffix == 'G'))
            size *= GB;
        coredump_set_limit(size);
    }
    assert(mm_register_mem_cleaner(init_closure_func(&uh->mem_cleaner, mem_cleaner,
                                                     unix_mem_cleaner)));
out:
    return kernel_process;
  alloc_fail:
    msg_err("%s: failed to allocate kernel objects", func_ss);
    return INVALID_ADDRESS;
}

closure_function(1, 2, void, shutdown_timeout,
                 struct timer, shutdown_timer,
                 u64 expiry, u64 overruns)
{
    closure_finish();
    if (overruns == timer_disabled)
        return;
    if (!(shutting_down & SHUTDOWN_ONGOING))
        kernel_shutdown(0);
}

void unix_shutdown(void)
{
    heap h = heap_locked(get_kernel_heaps());
    /* Skip kernel unix process for shutdown */
    spin_lock(&processes_lock);
    list_foreach(&processes, l) {
        process p = struct_from_list(l, process, l);
        if (process_is_kernel(p) || p->exiting)
            continue;
        struct siginfo *si = allocate_zero(h, sizeof(struct siginfo));
        if (si == INVALID_ADDRESS) {
            spin_unlock(&processes_lock);
            kernel_shutdown(0);
            return;
        }
        si->si_signo = SIGTERM;
        deliver_signal_to_process(p, si);
    }
    spin_unlock(&processes_lock);
    struct timer shutdown_timer = {0};
    init_timer(&shutdown_timer);
    timer_handler th = closure(h, shutdown_timeout, shutdown_timer);
    register_timer(kernel_timers, &closure_member(shutdown_timeout, th, shutdown_timer),
        CLOCK_ID_MONOTONIC, seconds(UNIX_SHUTDOWN_TIMEOUT_SECS), false, 0, th);
}

void program_set_perms(tuple root, tuple prog)
{
    if (get(root, sym(exec_protection)))
        set(prog, sym(exec), null_value);
    else if (!get(root, sym(program_overwrite)))
        set(prog, sym(readonly), null_value);
}

static void dump_heap_stats(buffer b, sstring name, heap h)
{
    bytes allocated = heap_allocated(h);
    bytes total = heap_total(h);
    if ((total != INVALID_PHYSICAL) && (total != 0)) {
        bprintf(b, " %s: total %ld, allocated %ld (%d%%)\n", name, total,
                allocated, 100 * allocated / total);
    } else {
        bprintf(b, " %s: allocated %ld\n", name, allocated);
    }
}

void dump_mem_stats(buffer b)
{
    unix_heaps uh = get_unix_heaps();
    kernel_heaps kh = get_kernel_heaps();
    bprintf(b, "Kernel heaps:\n");
    dump_heap_stats(b, ss("general"), heap_general(kh));
    dump_heap_stats(b, ss("physical"), (heap)heap_physical(kh));
    dump_heap_stats(b, ss("virtual huge"), (heap)heap_virtual_huge(kh));
    dump_heap_stats(b, ss("virtual page"), (heap)heap_virtual_page(kh));
    bprintf(b, "Unix heaps:\n");
    dump_heap_stats(b, ss("file cache"), (heap)uh->file_cache);
    dump_heap_stats(b, ss("pipe cache"), (heap)uh->pipe_cache);
    dump_heap_stats(b, ss("socket cache"), (heap)uh->socket_cache);
}
