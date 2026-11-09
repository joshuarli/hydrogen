#include <unix_internal.h>
#include <seccomp.h>
#include <ftrace.h>
#include <gdb.h>

BSS_RO_AFTER_INIT thread dummy_thread;

sysreturn gettid()
{
    return current->tid;
}

sysreturn set_tid_address(int *a)
{
    current->clear_tid = a;
    return current->tid;
}

#ifdef __x86_64__
sysreturn arch_prctl(int code, unsigned long addr)
{
    /* just validate the word at base */
    if ((code == ARCH_SET_FS || code == ARCH_SET_GS) &&
        !memory_is_user((void *)addr, sizeof(u64)))
        return set_syscall_error(current, EFAULT);

    switch (code) {
    case ARCH_SET_GS:
        thread_frame(current)[FRAME_GSBASE] = addr;
        break;
    case ARCH_SET_FS:
        thread_frame(current)[FRAME_FSBASE] = addr;
        return 0;
    case ARCH_GET_FS:
        if (!set_user_value((u64 *)addr, thread_frame(current)[FRAME_FSBASE]))
            return -EFAULT;
        break;
    case ARCH_GET_GS:
        if (!set_user_value((u64 *)addr, thread_frame(current)[FRAME_GSBASE]))
            return -EFAULT;
        break;
    default:
        return set_syscall_error(current, EINVAL);
    }
    return 0;
}
#endif

#define CLONE_UNSUPPORTED_NAMESPACES    (CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | \
                                         CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNET)

static sysreturn clone_validate(u64 flags)
{
    if ((flags & (CLONE_NEWNS | CLONE_FS)) == (CLONE_NEWNS | CLONE_FS))
        return -EINVAL;
    if ((flags & (CLONE_NEWUSER | CLONE_FS)) == (CLONE_NEWUSER | CLONE_FS))
        return -EINVAL;
    if ((flags & CLONE_THREAD) && !(flags & CLONE_SIGHAND))
        return -EINVAL;
    if ((flags & CLONE_SIGHAND) && !(flags & CLONE_VM))
        return -EINVAL;
    if ((flags & CLONE_THREAD) && (flags & (CLONE_NEWUSER | CLONE_NEWPID)))
        return -EINVAL;
    if ((flags & CLONE_PARENT) && process_is_init(current->p))
        return -EINVAL;
    if (flags & CLONE_UNSUPPORTED_NAMESPACES)
        return -EINVAL;
    if (flags & CLONE_NEWUSER) {
        process p = current->p;
        if (process_is_chrooted(p))
            return -EPERM;
        process_lock(p);
        u32 level = p->creds.user_ns->level;
        process_unlock(p);
        if (level >= USER_NS_LEVEL_MAX)
            return -EUSERS;
    }
    if (flags & CLONE_PIDFD) {
        msg_warn("clone: pidfds are not supported");
        return -EINVAL;
    }
    if (!(flags & CLONE_THREAD) && (flags & CLONE_SIGHAND)) {
        msg_warn("clone: sharing signal handlers between processes is not supported");
        return -ENOSYS;
    }
    return 0;
}

static sysreturn clone_internal(struct clone_args_internal *args)
{
     u64 flags = args->flags;
     void *stack = args->stack;
     bytes stack_size = args->stack_size;

     sysreturn rv = clone_validate(flags);
     if (rv)
          return rv;

     if (stack_size && !memory_is_user(stack, stack_size))
          return -EFAULT;

     if (((flags & CLONE_PARENT_SETTID) &&
          !memory_is_user(args->parent_tid, sizeof(int))) ||
         ((flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID)) &&
          !memory_is_user(args->child_tid, sizeof(int))))
          return -EFAULT;

     if (!(flags & CLONE_THREAD))
          return fork_process(current, args);

     if (!stack_size)
          return -EINVAL;

     thread t = create_thread(current->p, INVALID_PHYSICAL);
     context_frame f = thread_frame(t);

     clone_frame_pstate(f, thread_frame(current));
     thread_clone_sigmask(t, current);
     spin_lock(&current->p->threads_lock);
     seccomp_fork(t, current);
     spin_unlock(&current->p->threads_lock);

     set_syscall_return(t, 0);
     f[SYSCALL_FRAME_SP] = (u64)stack + stack_size;
     if (flags & CLONE_SETTLS)
	  set_tls(f, args->tls);
     context ctx = get_current_context(current_cpu());
     if (context_set_err(ctx)) {
         exit_thread(t);
         return -EFAULT;
     }
     if (flags & CLONE_PARENT_SETTID)
	  *(args->parent_tid) = t->tid;
     if (flags & CLONE_CHILD_SETTID)
	  *(args->child_tid) = t->tid;
     context_clear_err(ctx);
     if (flags & CLONE_CHILD_CLEARTID)
	  t->clear_tid = args->child_tid;
     t->syscall = 0;
     f[FRAME_FULL] = true;
     thread_reserve(t);
     schedule_thread(t);
     return t->tid;
}

#ifdef __x86_64__
sysreturn fork(void)
{
    struct clone_args_internal args = {
        .flags = 0,
        .exit_signal = SIGCHLD,
    };
    return fork_process(current, &args);
}

sysreturn vfork(void)
{
    struct clone_args_internal args = {
        .flags = CLONE_VM | CLONE_VFORK,
        .exit_signal = SIGCHLD,
    };
    return fork_process(current, &args);
}
#endif

#if defined(__x86_64__)
sysreturn clone(unsigned long flags, void *child_stack, int *ptid, int *ctid, unsigned long newtls)
#elif defined(__aarch64__) || defined(__riscv)
sysreturn clone(unsigned long flags, void *child_stack, int *ptid, unsigned long newtls, int *ctid)
#endif
{
    flags &= MASK(32);
    struct clone_args_internal args = {
         .flags = flags & ~CSIGNAL,
         .exit_signal = flags & CSIGNAL,
         .child_tid = ctid,
         .parent_tid = ptid,
         /* no stack size given, just validate the top word */
         .stack = child_stack ? child_stack - sizeof(u64) : 0,
         .stack_size = child_stack ? sizeof(u64) : 0,
         .tls = newtls,
    };

    return clone_internal(&args);
}

sysreturn clone3(struct clone_args *uargs, bytes size)
{
     if (size < CLONE_ARGS_SIZE_VER0)
          return -EINVAL;
     if (size > PAGESIZE)
          return -E2BIG;

     if (!memory_is_user(uargs, size))
          return -EFAULT;

     struct clone_args args;
     zero(&args, sizeof(args));
     context ctx = get_current_context(current_cpu());
     if (context_set_err(ctx))
         return -EFAULT;
     runtime_memcpy(&args, uargs, MIN(size, sizeof(args)));
     boolean trailing = false;
     for (bytes i = sizeof(args); i < size; i++)
          if (((u8 *)uargs)[i])
               trailing = true;
     context_clear_err(ctx);
     if (trailing)
          return -E2BIG;

     if (args.flags & ~(MASK(32) | CLONE_CLEAR_SIGHAND | CLONE_INTO_CGROUP))
          return -EINVAL;
     if (args.flags & (CLONE_DETACHED | (CSIGNAL & ~CLONE_NEWTIME)))
          return -EINVAL;
     if ((args.flags & (CLONE_SIGHAND | CLONE_CLEAR_SIGHAND)) ==
         (CLONE_SIGHAND | CLONE_CLEAR_SIGHAND))
          return -EINVAL;
     if ((args.exit_signal & ~(u64)CSIGNAL) || (args.exit_signal > NSIG))
          return -EINVAL;
     if ((!args.stack && args.stack_size) || (args.stack && !args.stack_size))
          return -EINVAL;
     if (args.set_tid || args.set_tid_size)
          return -EINVAL;
     if (args.flags & (CLONE_NEWTIME | CLONE_CLEAR_SIGHAND | CLONE_INTO_CGROUP))
          return -EINVAL;

     struct clone_args_internal argsi = {
          .flags = args.flags,
          .exit_signal = args.exit_signal,
          .child_tid = (int *)args.child_tid,
          .parent_tid = (int *)args.parent_tid,
          .stack = (void *)args.stack,
          .stack_size = args.stack_size,
          .tls = args.tls
     };

     return clone_internal(&argsi);
}

void register_thread_syscalls(struct syscall *map)
{
    register_syscall(map, futex, futex);
    register_syscall(map, set_robust_list, set_robust_list);
    register_syscall(map, get_robust_list, get_robust_list);
    register_syscall(map, clone, clone);
    register_syscall(map, clone3, clone3);
#ifdef __x86_64__
    register_syscall(map, arch_prctl, arch_prctl);
    register_syscall(map, fork, fork);
    register_syscall(map, vfork, vfork);
    register_syscall(map, execve, execve);
    register_syscall(map, execveat, execveat);
#endif
    register_syscall(map, set_tid_address, set_tid_address);
    register_syscall(map, gettid, gettid);
}

void thread_log_internal(thread t, sstring desc, ...)
{
    vlist ap;
    vstart (ap, desc);
    buffer b = little_stack_buffer(512);
#ifndef CONFIG_TRACELOG
    bprintf(b, "%n%d ", (int) ((MAX(MIN(t->tid, 20), 1) - 1) * 4), t->tid);
#endif
    sstring name = sstring_from_cstring(t->name, sizeof(t->name));
    if (!sstring_is_empty(name))
        bprintf(b, "[%s] ", name);
    vbprintf(b, desc, &ap);
    push_u8(b, '\n');
#ifdef CONFIG_TRACELOG
    tprintf(sym(thread), t->tracelog_attrs, ss("%b"), b);
#else
    buffer_print(b);
#endif
}

static inline boolean check_stop_conditions(thread t)
{
    sstring cause;
    int sig;
    u64 pending = sigstate_get_pending(&t->signals);

    /* rather abrupt to just halt...this should go do dump or recovery */
    if (pending & mask_from_sig(SIGSEGV)) {
        void * handler = sigaction_from_sig(t, SIGSEGV)->sa_handler;

        /* Terminate on uncaught SIGSEGV, or if triggered by signal handler. */
        if (handler == SIG_IGN || handler == SIG_DFL) {
            cause = ss("Unhandled SIGSEGV");
            sig = SIGSEGV;
            goto terminate;
        }
    }

    boolean is_sigkill = (pending & mask_from_sig(SIGKILL)) != 0;
    if (is_sigkill || (pending & mask_from_sig(SIGSTOP))) {
        cause = is_sigkill ? ss("SIGKILL") : ss("SIGSTOP");
        sig = is_sigkill ? SIGKILL : SIGSTOP;
        goto terminate;
    }
    return false;
  terminate:
    if (!process_is_init(t->p)) {
        process_kill(t->p, wait_status_signaled(sig));
        return true;
    }
    rprintf("\nProcess abort: %s received by thread %d\n\n", cause, t->tid);
    dump_context(&t->context);
    halt("Terminating.\n");
}

static void thread_cputime_update(thread t)
{
    if (t->start_time != 0) {
        timestamp diff = now(CLOCK_ID_MONOTONIC_RAW) - t->start_time;
        t->utime += diff;
        t->task.runtime += diff;
        t->start_time = 0;
        cputime_update(t, diff, true);
    }
}

static void thread_pause(context ctx)
{
    if (shutting_down & SHUTDOWN_ONGOING)
        return;
    thread t = (thread)ctx;
    context_frame f = thread_frame(t);
    thread_cputime_update(t);
    thread_frame_save_fpsimd(f);
    thread_frame_save_tls(f);
}

static void thread_resume(context ctx)
{
    thread t = (thread)ctx;
    assert(t->start_time == 0); // XXX tmp debug
    timestamp here = now(CLOCK_ID_MONOTONIC_RAW);
    t->start_time = here == 0 ? 1 : here;
    context_frame f = thread_frame(t);
    thread_frame_restore_tls(f);
    thread_frame_restore_fpsimd(f);
    frame_enable_interrupts(f);
}

static void thread_schedule_return(context ctx)
{
    thread t = (thread)ctx;
    thread_cputime_update(t);   /* so that it is scheduled based on how much CPU time it used */
    sched_enqueue(t->scheduling_queue, &t->task);
}

closure_func_basic(thunk, void, thread_return)
{
    cpuinfo ci = current_cpu();
    thread t = struct_from_closure(thread, thread_return);
    if (t->p->trap)
        runloop(); // XXX pause?

    address_space_switch(t->context.as);

    /* temporarily install fault handler to catch faults for stack pages */
    use_fault_handler(t->context.fault_handler);
    if (t->set_child_tid) {
        int tid = t->tid;
        set_user_value(t->set_child_tid, tid);
        t->set_child_tid = 0;
    }
    thread_lock(t);
    /* Keep track of the CPU on which this thread is about to run, so that the thread will continue
     * to be scheduled on the same CPU (unless the CPU affinity does not allow it). */
    if ((t->scheduling_queue != &ci->thread_queue) && (bitmap_get(t->task.affinity, ci->id)))
        t->scheduling_queue = &ci->thread_queue;
    thread_unlock(t);
    if (thread_replaced_by_exec(t))
        goto exit;
    while (true) {
        dispatch_signals(t);
        ci->state = cpu_user;
        memory_barrier();
        if (check_stop_conditions(t))
            goto exit;
        if (!thread_has_dispatchable_signal(t))
            break;
        ci->state = cpu_kernel;
    }
    // XXX fixme
    //ftrace_thread_switch(old, t);    /* ftrace needs to know about the switch event */

    thread_lock(t);
    /* cover wake-before-sleep situations (e.g. sched yield, fs ops that don't go to disk, etc.) */
    t->syscall = 0;
    thread_unlock(t);

    context_frame f = t->context.frame;
    assert(f[FRAME_FULL]);
    thread_trace(t, TRACE_THREAD_RUN, "run thread, cpu %d, frame %p, pc 0x%lx, sp 0x%lx, rv 0x%lx",
                 current_cpu()->id, f, f[SYSCALL_FRAME_PC], f[SYSCALL_FRAME_SP], f[SYSCALL_FRAME_RETVAL1]);
    clear_fault_handler();
    context_switch(&t->context);
    thread_release(t);
    frame_return(thread_frame(t));
    halt("return from frame_return!\n");
  exit:
    {
        process p = t->p;
        boolean last = exit_thread(t);
        clear_fault_handler();
        if (last)
            process_teardown(p);
        thread_release(t);
        runloop();
    }
}

void thread_sleep_interruptible(void)
{
    unix_context ctx = (unix_context)get_current_context(current_cpu());
    thread_log(current, "sleep interruptible (on \"%s\")", blockq_name(ctx->blocked_on));
    if (is_syscall_context(&ctx->kc.context)) {
        thread t = ((syscall_context)ctx)->t;
        ftrace_thread_switch(t, 0);
        syscall_yield();
    } else {
        kern_yield();
    }
}

void thread_sleep_uninterruptible(thread t)
{
    t->syscall->uc.blocked_on = INVALID_ADDRESS;
    thread_log(current, "sleep uninterruptible");
    ftrace_thread_switch(t, 0);
    thread_unlock(t);
    syscall_yield();
}

void thread_yield(void)
{
    current->syscall = 0;
    set_syscall_return(current, 0);
    syscall_finish(false);
}

/* Schedule a thread for execution, disassociating the syscall context with
   the thread. Execution stays on the syscall context into runloop(), at which
   point pause and release are called and the context is placed on a free list. */
void thread_wakeup(thread t)
{
    syscall_context sc = t->syscall;
    blockq bq = sc->uc.blocked_on;
    assert(bq);
    thread_log(current, "%s: %ld->%ld blocked_on %s, RIP=0x%lx", func_ss, current->tid, t->tid,
               bq != INVALID_ADDRESS ? blockq_name(bq) : ss("uninterruptible"),
               thread_frame(t)[SYSCALL_FRAME_PC]);
    sc->uc.blocked_on = 0;
    t->syscall = 0;
    context_release_refcount(&sc->uc.kc.context);
    schedule_thread(t);
}

/* hacky callback for interrupt dispatch - should be scheduler interface */
void thread_reenqueue(thread t)
{
    schedule_thread(t);
}

boolean thread_attempt_interrupt(thread t)
{
    thread_log(current, "%s: tid %d", func_ss, t->tid);
    unix_context ctx;
    blockq bq;
    boolean success = false;
    thread_lock(t);
    if (!thread_in_interruptible_sleep(t)) {
        thread_log(current, "   uninterruptible or already running");
        bq = 0;
    } else {
        ctx = &t->syscall->uc;
        bq = ctx->blocked_on;
        blockq_reserve(bq);
    }
    thread_unlock(t);

    /* flush pending blockq */
    if (bq) {
        thread_log(current, "   attempting to interrupt blocked thread %d", t->tid);
        if (blockq_wake_one_for_thread(bq, ctx, true))
            success = true;
        blockq_release(bq);
    }
    return success;
}

closure_func_basic(clock_now, timestamp, thread_now)
{
    thread t = struct_from_field(closure_self(), thread, now);
    return thread_cputime(t);
}

timerqueue thread_get_cpu_timer_queue(thread t)
{
    thread_lock(t);
    if (!t->cpu_timers) {
        timerqueue tq = allocate_timerqueue(heap_locked(get_kernel_heaps()),
                                            init_closure_func(&t->now, clock_now, thread_now),
                                            sstring_from_cstring(t->name, sizeof(t->name)));
        if (tq != INVALID_ADDRESS)
            t->cpu_timers = tq;
    }
    thread_unlock(t);
    return t->cpu_timers;
}

closure_func_basic(thunk, void, free_thread)
{
    thread t = struct_from_closure(thread, free);
    if (t->cpu_timers)
        deallocate_timerqueue(t->cpu_timers);
    deallocate_bitmap(t->task.affinity);
    destruct_context(&t->context);
    /* XXX only free tids from non-leader threads. Leader threads will
     * need different handling */
    process p = t->p;
    if (p->pid != t->tid)
        deallocate_u64((heap)get_unix_heaps()->processes, t->tid, 1);
    deallocate(heap_locked(get_kernel_heaps()), t, sizeof(struct thread));
    process_release(p);
    /* TODO: Intentionally leaking tracelog_attrs; no accounting for attrs lifetime... */
}

thread create_thread(process p, u64 tid)
{
    heap h = heap_locked(get_kernel_heaps());

    thread t = allocate(h, sizeof(struct thread));
    if (t == INVALID_ADDRESS)
        goto fail;
    if (!init_context(&t->context, CONTEXT_TYPE_THREAD, 0))
        goto fail_ctx;
    t->context.pause = thread_pause;
    t->context.resume = thread_resume;
    t->context.schedule_return = thread_schedule_return;
    t->context.pre_suspend = 0;
    t->task.t = init_closure_func(&t->thread_return, thunk, thread_return);
    t->task.runtime = 0;

    t->thread_bq = allocate_blockq(h, ss("thread"));
    if (t->thread_bq == INVALID_ADDRESS)
        goto fail_bq;

    t->p = p;
    process_reserve(p);
    t->context.as = p->vm ? p->vm->as : 0;
    t->syscall = 0;
    runtime_memcpy(&t->uh, p->uh, sizeof(*p->uh));
    init_refcount(&t->context.refcount, 1, init_closure_func(&t->free, thunk, free_thread));
    t->select_epoll = 0;
    init_rbnode(&t->n);
    t->clear_tid = 0;
    t->set_child_tid = 0;
    t->name[0] = '\0';

    init_thread_fault_handler(t);

    t->scheduling_queue = &current_cpu()->thread_queue;
    context_frame f = thread_frame(t);
#ifdef __x86_64__
    f[FRAME_CS] = 0x2b & ~1; // CS 0x28 + CPL 3 but clear bit 0 to indicate syscall
    f[FRAME_SS] = USER_DATA_SELECTOR | 0x3 /* RPL */;
#endif
#ifdef __aarch64__
    f[FRAME_EL] = 0;
#endif
#ifdef __riscv
    f[FRAME_STATUS] = FS_INITIAL<<STATUS_BIT_FS;
#endif

    t->signal_stack = 0;
    t->signal_stack_length = 0;
    t->seccomp_mode = 0;
    t->seccomp = 0;
    t->no_new_privs = false;
    bitmap affinity = allocate_bitmap(h, h, total_processors);
    if (affinity == INVALID_ADDRESS)
        goto fail_affinity;
    bitmap_range_check_and_set(affinity, 0, total_processors, false, true);
    t->task.affinity = affinity;
    t->syscall_complete = false;
    init_sigstate(&t->signals);
    t->signal_mask = 0;
    t->saved_signal_mask = -1ull;
    t->interrupting_syscall = false;
    t->utime = t->stime = 0;
    t->start_time = 0;
    t->cpu_timers = 0;

    spin_lock_init(&t->lock);

    /* install gdb fault handler if gdb is inited */
    gdb_check_fault_handler(t);
    if (tid != INVALID_PHYSICAL)
        t->tid = tid;
    else
        t->tid = allocate_u64(p->uh->processes, 1);
    assert(t->tid != INVALID_PHYSICAL);
    spin_lock(&p->threads_lock);
    rbtree_insert_node(p->threads, &t->n);
    spin_unlock(&p->threads_lock);
#ifdef CONFIG_TRACELOG
    t->tracelog_attrs = allocate_tuple();
    if (t->tracelog_attrs == INVALID_ADDRESS) {
        deallocate_bitmap(t->affinity);
        goto fail_affinity;
    }
    set(t->tracelog_attrs, sym(tid), aprintf(h, "%d", t->tid));
#endif
    return t;
  fail_affinity:
    process_release(p);
    deallocate_blockq(t->thread_bq);
  fail_bq:
    destruct_context(&t->context);
  fail_ctx:
    deallocate(h, t, sizeof(struct thread));
  fail:
    msg_err("thread: failed to allocate structure");
    return INVALID_ADDRESS;
}

NOTRACE
boolean exit_thread(thread t)
{
    process p = t->p;
    spin_lock(&p->threads_lock);
    rbtree_remove_by_key(p->threads, &t->n);
    u64 remaining = rbtree_get_count(p->threads);
    boolean last = remaining == 0;
    context exec_waiter = 0;
    if (remaining == 1) {
        exec_waiter = p->exec_waiter;
        p->exec_waiter = 0;
    }
    if (p->exec_thread == t)
        p->exec_thread = 0;
    spin_unlock(&p->threads_lock);
    if (exec_waiter)
        context_schedule_return(exec_waiter);
    t->signal_mask = -1ull;

    /* dequeue signals for thread */
    sigstate_flush_queue(&t->signals);

    if (t->clear_tid) {
        int val = 0;
        if (set_user_value(t->clear_tid, val))
            futex_wake_one_by_uaddr(t->p, t->clear_tid);    /* ignore errors */
    }

    if (t->select_epoll)
        epoll_finish(t->select_epoll);

    wake_robust_list(t);
    t->robust_list = 0;
    seccomp_thread_exit(t);

    blockq_flush(t->thread_bq);
    deallocate_blockq(t->thread_bq);
    t->thread_bq = INVALID_ADDRESS;
    thread_release(t);
    return last;
}

closure_func_basic(rbnode_handler, boolean, tid_print_key,
                   rbnode n)
{
    rprintf(" %d", struct_from_field(n, thread, n)->tid);
    return true;
}

closure_func_basic(rb_key_compare, int, thread_tid_compare,
                   rbnode a, rbnode b)
{
    thread ta = struct_from_field(a, thread, n);
    thread tb = struct_from_field(b, thread, n);
    return ta->tid == tb->tid ? 0 : (ta->tid < tb->tid ? -1 : 1);
}

closure_function(1, 1, boolean, vector_from_tree_handler,
                 vector, v,
                 rbnode n)
{
    thread t = struct_from_field(n, thread, n);
    vector_push(bound(v), t);
    return true;
}

void threads_to_vector(process p, vector v)
{
    rbtree_traverse(p->threads, RB_INORDER, stack_closure(vector_from_tree_handler, v));
}

void init_threads(process p)
{
    heap h = heap_locked(get_kernel_heaps());
    p->threads = allocate_rbtree(h, closure_func(h, rb_key_compare, thread_tid_compare),
                                 closure_func(h, rbnode_handler, tid_print_key));
    spin_lock_init(&p->threads_lock);
}
