#include <unix_internal.h>
#include <elf64.h>
#include <gdb.h>
#include <symtab.h>
#include <filesystem.h>
#include <ltrace.h>

//#define EXEC_DEBUG
#ifdef EXEC_DEBUG
#define exec_debug(x, ...) do {tprintf(sym(exec), 0, ss(x), ##__VA_ARGS__);} while(0)
#else
#define exec_debug(x, ...)
#endif

#define DEFAULT_PROG_ADDR       0x400000

static void *stack_prealloc(process p, void *start, u64 size)
{
    u64 sphys = mem_alloc_u64((heap)heap_physical(get_kernel_heaps()), size, MEM_NOFAIL);
    start -= size;
    exec_debug("stack prealloc at %p, size 0x%lx, phys 0x%lx\n", start, size, sphys);
    address_space_map(p->vm->as, u64_from_pointer(start), sphys, size,
                      pageflags_writable(pageflags_default_user()));
    return start;
}

#define check_s(__p, __s, __a) do { if ((void*)(__s) < (__a))                \
            (__a) = stack_prealloc((__p), (__a), pad((__a) - (void*)(__s), PAGESIZE)); } while(0);

typedef struct exec_args {
    buffer strings;
    u64 argc;
    u64 envc;
    u64 argv_bytes;
    sstring execfn;
} *exec_args;

static boolean exec_args_push(exec_args args, sstring s)
{
    return buffer_write_sstring(args->strings, s) && buffer_write_byte(args->strings, '\0');
}

closure_function(2, 2, boolean, environment_each,
                 exec_args, args, buffer, b,
                 value n, value v)
{
    assert(is_symbol(n));
    buffer b = bound(b);
    buffer_clear(b);
    bprintf(b, "%b=%b", symbol_string(n), v);
    if (!exec_args_push(bound(args), buffer_to_sstring(b)))
        return false;
    bound(args)->envc++;
    return true;
}

closure_function(1, 2, boolean, fill_arguments_each,
                 vector, r,
                 value a, value v)
{
    u64 i;
    if (!u64_from_attribute(a, &i)) {
        msg_err("arguments attribute %v is not an index", a);
        return false;
    }
    vector_set(bound(r), i, v);
    return true;
}

static void exec_args_from_manifest(exec_args args, tuple process_root, heap h)
{
    args->strings = allocate_buffer(h, 256);
    assert(args->strings != INVALID_ADDRESS);
    args->argc = args->envc = 0;
    value arg_value = get(process_root, sym(arguments));
    vector arguments;
    if (is_vector(arg_value)) {
        arguments = arg_value;
    } else {
        if (is_tuple(arg_value)) {
            arguments = allocate_vector(transient, tuple_count(arg_value));
            if (!iterate(arg_value, stack_closure(fill_arguments_each, arguments)))
                halt("failed to parse program arguments\n");
        } else if (!arg_value) {
            arguments = allocate_vector(transient, 1);
        } else {
            halt("program arguments must be a vector or tuple\n");
        }
    }
    value program = get(process_root, sym(program));
    assert(program);
    if (vector_length(arguments) == 0)
        vector_push(arguments, program);
    buffer a;
    vector_foreach(arguments, a) {
        if (!a)
            continue;
        assert(exec_args_push(args, buffer_to_sstring(a)));
        args->argc++;
    }
    args->argv_bytes = buffer_length(args->strings);
    if (arguments != arg_value)
        deallocate_vector(arguments);
    tuple environment = get_tuple(process_root, sym(environment));
    if (environment) {
        buffer b = allocate_buffer(transient, 128);
        assert(iterate(environment, stack_closure(environment_each, args, b)));
        deallocate_buffer(b);
    }
    args->execfn = buffer_to_sstring(program);
}

static void process_set_image_names(process p, buffer cmdline, buffer exe)
{
    process_lock(p);
    buffer old_cmdline = p->cmdline;
    buffer old_exe = p->exe;
    p->cmdline = cmdline;
    p->exe = exe;
    process_unlock(p);
    if (old_cmdline)
        deallocate_buffer(old_cmdline);
    if (old_exe)
        deallocate_buffer(old_exe);
}

#define EXEC_STACK_SIZE_MIN     MB
#define EXEC_STACK_SIZE_MAX     (256 * MB)

static u64 exec_stack_size(process p)
{
    return MIN(MAX(p->rlimit_stack, EXEC_STACK_SIZE_MIN), EXEC_STACK_SIZE_MAX);
}

static void build_exec_stack(process p, thread t, Elf64_Ehdr * e, void *start,
        u64 va, u64 interp_load_addr, boolean aslr, exec_args args)
{
    exec_debug("build_exec_stack start %p, tid %d, va 0x%lx\n", start, t->tid, va);

    /* allocate process stack at top of 32-bit address space */
    u64 stack_size = exec_stack_size(p);
    u64 stack_start = 0x100000000 - stack_size;
    if (aslr)
        stack_start = (stack_start - PROCESS_STACK_ASLR_RANGE) +
            get_aslr_offset(PROCESS_STACK_ASLR_RANGE);

    p->vm->stack_map = allocate_vmap(p, irange(stack_start, stack_start + stack_size),
                                 ivmap(VMAP_FLAG_STACK | VMAP_FLAG_READABLE | VMAP_FLAG_WRITABLE,
                                       0, 0, 0, 0));
    assert(p->vm->stack_map != INVALID_ADDRESS);

    u64 *s = (pointer_from_u64(stack_start) + stack_size);
    void *stack_low = stack_prealloc(p, (void*)s, PROCESS_STACK_PREALLOC_SIZE);

    /* 16 bytes of random data for userspace (e.g. SSP guard init) */
    for (int i = 0; i < 2; i++) {
        s--;
        *s = random_u64();
    }
    u64 *randbuf = s;

    s -= pad(args->execfn.len + 1, STACK_ALIGNMENT) >> 3;
    check_s(p, s, stack_low);
    char *execfn = (char *)s;
    runtime_memcpy(execfn, args->execfn.ptr, args->execfn.len);
    execfn[args->execfn.len] = '\0';

    u64 strings_len = buffer_length(args->strings);
    s -= pad(strings_len, STACK_ALIGNMENT) >> 3;
    check_s(p, s, stack_low);
    char *strings = (char *)s;
    runtime_memcpy(strings, buffer_ref(args->strings, 0), strings_len);

    struct aux auxp[] = {
        {AT_PHDR, e->e_phoff + va},
        {AT_PHENT, e->e_phentsize},
        {AT_PHNUM, e->e_phnum},
        {AT_PAGESZ, PAGESIZE},
        {AT_BASE, interp_load_addr},
        {AT_FLAGS, 0},
        {AT_ENTRY, u64_from_pointer(start)},
        {AT_UID, p->creds.uid},
        {AT_EUID, p->creds.euid},
        {AT_GID, p->creds.gid},
        {AT_EGID, p->creds.egid},
        {AT_RANDOM, u64_from_pointer(randbuf)},
        {AT_EXECFN, u64_from_pointer(execfn)},
#ifdef __aarch64__
        /* This is aarch64 specific because it's needed for arm .so search paths */
        {AT_HWCAP, get_cpu_capabilities()},
#endif
#if defined(__x86_64__)
        {AT_HWCAP2, get_hwcap2()},
#endif
        {AT_SYSINFO_EHDR, p->vm->vdso_base},
        {AT_NULL, 0},
    };
    u64 naux = sizeof(auxp) / sizeof(auxp[0]);
    u64 words = 1 + args->argc + 1 + args->envc + 1 + 2 * naux;
    s = pointer_from_u64((u64_from_pointer(s - words)) & ~(STACK_ALIGNMENT - 1));
    check_s(p, s, stack_low);
    u64 *w = s;
    *w++ = args->argc;
    char *str = strings;
    for (u64 i = 0; i < args->argc; i++) {
        *w++ = u64_from_pointer(str);
        while (*str++);
    }
    *w++ = 0;
    for (u64 i = 0; i < args->envc; i++) {
        *w++ = u64_from_pointer(str);
        while (*str++);
    }
    *w++ = 0;
    runtime_memcpy(w, auxp, sizeof(auxp));
    zero(p->saved_aux, sizeof(p->saved_aux));
    runtime_memcpy(p->saved_aux, auxp, MIN(sizeof(auxp), sizeof(p->saved_aux)));

    frame_set_stack(thread_frame(t), u64_from_pointer(s));
}

void start_process(thread t, void *start)
{
    thread_frame(t)[SYSCALL_FRAME_PC] = u64_from_pointer(start);
    thread_frame(t)[FRAME_FULL] = true;
    thread_reserve(t);
    if (get(t->p->process_root, sym(gdb))) {
        rputs("NOTE: in-kernel gdb is a work in progress\n");
        init_tcp_gdb(heap_locked(get_kernel_heaps()), t->p, 9090);
    } else {
        schedule_thread(t);
    }
}

closure_function(4, 5, boolean, static_map,
                 process, p, kernel_heaps, kh, u32, allowed_flags, buffer, b,
                 u64 vaddr, u64 offset, u64 data_size, u64 bss_size, pageflags flags)
{
    exec_debug("%s: vaddr 0x%lx, offset 0x%lx, data_size 0x%lx, bss_size 0x%lx, flags 0x%lx\n",
               func_ss, vaddr, offset, data_size, bss_size, flags);
    u64 map_start = vaddr & ~PAGEMASK;
    data_size += vaddr & PAGEMASK;

    u64 tail_copy = bss_size > 0 ? data_size & PAGEMASK : 0;
    if (tail_copy > 0)
        data_size -= tail_copy;
    else
        data_size = pad(data_size, PAGESIZE);

    offset &= ~PAGEMASK;
    if (data_size > 0) {
        u64 paddr = physical_from_virtual(buffer_ref(bound(b), offset));
        u64 vmflags = VMAP_FLAG_READABLE | VMAP_FLAG_PROG;
        if (pageflags_is_exec(flags))
            vmflags |= VMAP_FLAG_EXEC;
        if (pageflags_is_writable(flags))
            vmflags |= VMAP_FLAG_WRITABLE;
        range r = irangel(map_start, data_size);
        exec_debug("   add %s to vmap: %R vmflags 0x%lx, paddr 0x%lx\n",
                   pageflags_is_exec(flags) ? ss("text") : ss("data"), r, vmflags, paddr);
        struct vmap k = ivmap(vmflags, bound(allowed_flags), 0, 0, 0);
        if (allocate_vmap(bound(p), r, k) == INVALID_ADDRESS)
            goto alloc_fail;
        address_space_map(bound(p)->vm->as, map_start, paddr, data_size, pageflags_user(flags));
        map_start += data_size;
    }
    if (bss_size > 0) {
        u64 maplen = pad(bss_size + tail_copy, PAGESIZE);
        u64 paddr = allocate_u64((heap)heap_physical(bound(kh)), maplen);
        if (paddr == INVALID_PHYSICAL)
            goto alloc_fail;
        address_space_map(bound(p)->vm->as, map_start, paddr, maplen, pageflags_user(flags));
        u64 vmflags = VMAP_FLAG_READABLE | VMAP_FLAG_WRITABLE | VMAP_FLAG_BSS;
        range r = irangel(map_start, maplen);
        exec_debug("   add bss vmap: %R vmflags 0x%lx\n", r, vmflags);
        struct vmap k = ivmap(vmflags, bound(allowed_flags), 0, 0, 0);
        if (allocate_vmap(bound(p), r, k) == INVALID_ADDRESS)
            goto alloc_fail;
        if (tail_copy > 0) {
            void *src = buffer_ref(bound(b), offset + data_size);
            exec_debug("   tail copy at 0x%lx, %ld bytes, offset 0x%lx, from %p\n",
                       map_start, tail_copy, data_size, src);
            runtime_memcpy(pointer_from_u64(map_start), src, tail_copy);
        }
        exec_debug("   zero at 0x%lx, len 0x%lx\n", map_start + tail_copy, maplen - tail_copy);
        zero(pointer_from_u64(map_start + tail_copy), maplen - tail_copy);
    }
    return true;
  alloc_fail:
    msg_err("exec: failed to allocate vmap");
    return false;
}

closure_function(4, 5, boolean, faulting_map,
                 process, p, kernel_heaps, kh, u32, allowed_flags, fsfile, f,
                 u64 vaddr, u64 offset, u64 data_size, u64 bss_size, pageflags flags)
{
    exec_debug("%s: vaddr 0x%lx, offset 0x%lx, data_size 0x%lx, bss_size 0x%lx, flags 0x%lx\n",
               func_ss, vaddr, offset, data_size, bss_size, flags);
    u64 map_start = vaddr & ~PAGEMASK;
    if (data_size > 0) {
        offset &= ~PAGEMASK;
        data_size += vaddr & PAGEMASK;
        u64 data_map_size = pad(data_size, PAGESIZE);
        u64 tail_bss = MIN(data_map_size - data_size, bss_size);
        u64 vmflags = VMAP_FLAG_READABLE | VMAP_FLAG_PROG;
        if (pageflags_is_exec(flags))
            vmflags |= VMAP_FLAG_EXEC;
        boolean rw = pageflags_is_writable(flags);
        if (rw)
            vmflags |= VMAP_FLAG_WRITABLE;
        if (tail_bss > 0)
            vmflags |= VMAP_FLAG_TAIL_BSS;
        range r = irangel(map_start, data_map_size);
        exec_debug("%s: add %s to vmap: %R vmflags 0x%lx, offset 0x%lx, data_size 0x%lx, tail_bss 0x%lx\n",
                   func_ss, pageflags_is_exec(flags) ? ss("text") : ss("data"),
                   r, vmflags, offset, data_size, tail_bss);
        pagecache_node pn = fsfile_get_cachenode(bound(f));
        struct vmap k = ivmap(vmflags, bound(allowed_flags), offset,
                              pn, 0);
        if (tail_bss > 0)
            k.bss_offset = data_size;
        if (allocate_vmap(bound(p), r, k) == INVALID_ADDRESS)
            goto alloc_fail;
        if (!rw)
            /* Make the page cache aware of this mapping so that it can evict relevant pages on
             * memory pressure. */
            pagecache_node_add_mapping(pn, bound(p)->vm->as, r, offset, false);
        map_start += data_map_size;
        bss_size -= tail_bss;
    }
    if (bss_size > 0) {
        u64 vmflags = VMAP_FLAG_READABLE | VMAP_FLAG_WRITABLE | VMAP_FLAG_BSS;
        range r = irangel(map_start, pad(bss_size, PAGESIZE));
        exec_debug("%s: add bss vmap: %R vmflags 0x%lx\n", func_ss, r, vmflags);
        struct vmap k = ivmap(vmflags, bound(allowed_flags), 0, 0, 0);
        if (allocate_vmap(bound(p), r, k) == INVALID_ADDRESS)
            goto alloc_fail;
    }
    return true;
  alloc_fail:
    msg_err("exec: failed to allocate vmap");
    return false;
}

closure_function(7, 2, void, load_interp_complete,
                 thread, t, kernel_heaps, kh, buffer, b, fsfile, f, u64, load_addr, boolean, static_map, boolean, ingest_symbols,
                 status s, bytes length)
{
    thread t = bound(t);
    process p = t->p;
    kernel_heaps kh = bound(kh);
    buffer b = bound(b);

    if (!is_ok(s))
        halt("read interp failed %v\n", s);
    exec_debug("interpreter load complete, length %ld, reading elf\n", length);
    buffer_produce(b, length);
    u64 where = bound(load_addr);
    if (bound(ingest_symbols)) {
        exec_debug("ingesting interp symbols\n");
        add_elf_syms(b, where);
    }
    elf_map_handler emh;
    if (bound(static_map))
        emh = stack_closure(static_map, p, kh, 0, b);
    else
        emh = stack_closure(faulting_map, p, kh, 0, bound(f));
    address_space prev_as = use_address_space(p->vm->as);
    void *start = load_elf(b, where, emh);
    restore_address_space(prev_as);
    if (!bound(static_map))
        deallocate_buffer(b);
    exec_debug("starting process tid %d, start %p\n", t->tid, start);
    start_process(t, start);
    closure_finish();
}

closure_function(1, 1, boolean, trace_notify,
                 process, p,
                 value v)
{
    bound(p)->trace = trace_get_flags(v);
    return true;
}

static void exec_elf_finish(buffer ex, fsfile f, process kp,
                            range load_range, sstring interp_path, boolean ingest_symbols,
                            status_handler complete)
{
    status s = STATUS_OK;
    unix_heaps uh = kp->uh;
    tuple root = kp->process_root;
    filesystem fs = kp->root_fs;
    kernel_heaps kh = get_kernel_heaps();
    process proc = create_process(uh, root, fs);
    thread t = create_thread(proc, proc->pid);
    fsfile interp;
    u64 interp_load_addr;
    Elf64_Ehdr *e = (Elf64_Ehdr *)buffer_ref(ex, 0);
    boolean aslr = get(root, sym(noaslr)) == 0;
    heap general = heap_locked(kh);

    exec_debug("exec_elf enter\n");

    if (!sstring_is_null(interp_path)) {
        interp = fsfile_open(interp_path);
        if (!interp) {
            s = timm("result", "couldn't find program interpreter %s", interp_path);
            goto out;
        }
        interp_load_addr = process_get_virt_range(proc, HUGE_PAGESIZE, PROCESS_VIRTUAL_MMAP_RANGE);
        exec_debug("interp: %p\n", interp);
    } else {
        interp = 0;
        interp_load_addr = 0;
    }
    exec_debug("range of loadable segments prior to adjustment: %R\n", load_range);

    u64 load_offset = 0;
    if (e->e_type == ET_DYN) {
        /* Have some PIE */
        load_offset = DEFAULT_PROG_ADDR;
        if (aslr) {
            load_offset += get_aslr_offset(PROCESS_PIE_LOAD_ASLR_RANGE);
        }
        exec_debug("placing PIE at 0x%lx\n", load_offset);
        load_range = range_add(load_range, load_offset);
    }

    if (load_range.end > PROCESS_ELF_LOAD_END) {
        s = timm("result", "exec_elf failed: elf segment load range (%R) exceeds hard limit 0x%lx",
             load_range, PROCESS_ELF_LOAD_END);
        goto out;
    }

    exec_debug("offset 0x%lx, range after adjustment: %R, span 0x%lx\n",
               load_offset, load_range, range_span(load_range));
    u32 allowed_flags = proc_is_exec_protected(proc) ? 0 :
            (VMAP_FLAG_READABLE | VMAP_FLAG_WRITABLE | VMAP_FLAG_EXEC);
    elf_map_handler emh;
    boolean static_map = get(proc->process_root, sym(ltrace)) ||
        get(proc->process_root, sym(static_map_program));
    if (static_map)
        emh = stack_closure(static_map, proc, kh, allowed_flags, ex);
    else
        emh = stack_closure(faulting_map, proc, kh, allowed_flags, f);
    address_space prev_as = use_address_space(proc->vm->as);
    void * entry = load_elf(ex, load_offset, emh);
    u64 brk_offset = aslr ? get_aslr_offset(PROCESS_HEAP_ASLR_RANGE) : 0;
    u64 brk = pad(load_range.end, PAGESIZE) + brk_offset;
    proc->vm->brk = pointer_from_u64(brk);
    proc->vm->heap_base = brk;
    proc->vm->heap_map = allocate_vmap(proc, irange(brk, brk),
                                   ivmap(VMAP_FLAG_HEAP | VMAP_FLAG_READABLE | VMAP_FLAG_WRITABLE,
                                         0, 0, 0, 0));
    assert(proc->vm->heap_map != INVALID_ADDRESS);
    exec_debug("entry %p, brk %p (offset 0x%lx)\n", entry, proc->vm->brk, brk_offset);

    /* XXX temporarily disable because it breaks ftrace. Will need to 
       eventually deal with this for issue #1269 */
    //current_cpu()->current_thread = (nanos_thread)t;
    struct exec_args args;
    exec_args_from_manifest(&args, root, general);
    build_exec_stack(proc, t, e, entry, load_range.start, interp_load_addr, aslr, &args);
    restore_address_space(prev_as);
    buffer cmdline = allocate_buffer(general, args.argv_bytes);
    assert(cmdline != INVALID_ADDRESS);
    assert(buffer_write(cmdline, buffer_ref(args.strings, 0), args.argv_bytes));
    deallocate_buffer(args.strings);
    buffer exe = allocate_buffer(general, args.execfn.len + 1);
    assert(exe != INVALID_ADDRESS);
    if (args.execfn.len && (args.execfn.ptr[0] != '/'))
        assert(buffer_write_byte(exe, '/'));
    assert(buffer_write_sstring(exe, args.execfn));
    process_set_image_names(proc, cmdline, exe);

    if (ingest_symbols) {
        exec_debug("ingesting program symbols\n");
        add_elf_syms(ex, load_offset);
    }

    value ltrace = get(proc->process_root, sym(ltrace));
    if (ltrace) {
        exec_debug("initializing ltrace...\n");
        ltrace_init(ltrace, ex, load_offset);
    }
    if (!static_map)
        deallocate_buffer(ex);

    register_root_notify(sym(trace), closure(heap_locked(kh), trace_notify, proc));
    string cwd = get_string(root, sym(cwd));
    if (cwd) {
        int fss = filesystem_chdir(proc, buffer_to_sstring(cwd));
        if (fss != 0) {
            s = timm("result", "unable to change cwd to \"%b\"; %s", cwd, string_from_errno(-fss));
            goto out;
        }
    }

    if (interp) {
        program_set_perms(root, interp->md);
        exec_debug("reading interp...\n");
        /* check if we neeed a full program read */
        boolean load_entire = static_map || ingest_symbols;
        u64 length = load_entire ? fsfile_get_length(interp) : ELF_PROGRAM_LOAD_MIN_SIZE;
        buffer b = allocate_buffer(general, pad(length, PAGESIZE));
        assert(b != INVALID_ADDRESS);
        io_status_handler sh = closure(general, load_interp_complete, t, kh, b,
                                       interp, interp_load_addr, static_map, ingest_symbols);
        filesystem_read_linear(interp, buffer_ref(b, 0), irangel(0, length), sh);
        goto out;
    }

    exec_debug("starting process tid %d, start %p\n", t->tid, entry);
    start_process(t, entry);
  out:
    apply(complete, s);
}

static boolean elf_check_extend(u64 req_len, fsfile f, buffer b, io_status_handler self)
{
    u64 curr = buffer_length(b);
    exec_debug("%s: req_len %ld, curr %ld\n", func_ss, req_len, curr);
    if (req_len <= curr)
        return false;
    u64 readlen = req_len - curr;
    assert(buffer_extend(b, readlen));
    exec_debug("%s: curr %ld, readlen %ld\n", func_ss, curr, readlen);
    filesystem_read_linear(f, buffer_ref(b, curr), irangel(curr, readlen), self);
    return true;
}

closure_function(4, 2, void, exec_elf_read,
                 fsfile, f, buffer, b, process, kp, status_handler, complete,
                 status s, bytes length)
{
    fsfile f = bound(f);
    buffer b = bound(b);
    process kp = bound(kp);
    status_handler complete = bound(complete);
    exec_debug("%s: status %v, read %ld bytes\n", func_ss, s, length);
    if (!is_ok(s)) {
        apply(complete, timm_up(s, "result", "failed to read elf file"));
        closure_finish();
        return;
    }
    buffer_produce(b, length);
    exec_debug("buffer length %ld\n", buffer_length(b));
    Elf64_Ehdr *e = (Elf64_Ehdr *)buffer_ref(b, 0);
    sstring interp_path = sstring_null();
    boolean ingest_symbols = !!get(kp->process_root, sym(ingest_program_symbols));

    /* This procedure will repeat until we have all the ELF info we need. */
    range load_range = irange(infinity, 0);
    foreach_phdr(e, p) {
        if ((p->p_type == PT_INTERP) && (p->p_filesz > 0)) {
            interp_path = isstring((void *)e + p->p_offset,
                                   p->p_filesz - 1  /* the last byte is the string terminator */);
            exec_debug("interp offset p->p_offset %ld, p->p_filesz %ld\n", p->p_offset, p->p_filesz);
            if (elf_check_extend(p->p_offset + p->p_filesz, f, b, (io_status_handler)closure_self()))
                return;
        } else if (p->p_type == PT_LOAD) {
            if (p->p_vaddr < load_range.start)
                load_range.start = p->p_vaddr;
            u64 segend = p->p_vaddr + p->p_memsz;
            if (segend > load_range.end)
                load_range.end = segend;
        }
    }
    if (ingest_symbols) {
        if (elf_check_extend(e->e_shoff + (e->e_shnum * e->e_shentsize), f, b,
                             (io_status_handler)closure_self()))
            return;
        u64 req_size = 0;
        foreach_shdr(e, shdr) {
            if (shdr->sh_type == SHT_SYMTAB || shdr->sh_type == SHT_STRTAB) {
                u64 sz = shdr->sh_offset + shdr->sh_size;
                if (sz > req_size)
                    req_size = sz;
            }
        }
        if (elf_check_extend(req_size, f, b, (io_status_handler)closure_self()))
            return;
    }
    exec_debug("finished reading ELF data, buffer length %ld\n", buffer_length(b));
    closure_finish();
    exec_elf_finish(b, f, kp, load_range, interp_path, ingest_symbols, complete);
}

void exec_elf(process kp, string program_path, status_handler complete)
{
    exec_debug("%s: path \"%b\", complete %p (%F)\n", func_ss, program_path, complete, complete);
    kernel_heaps kh = get_kernel_heaps();
    heap general = heap_locked(kh);
    tuple root = kp->process_root;
    fsfile f = fsfile_open(buffer_to_sstring(program_path));
    if (!f) {
        apply(complete, timm("result", "unable to open program file %v", program_path));
        return;
    }
    program_set_perms(root, f->md);

    /* any of these options force a full program read */
    boolean static_map = get(root, sym(ltrace)) || get(root, sym(static_map_program));
    u64 length = static_map ? fsfile_get_length(f) : ELF_PROGRAM_LOAD_MIN_SIZE;
    u64 alloc = pad(length, PAGESIZE);
    buffer b = allocate_buffer(general, alloc);
    if (b == INVALID_ADDRESS) {
        apply(complete, timm("result", "unable to allocate memory for program read"));
        return;
    }
    if (static_map && alloc > length) {
        /* clear area past unaligned end */
        zero(buffer_ref(b, length), alloc - length);
    }
    io_status_handler sh = closure(general, exec_elf_read, f, b, kp, complete);
    filesystem_read_linear(f, buffer_ref(b, 0), irange(0, length), sh);
}

#ifdef __x86_64__

#define EXEC_ARG_STRLEN_MAX     (32 * PAGESIZE)
#define EXEC_PHDRS_MAX_SIZE     PAGESIZE
#define FXSAVE_FCW_OFFSET       0
#define FXSAVE_MXCSR_OFFSET     24
#define X87_FCW_RESET           0x37f
#define MXCSR_RESET             0x1f80

typedef struct exec_image {
    fsfile f;
    buffer hdr;
    range load_range;
    sstring interp;
} *exec_image;

closure_function(2, 2, void, exec_read_complete,
                 context, ctx, status *, result,
                 status s, bytes length)
{
    *bound(result) = s;
    context_schedule_return(bound(ctx));
}

static sysreturn exec_read(fsfile f, buffer b, u64 length)
{
    buffer_clear(b);
    if (!buffer_extend(b, pad(length, PAGESIZE)))
        return -ENOMEM;
    context ctx = get_current_context(current_cpu());
    status s = STATUS_OK;
    context_pre_suspend(ctx);
    filesystem_read_linear(f, buffer_ref(b, 0), irangel(0, length),
                           stack_closure(exec_read_complete, ctx, &s));
    context_suspend();
    if (!is_ok(s)) {
        timm_dealloc(s);
        return -EIO;
    }
    buffer_produce(b, length);
    return 0;
}

static boolean exec_ehdr_valid(Elf64_Ehdr *e)
{
    return (e->e_ident[EI_MAG0] == ELFMAG0) && (e->e_ident[EI_MAG1] == ELFMAG1) &&
        (e->e_ident[EI_MAG2] == ELFMAG2) && (e->e_ident[EI_MAG3] == ELFMAG3) &&
        (e->e_ident[EI_CLASS] == ELFCLASS64) && (e->e_ident[EI_DATA] == ELFDATA2LSB) &&
        (e->e_ident[EI_VERSION] == EV_CURRENT) && (e->e_machine == EM_X86_64) &&
        ((e->e_type == ET_EXEC) || (e->e_type == ET_DYN)) &&
        (e->e_phentsize == sizeof(Elf64_Phdr)) && (e->e_phnum > 0) &&
        (e->e_phnum * sizeof(Elf64_Phdr) <= EXEC_PHDRS_MAX_SIZE);
}

static sysreturn exec_image_open(exec_image img, fsfile f, int bad_format)
{
    img->f = f;
    img->interp = sstring_null();
    img->hdr = allocate_buffer(heap_locked(get_kernel_heaps()), PAGESIZE);
    if (img->hdr == INVALID_ADDRESS) {
        img->hdr = 0;
        return -ENOMEM;
    }
    u64 file_len = fsfile_get_length(f);
    if (file_len < sizeof(Elf64_Ehdr))
        return -bad_format;
    sysreturn rv = exec_read(f, img->hdr, MIN(file_len, PAGESIZE));
    if (rv)
        return rv;
    Elf64_Ehdr *e = buffer_ref(img->hdr, 0);
    if (!exec_ehdr_valid(e))
        return -bad_format;
    u64 need = e->e_phoff + e->e_phnum * sizeof(Elf64_Phdr);
    if ((need < e->e_phoff) || (need > file_len))
        return -bad_format;
    for (int pass = 0; pass < 2; pass++) {
        if (need > buffer_length(img->hdr)) {
            rv = exec_read(f, img->hdr, need);
            if (rv)
                return rv;
            e = buffer_ref(img->hdr, 0);
        }
        foreach_phdr(e, p) {
            if (p->p_type != PT_INTERP)
                continue;
            u64 end = p->p_offset + p->p_filesz;
            if ((p->p_filesz < 2) || (p->p_filesz > PATH_MAX) || (end < p->p_offset) ||
                (end > file_len))
                return -bad_format;
            need = MAX(need, end);
        }
    }
    range load_range = irange(infinity, 0);
    foreach_phdr(e, p) {
        if (p->p_type == PT_INTERP) {
            char *path = buffer_ref(img->hdr, p->p_offset);
            if (path[p->p_filesz - 1] != '\0')
                return -bad_format;
            img->interp = isstring(path, p->p_filesz - 1);
        } else if (p->p_type == PT_LOAD) {
            if ((p->p_memsz < p->p_filesz) || (p->p_vaddr + p->p_memsz < p->p_vaddr) ||
                (p->p_offset + p->p_filesz < p->p_offset) ||
                ((p->p_vaddr & PAGEMASK) != (p->p_offset & PAGEMASK)))
                return -bad_format;
            load_range.start = MIN(load_range.start, p->p_vaddr);
            load_range.end = MAX(load_range.end, p->p_vaddr + p->p_memsz);
        }
    }
    if (load_range.start >= load_range.end)
        return -bad_format;
    img->load_range = load_range;
    return 0;
}

static void exec_image_close(exec_image img)
{
    if (img->hdr)
        deallocate_buffer(img->hdr);
    if (img->f)
        fsfile_release(img->f);
}

static sysreturn exec_copy_strings(exec_args args, char *const *uv, boolean env, u64 limit)
{
    if (!uv)
        return 0;
    for (u64 i = 0; ; i++) {
        char *ustr;
        if (!get_user_value(uv + i, &ustr))
            return -EFAULT;
        if (!ustr)
            return 0;
        sstring str;
        if (!fault_in_user_string(ustr, &str))
            return -EFAULT;
        if (str.len + 1 > EXEC_ARG_STRLEN_MAX)
            return -E2BIG;
        u64 total = buffer_length(args->strings) + str.len + 1 +
            (args->argc + args->envc + 1) * sizeof(u64);
        if (total > limit)
            return -E2BIG;
        if (!buffer_extend(args->strings, str.len + 1))
            return -ENOMEM;
        context ctx = get_current_context(current_cpu());
        if (context_set_err(ctx))
            return -EFAULT;
        boolean ok = exec_args_push(args, str);
        context_clear_err(ctx);
        if (!ok)
            return -ENOMEM;
        if (env)
            args->envc++;
        else
            args->argc++;
    }
}

static sysreturn exec_copy_args(exec_args args, sstring path, char *const *argv,
                                char *const *envp, u64 stack_size)
{
    args->strings = allocate_buffer(heap_locked(get_kernel_heaps()), PAGESIZE);
    if (args->strings == INVALID_ADDRESS) {
        args->strings = 0;
        return -ENOMEM;
    }
    args->argc = args->envc = 0;
    args->execfn = path;
    u64 limit = MAX(stack_size / 4, EXEC_ARG_STRLEN_MAX);
    sysreturn rv = exec_copy_strings(args, argv, false, limit);
    if (rv)
        return rv;
    if (args->argc == 0) {
        if (!exec_args_push(args, ss("")))
            return -ENOMEM;
        args->argc = 1;
    }
    args->argv_bytes = buffer_length(args->strings);
    return exec_copy_strings(args, envp, true, limit);
}

static sysreturn exec_resolve(int dirfd, sstring path, int flags, fsfile *fp, buffer exe)
{
    process p = current->p;
    filesystem fs;
    inode cwd;
    tuple n;
    fsfile fsf = 0;
    if (path.len == 0) {
        if (!(flags & AT_EMPTY_PATH))
            return -ENOENT;
        fdesc d = fdesc_get(p, dirfd);
        if (!d)
            return -EBADF;
        sysreturn rv = 0;
        if (d->type != FDESC_TYPE_REGULAR) {
            rv = -EACCES;
        } else {
            file f = (file)d;
            n = filesystem_get_meta(f->fs, f->n);
            if (!(file_meta_perms(p, n) & ACCESS_PERM_EXEC))
                rv = -EACCES;
            if (n)
                filesystem_put_meta(f->fs, n);
            if (!rv) {
                fsf = f->fsf;
                fsfile_reserve(fsf);
                bprintf(exe, "/dev/fd/%d", dirfd);
            }
        }
        fdesc_put(d);
        *fp = fsf;
        return rv;
    }
    if (path.ptr[0] == '/') {
        process_get_root(p, &fs, &cwd);
    } else if (dirfd == AT_FDCWD) {
        process_get_cwd(p, &fs, &cwd);
    } else {
        fdesc d = fdesc_get(p, dirfd);
        if (!d)
            return -EBADF;
        if (d->type != FDESC_TYPE_DIRECTORY) {
            fdesc_put(d);
            return -ENOTDIR;
        }
        fs = ((file)d)->fs;
        filesystem_reserve(fs);
        cwd = ((file)d)->n;
        fdesc_put(d);
    }
    if (path.ptr[0] != '/') {
        char *dir = allocate(heap_locked(get_kernel_heaps()), PATH_MAX);
        if (dir == INVALID_ADDRESS) {
            filesystem_release(fs);
            return -ENOMEM;
        }
        int len = file_get_path(fs, cwd, dir, PATH_MAX);
        if (len > 1) {
            buffer_write(exe, dir, len - 1);
            if ((len > 2) || (dir[0] != '/'))
                buffer_write_byte(exe, '/');
        } else {
            buffer_write_byte(exe, '/');
        }
        deallocate(heap_locked(get_kernel_heaps()), dir, PATH_MAX);
    }
    buffer_write_sstring(exe, path);
    filesystem lookup_fs = fs;
    u8 lookup_flags = (flags & AT_SYMLINK_NOFOLLOW) ? 0 : FS_NODE_FOLLOW;
    sysreturn rv = filesystem_get_node(&lookup_fs, cwd, path, lookup_flags, &n, 0, &fsf);
    if (rv == 0) {
        if (is_symlink(n))
            rv = -ELOOP;
        else if (!is_regular(n) || !fsf || !(file_meta_perms(p, n) & ACCESS_PERM_EXEC))
            rv = -EACCES;
        filesystem_put_node(lookup_fs, n);
        if (rv && fsf) {
            fsfile_release(fsf);
            fsf = 0;
        }
    }
    filesystem_release(fs);
    *fp = fsf;
    return rv;
}

closure_function(1, 1, boolean, exec_kill_thread,
                 thread, self,
                 rbnode n)
{
    thread t = struct_from_field(n, thread, n);
    if (t != bound(self)) {
        struct siginfo si = { .si_signo = SIGKILL, .si_code = SI_KERNEL };
        deliver_signal_to_thread(t, &si);
    }
    return true;
}

static boolean exec_kill_other_threads(thread t)
{
    process p = t->p;
    spin_lock(&p->threads_lock);
    boolean doomed = (p->exec_thread && (p->exec_thread != t));
    if (!doomed)
        p->exec_thread = t;
    spin_unlock(&p->threads_lock);
    if (doomed || p->exiting)
        return false;
    spin_lock(&p->threads_lock);
    rbtree_traverse(p->threads, RB_INORDER, stack_closure(exec_kill_thread, t));
    spin_unlock(&p->threads_lock);
    context ctx = get_current_context(current_cpu());
    while (true) {
        spin_lock(&p->threads_lock);
        boolean alone = rbtree_get_count(p->threads) == 1;
        spin_unlock(&p->threads_lock);
        if (alone)
            break;
        context_pre_suspend(ctx);
        spin_lock(&p->threads_lock);
        alone = rbtree_get_count(p->threads) == 1;
        if (!alone)
            p->exec_waiter = ctx;
        spin_unlock(&p->threads_lock);
        if (alone)
            context_schedule_return(ctx);
        context_suspend();
    }
    return !p->exiting;
}

static void exec_become_leader(thread t)
{
    process p = t->p;
    if (t->tid == p->pid)
        return;
    spin_lock(&p->threads_lock);
    rbtree_remove_by_key(p->threads, &t->n);
    u64 old_tid = t->tid;
    t->tid = p->pid;
    init_rbnode(&t->n);
    assert(rbtree_insert_node(p->threads, &t->n));
    spin_unlock(&p->threads_lock);
    deallocate_u64((heap)p->uh->processes, old_tid, 1);
}

static void exec_reset_frame(thread t, void *entry)
{
    context_frame f = thread_frame(t);
    u64 sp = f[SYSCALL_FRAME_SP];
    for (int i = FRAME_RAX; i <= FRAME_R15; i++)
        f[i] = 0;
    f[SYSCALL_FRAME_SP] = sp;
    f[SYSCALL_FRAME_PC] = u64_from_pointer(entry);
    f[FRAME_EFLAGS] = U64_FROM_BIT(EFLAG_INTERRUPT) | U64_FROM_BIT(1);
    f[FRAME_FSBASE] = 0;
    f[FRAME_GSBASE] = 0;
    f[FRAME_SAVED_RAX] = 0;
    u8 *x = frame_extended(f);
    zero(x, extended_frame_size);
    *(u16 *)(x + FXSAVE_FCW_OFFSET) = X87_FCW_RESET;
    *(u32 *)(x + FXSAVE_MXCSR_OFFSET) = MXCSR_RESET;
}

static void exec_reset_signals(thread t)
{
    process p = t->p;
    for (int i = 0; i < NSIG; i++) {
        struct sigaction *sa = &p->sigactions[i];
        void *handler = sa->sa_handler;
        zero(sa, sizeof(*sa));
        if (handler == SIG_IGN)
            sa->sa_handler = SIG_IGN;
    }
    t->signal_stack = 0;
    t->signal_stack_length = 0;
}

static void exec_set_name(thread t, buffer exe)
{
    int slash = buffer_strrchr(exe, '/');
    u64 start = (slash < 0) ? 0 : slash + 1;
    u64 len = MIN(buffer_length(exe) - start, sizeof(t->name) - 1);
    runtime_memcpy(t->name, buffer_ref(exe, start), len);
    t->name[len] = '\0';
}

static void *exec_map_image(process p, exec_image img, u64 load_offset, u32 allowed_flags)
{
    elf_map_handler emh = stack_closure(faulting_map, p, get_kernel_heaps(), allowed_flags, img->f);
    return load_elf(img->hdr, load_offset, emh);
}

static boolean exec_replace_image(thread t, exec_image img, exec_image interp, exec_args args,
                                  buffer exe)
{
    process p = t->p;
    heap h = heap_locked(get_kernel_heaps());
    exec_become_leader(t);
    if (t->clear_tid) {
        if (p->vm->refcount.c > 1) {
            int zero_tid = 0;
            if (set_user_value(t->clear_tid, zero_tid))
                futex_wake_one_by_uaddr(p, t->clear_tid);
        }
        t->clear_tid = 0;
    }
    wake_robust_list(t);
    t->robust_list = 0;
    t->set_child_tid = 0;
    aio_process_exit(p);
    posix_timers_delete_all(p);

    process_vm vm = mmap_process_init(p->process_root);
    process_lock(p);
    process_vm old_vm = p->vm;
    p->vm = vm;
    process_unlock(p);
    t->context.as = vm->as;
    use_address_space(vm->as);
    init_vdso(p);
    process_vm_release(old_vm);
    process_vfork_release(p);

    Elf64_Ehdr *e = buffer_ref(img->hdr, 0);
    boolean aslr = get(p->process_root, sym(noaslr)) == 0;
    u64 load_offset = 0;
    if (e->e_type == ET_DYN)
        load_offset = DEFAULT_PROG_ADDR +
            (aslr ? get_aslr_offset(PROCESS_PIE_LOAD_ASLR_RANGE) : 0);
    range load_range = range_add(img->load_range, load_offset);
    u32 allowed_flags = proc_is_exec_protected(p) ? 0 :
            (VMAP_FLAG_READABLE | VMAP_FLAG_WRITABLE | VMAP_FLAG_EXEC);
    void *entry = exec_map_image(p, img, load_offset, allowed_flags);
    if (entry == INVALID_ADDRESS)
        return false;
    u64 brk = pad(load_range.end, PAGESIZE) +
        (aslr ? get_aslr_offset(PROCESS_HEAP_ASLR_RANGE) : 0);
    vm->brk = pointer_from_u64(brk);
    vm->heap_base = brk;
    vm->heap_map = allocate_vmap(p, irange(brk, brk),
                                 ivmap(VMAP_FLAG_HEAP | VMAP_FLAG_READABLE | VMAP_FLAG_WRITABLE,
                                       0, 0, 0, 0));
    if (vm->heap_map == INVALID_ADDRESS)
        return false;
    vm->image = img->f;
    img->f = 0;

    u64 interp_base = 0;
    void *start = entry;
    if (interp->f) {
        Elf64_Ehdr *ie = buffer_ref(interp->hdr, 0);
        u64 span = pad(range_span(interp->load_range) + (interp->load_range.start & PAGEMASK),
                       PAGESIZE);
        u64 interp_offset = 0;
        if (ie->e_type == ET_DYN) {
            interp_base = process_get_virt_range(p, span, PROCESS_VIRTUAL_MMAP_RANGE);
            if (interp_base == INVALID_PHYSICAL)
                return false;
            interp_offset = interp_base - (interp->load_range.start & ~PAGEMASK);
        } else {
            interp_base = interp->load_range.start & ~PAGEMASK;
        }
        start = exec_map_image(p, interp, interp_offset, allowed_flags);
        if (start == INVALID_ADDRESS)
            return false;
        vm->interp = interp->f;
        interp->f = 0;
    }
    creds_exec(t);
    build_exec_stack(p, t, e, entry, load_range.start, interp_base, aslr, args);

    fdtable fdt = fdtable_copy(p->fdtable);
    if (fdt == INVALID_ADDRESS)
        return false;
    process_lock(p);
    fdtable old_fdt = p->fdtable;
    p->fdtable = fdt;
    process_unlock(p);
    fdtable_release(old_fdt);
    fdtable_close_on_exec(fdt);

    exec_reset_signals(t);
    exec_set_name(t, exe);
    buffer cmdline = allocate_buffer(h, args->argv_bytes);
    if (cmdline == INVALID_ADDRESS)
        return false;
    assert(buffer_write(cmdline, buffer_ref(args->strings, 0), args->argv_bytes));
    process_set_image_names(p, cmdline, exe);
    exec_reset_frame(t, start);
    spin_lock(&p->threads_lock);
    p->exec_thread = 0;
    spin_unlock(&p->threads_lock);
    return true;
}

static sysreturn exec_internal(int dirfd, const char *upath, char *const *argv, char *const *envp,
                               int flags)
{
    if (flags & ~(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW))
        return -EINVAL;
    thread t = current;
    process p = t->p;
    heap h = heap_locked(get_kernel_heaps());
    sstring upath_ss;
    if (!fault_in_user_string(upath, &upath_ss))
        return -EFAULT;
    if (upath_ss.len >= PATH_MAX)
        return -ENAMETOOLONG;
    buffer path = allocate_buffer(h, upath_ss.len + 1);
    if (path == INVALID_ADDRESS)
        return -ENOMEM;
    buffer exe = 0;
    struct exec_args args = { 0 };
    struct exec_image img = { 0 }, interp = { 0 };
    sysreturn rv;
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx)) {
        rv = -EFAULT;
        goto out;
    }
    buffer_write_sstring(path, upath_ss);
    context_clear_err(ctx);
    sstring path_ss = buffer_to_sstring(path);
    rv = exec_copy_args(&args, path_ss, argv, envp, exec_stack_size(p));
    if (rv)
        goto out;
    exe = allocate_buffer(h, PATH_MAX);
    if (exe == INVALID_ADDRESS) {
        exe = 0;
        rv = -ENOMEM;
        goto out;
    }
    fsfile f;
    rv = exec_resolve(dirfd, path_ss, flags, &f, exe);
    if (rv)
        goto out;
    rv = exec_image_open(&img, f, ENOEXEC);
    if (rv)
        goto out;
    u64 max_load_offset = (((Elf64_Ehdr *)buffer_ref(img.hdr, 0))->e_type == ET_DYN) ?
        DEFAULT_PROG_ADDR + PROCESS_PIE_LOAD_ASLR_RANGE : 0;
    if (img.load_range.end + max_load_offset > PROCESS_ELF_LOAD_END) {
        rv = -ENOEXEC;
        goto out;
    }
    if (!sstring_is_null(img.interp)) {
        fsfile interp_f = fsfile_open(img.interp);
        if (!interp_f) {
            rv = -ENOENT;
            goto out;
        }
        rv = exec_image_open(&interp, interp_f, ELIBBAD);
        if (rv)
            goto out;
        if (!sstring_is_null(interp.interp)) {
            rv = -ELIBBAD;
            goto out;
        }
    }
    if (!exec_kill_other_threads(t)) {
        rv = -EINTR;
        goto out;
    }
    if (!exec_replace_image(t, &img, &interp, &args, exe)) {
        if (process_is_init(p))
            halt("execve: failed to load the new image of init\n");
        process_kill(p, wait_status_signaled(SIGSEGV));
        rv = -ENOMEM;
        goto out;
    }
    exe = 0;
    rv = 0;
  out:
    exec_image_close(&interp);
    exec_image_close(&img);
    if (args.strings)
        deallocate_buffer(args.strings);
    if (exe)
        deallocate_buffer(exe);
    deallocate_buffer(path);
    return rv;
}

sysreturn execve(const char *path, char *const argv[], char *const envp[])
{
    return exec_internal(AT_FDCWD, path, argv, envp, 0);
}

sysreturn execveat(int dirfd, const char *path, char *const argv[], char *const envp[], int flags)
{
    return exec_internal(dirfd, path, argv, envp, flags);
}

#endif
