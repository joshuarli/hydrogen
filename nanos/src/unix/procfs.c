#include <unix_internal.h>
#include <seccomp.h>
#include <filesystem.h>
#include <storage.h>

enum procfs_kind {
    PROCFS_ROOT,
    PROCFS_STATIC,
    PROCFS_SELF,
    PROCFS_THREAD_SELF,
    PROCFS_PID,
    PROCFS_STATUS,
    PROCFS_CMDLINE,
    PROCFS_STAT,
    PROCFS_MAPS,
    PROCFS_EXE,
    PROCFS_FD_DIR,
    PROCFS_FD,
    PROCFS_FDINFO_DIR,
    PROCFS_FDINFO,
    PROCFS_TASK_DIR,
    PROCFS_TID,
    PROCFS_TID_STATUS,
    PROCFS_UID_MAP,
    PROCFS_GID_MAP,
    PROCFS_SETGROUPS,
    PROCFS_ROOT_LINK,
    PROCFS_NS_DIR,
    PROCFS_NS_USER,
    PROCFS_NS_PID,
    PROCFS_NS_NET,
    PROCFS_NS_IPC,
    PROCFS_NS_MNT,
    PROCFS_NS_UTS,
};

typedef struct procfs_node {
    tuple md;
    inode ino;
    enum procfs_kind kind;
    int pid;
    int n;
    closure_struct(spec_file_open, open);
} *procfs_node;

static struct procfs {
    struct filesystem fs;
    table by_md;
    table by_ino;
    inode next_ino;
    procfs_node root;
} procfs;

typedef struct procfs_file {
    struct special_file_wrapper w;
    closure_struct(file_io, read);
    closure_struct(file_io, write);
    closure_struct(fdesc_events, events);
    closure_struct(fdesc_close, close);
    enum procfs_kind kind;
    int pid;
    int n;
    user_namespace ns;
} *procfs_file;

static heap procfs_heap(void)
{
    return heap_locked(get_kernel_heaps());
}

static boolean procfs_kind_is_dir(enum procfs_kind kind)
{
    switch (kind) {
    case PROCFS_ROOT:
    case PROCFS_PID:
    case PROCFS_FD_DIR:
    case PROCFS_FDINFO_DIR:
    case PROCFS_TASK_DIR:
    case PROCFS_TID:
    case PROCFS_NS_DIR:
        return true;
    default:
        return false;
    }
}

static boolean procfs_kind_is_generated_file(enum procfs_kind kind)
{
    switch (kind) {
    case PROCFS_STATUS:
    case PROCFS_CMDLINE:
    case PROCFS_STAT:
    case PROCFS_MAPS:
    case PROCFS_FDINFO:
    case PROCFS_TID_STATUS:
    case PROCFS_UID_MAP:
    case PROCFS_GID_MAP:
    case PROCFS_SETGROUPS:
        return true;
    default:
        return false;
    }
}

static procfs_node procfs_node_of(tuple md)
{
    return md ? table_find(procfs.by_md, md) : 0;
}

static boolean process_reaped(process p)
{
    return list_empty(&p->l);
}

static procfs_node procfs_node_new(procfs_node parent, symbol name, enum procfs_kind kind,
                                   int pid, int n);

static void procfs_node_destroy(procfs_node node);

closure_function(1, 2, boolean, procfs_collect_children,
                 vector, v,
                 value k, value v)
{
    vector_push(bound(v), v);
    return true;
}

static void procfs_destroy_children(tuple c)
{
    vector v = allocate_vector(procfs_heap(), 8);
    assert(v != INVALID_ADDRESS);
    iterate(c, stack_closure(procfs_collect_children, v));
    tuple child;
    vector_foreach(v, child) {
        procfs_node cn = procfs_node_of(child);
        if (cn)
            procfs_node_destroy(cn);
    }
    deallocate_vector(v);
}

static void procfs_node_destroy(procfs_node node)
{
    tuple md = node->md;
    tuple c = children(md);
    if (c) {
        procfs_destroy_children(c);
        set(md, sym(children), 0);
        deallocate_value(c);
    }
    tuple parent = get_tuple(md, sym_this(".."));
    if (parent && parent != md) {
        tuple pc = children(parent);
        symbol name = pc ? tuple_get_symbol(pc, md) : 0;
        if (name)
            set(pc, name, 0);
    }
    set(md, sym_this(".."), 0);
    set(md, sym(special), 0);
    value v = get(md, sym(linktarget));
    if (v) {
        set(md, sym(linktarget), 0);
        deallocate_value(v);
    }
    v = get(md, sym(nlink));
    if (v) {
        set(md, sym(nlink), 0);
        deallocate_value(v);
    }
    set(md, sym(readonly), 0);
    set(md, sym(procfd), 0);
    table_set(procfs.by_md, md, 0);
    table_set(procfs.by_ino, pointer_from_u64(node->ino), 0);
    deallocate_value(md);
    deallocate(procfs_heap(), node, sizeof(*node));
}

static void procfs_set_linktarget(procfs_node node, buffer target)
{
    value old = get(node->md, sym(linktarget));
    set(node->md, sym(linktarget), target);
    if (old)
        deallocate_value(old);
}

static void procfs_set_nlink(procfs_node node, u64 nlink)
{
    value old = get(node->md, sym(nlink));
    set(node->md, sym(nlink), value_from_u64(nlink));
    if (old)
        deallocate_value(old);
}

static procfs_node procfs_child(procfs_node parent, symbol name)
{
    tuple c = children(parent->md);
    return c ? procfs_node_of(get_tuple(c, name)) : 0;
}

static void procfs_buffer_append_number(buffer b, u64 n)
{
    print_number(b, n, 10, 0, false);
}

static void procfs_refresh(procfs_node node);

closure_function(1, 2, boolean, procfs_prune_each,
                 vector, stale,
                 value k, value v)
{
    procfs_node cn = procfs_node_of(v);
    if (cn)
        vector_push(bound(stale), cn);
    return true;
}

static boolean procfs_int_in(vector v, int n)
{
    void *x;
    vector_foreach(v, x) {
        if ((int)u64_from_pointer(x) == n)
            return true;
    }
    return false;
}

static void procfs_sync_numbered(procfs_node dir, vector want, enum procfs_kind kind, int pid)
{
    vector existing = allocate_vector(procfs_heap(), 8);
    assert(existing != INVALID_ADDRESS);
    iterate(children(dir->md), stack_closure(procfs_prune_each, existing));
    procfs_node cn;
    vector_foreach(existing, cn) {
        if ((cn->kind == kind) && !procfs_int_in(want, cn->n))
            procfs_node_destroy(cn);
    }
    deallocate_vector(existing);
    void *x;
    vector_foreach(want, x) {
        int n = u64_from_pointer(x);
        symbol name = intern_u64(n);
        if (!procfs_child(dir, name))
            procfs_node_new(dir, name, kind, (kind == PROCFS_PID) ? n : pid, n);
    }
}

static void procfs_fds(process p, vector v)
{
    process_lock(p);
    fdtable fdt = p->fdtable;
    if (fdt)
        fdtable_reserve(fdt);
    process_unlock(p);
    if (!fdt)
        return;
    spin_lock(&fdt->lock);
    for (int fd = 0; fd < vector_length(fdt->files); fd++) {
        if (vector_get(fdt->files, fd))
            vector_push(v, pointer_from_u64((u64)fd));
    }
    spin_unlock(&fdt->lock);
    fdtable_release(fdt);
}

closure_function(1, 1, boolean, procfs_tid_each,
                 vector, v,
                 rbnode n)
{
    thread t = struct_from_field(n, thread, n);
    vector_push(bound(v), pointer_from_u64((u64)t->tid));
    return true;
}

static void procfs_tids(process p, vector v)
{
    spin_lock(&p->threads_lock);
    rbtree_traverse(p->threads, RB_INORDER, stack_closure(procfs_tid_each, v));
    spin_unlock(&p->threads_lock);
}

static void procfs_refresh(procfs_node node)
{
    vector want;
    process p;
    switch (node->kind) {
    case PROCFS_ROOT:
        want = allocate_vector(procfs_heap(), 16);
        assert(want != INVALID_ADDRESS);
        process_list_pids(want);
        procfs_sync_numbered(node, want, PROCFS_PID, 0);
        deallocate_vector(want);
        break;
    case PROCFS_FD_DIR:
    case PROCFS_FDINFO_DIR:
    case PROCFS_TASK_DIR:
        p = process_get(node->pid);
        if (!p)
            return;
        want = allocate_vector(procfs_heap(), 16);
        assert(want != INVALID_ADDRESS);
        if (node->kind == PROCFS_TASK_DIR) {
            procfs_tids(p, want);
            procfs_sync_numbered(node, want, PROCFS_TID, node->pid);
            procfs_set_nlink(node, vector_length(want) + 2);
        } else {
            procfs_fds(p, want);
            procfs_sync_numbered(node, want,
                                 (node->kind == PROCFS_FD_DIR) ? PROCFS_FD : PROCFS_FDINFO,
                                 node->pid);
        }
        process_release(p);
        deallocate_vector(want);
        break;
    case PROCFS_SELF:
    case PROCFS_THREAD_SELF: {
        buffer b = allocate_string(24);
        assert(b != INVALID_ADDRESS);
        procfs_buffer_append_number(b, current->p->pid);
        if (node->kind == PROCFS_THREAD_SELF) {
            buffer_write_cstring(b, "/task/");
            procfs_buffer_append_number(b, current->tid);
        }
        procfs_set_linktarget(node, b);
        break;
    }
    case PROCFS_EXE:
        p = process_get(node->pid);
        if (!p)
            return;
        buffer b = allocate_string(64);
        assert(b != INVALID_ADDRESS);
        process_lock(p);
        if (p->exe)
            buffer_write(b, buffer_ref(p->exe, 0), buffer_length(p->exe));
        process_unlock(p);
        process_release(p);
        procfs_set_linktarget(node, b);
        break;
    case PROCFS_ROOT_LINK: {
        p = process_get(node->pid);
        if (!p)
            return;
        buffer b = allocate_buffer(procfs_heap(), PATH_MAX);
        assert(b != INVALID_ADDRESS);
        fs_struct pfs = p->fs;
        spin_lock(&pfs->lock);
        if (buffer_length(pfs->root_path))
            buffer_write(b, buffer_ref(pfs->root_path, 0), buffer_length(pfs->root_path));
        else
            push_u8(b, '/');
        spin_unlock(&pfs->lock);
        process_release(p);
        procfs_set_linktarget(node, b);
        break;
    }
    default:
        break;
    }
}

static boolean procfs_node_alive(procfs_node node)
{
    if (node->pid == 0)
        return true;
    process p = process_get(node->pid);
    if (!p)
        return false;
    boolean alive = !process_reaped(p);
    if (alive && (node->kind == PROCFS_TID || node->kind == PROCFS_TID_STATUS)) {
        thread t = thread_from_tid(p, node->n);
        if (t == INVALID_ADDRESS)
            alive = false;
        else
            thread_release(t);
    }
    if (alive && (node->kind == PROCFS_FD || node->kind == PROCFS_FDINFO)) {
        fdtable fdt;
        process_lock(p);
        fdt = p->fdtable;
        if (fdt)
            fdtable_reserve(fdt);
        process_unlock(p);
        if (fdt) {
            spin_lock(&fdt->lock);
            alive = vector_get(fdt->files, node->n) != 0;
            spin_unlock(&fdt->lock);
            fdtable_release(fdt);
        } else {
            alive = false;
        }
    }
    process_release(p);
    return alive;
}

static void procfs_cap_line(buffer b, sstring name, u64 caps)
{
    bprintf(b, "%s:\t", name);
    print_number(b, caps, 16, 16, false);
    push_u8(b, '\n');
}

static void procfs_thread_name(process p, int tid, char *name)
{
    zero(name, 16);
    thread t = thread_from_tid(p, tid);
    if (t == INVALID_ADDRESS) {
        spin_lock(&p->threads_lock);
        rbnode n = rbtree_find_first(p->threads);
        if (n != INVALID_ADDRESS)
            runtime_memcpy(name, struct_from_field(n, thread, n)->name, 15);
        spin_unlock(&p->threads_lock);
        return;
    }
    runtime_memcpy(name, t->name, 15);
    thread_release(t);
}

static int procfs_thread_count(process p)
{
    vector v = allocate_vector(procfs_heap(), 8);
    assert(v != INVALID_ADDRESS);
    procfs_tids(p, v);
    int n = vector_length(v);
    deallocate_vector(v);
    return n;
}

static void procfs_status(buffer b, process p, int tid)
{
    char name[16];
    procfs_thread_name(p, tid, name);
    boolean zombie = (p->state == PROCESS_ZOMBIE);
    int ppid = process_getppid(p);
    user_namespace viewer_ns = process_user_ns(current->p);
    bprintf(b, "Name:\t%s\n", sstring_from_cstring(name, sizeof(name)));
    bprintf(b, "State:\t%s\n", zombie ? ss("Z (zombie)") : ss("R (running)"));
    bprintf(b, "Tgid:\t%d\nNgid:\t0\nPid:\t%d\nPPid:\t%d\nTracerPid:\t0\n", p->pid, tid, ppid);
    process_lock(p);
    struct creds *c = &p->creds;
    bprintf(b, "Uid:\t%d\t%d\t%d\t%d\n", user_ns_from_kuid(viewer_ns, c->uid),
            user_ns_from_kuid(viewer_ns, c->euid), user_ns_from_kuid(viewer_ns, c->suid),
            user_ns_from_kuid(viewer_ns, c->fsuid));
    bprintf(b, "Gid:\t%d\t%d\t%d\t%d\n", user_ns_from_kgid(viewer_ns, c->gid),
            user_ns_from_kgid(viewer_ns, c->egid), user_ns_from_kgid(viewer_ns, c->sgid),
            user_ns_from_kgid(viewer_ns, c->fsgid));
    buffer_write_cstring(b, "Groups:\t");
    for (u32 i = 0; i < c->ngroups; i++)
        bprintf(b, "%d ", user_ns_from_kgid(viewer_ns, c->groups[i]));
    push_u8(b, '\n');
    u64 inh = c->cap_inheritable, prm = c->cap_permitted, eff = c->cap_effective;
    u64 bnd = c->cap_bset, amb = c->cap_ambient;
    int pgid = p->pgid;
    process_unlock(p);
    bprintf(b, "NStgid:\t%d\nNSpid:\t%d\nNSpgid:\t%d\nNSsid:\t%d\n", p->pid, tid, pgid, pgid);
    bprintf(b, "Threads:\t%d\n", zombie ? 1 : procfs_thread_count(p));
    u64 ign = 0, cgt = 0;
    for (int sig = 1; sig <= NSIG; sig++) {
        void *h = p->sigactions[sig - 1].sa_handler;
        if (h == SIG_IGN)
            ign |= 1ull << (sig - 1);
        else if (h != SIG_DFL)
            cgt |= 1ull << (sig - 1);
    }
    procfs_cap_line(b, ss("SigIgn"), ign);
    procfs_cap_line(b, ss("SigCgt"), cgt);
    procfs_cap_line(b, ss("CapInh"), inh);
    procfs_cap_line(b, ss("CapPrm"), prm);
    procfs_cap_line(b, ss("CapEff"), eff);
    procfs_cap_line(b, ss("CapBnd"), bnd);
    procfs_cap_line(b, ss("CapAmb"), amb);
    u8 sec_mode = 0;
    u32 sec_filters = 0;
    boolean nnp = false;
    thread tt = thread_from_tid(p, tid);
    if (tt != INVALID_ADDRESS) {
        nnp = tt->no_new_privs;
        sec_mode = tt->seccomp_mode;
        sec_filters = seccomp_filter_count(tt->seccomp);
        thread_release(tt);
    }
    bprintf(b, "NoNewPrivs:\t%d\nSeccomp:\t%d\nSeccomp_filters:\t%d\n", nnp ? 1 : 0, sec_mode, sec_filters);
    user_ns_release(viewer_ns);
}

static void procfs_stat(buffer b, process p)
{
    char name[16];
    procfs_thread_name(p, p->pid, name);
    boolean zombie = (p->state == PROCESS_ZOMBIE);
    bprintf(b, "%d (%s) %c %d %d %d", p->pid, sstring_from_cstring(name, sizeof(name)),
            zombie ? 'Z' : 'R', process_getppid(p), p->pgid, p->pgid);
    for (int field = 7; field <= 52; field++) {
        if (field == 20)
            bprintf(b, " %d", zombie ? 1 : procfs_thread_count(p));
        else
            buffer_write_cstring(b, " 0");
    }
    push_u8(b, '\n');
}

closure_function(3, 1, boolean, procfs_maps_each,
                 buffer, b, vmap, stack, vmap, heap_map,
                 vmap map)
{
    buffer b = bound(b);
    bprintf(b, "%016lx-%016lx %c%c%c%c 00000000 00:00 0", map->node.r.start, map->node.r.end,
            (map->flags & VMAP_FLAG_READABLE) ? 'r' : '-',
            (map->flags & VMAP_FLAG_WRITABLE) ? 'w' : '-',
            (map->flags & VMAP_FLAG_EXEC) ? 'x' : '-',
            (map->flags & VMAP_FLAG_SHARED) ? 's' : 'p');
    if (map == bound(stack))
        buffer_write_cstring(b, "\t[stack]");
    else if (map == bound(heap_map))
        buffer_write_cstring(b, "\t[heap]");
    push_u8(b, '\n');
    return true;
}

static void procfs_maps(buffer b, process p)
{
    process_lock(p);
    process_vm vm = p->vm;
    if (vm)
        process_vm_reserve(vm);
    process_unlock(p);
    if (!vm)
        return;
    process_vm_lock(vm);
    vmap_handler h = stack_closure(procfs_maps_each, b, vm->stack_map, vm->heap_map);
    vmap m = (vmap)rangemap_first_node(vm->vmaps);
    while (m != INVALID_ADDRESS) {
        apply(h, m);
        m = (vmap)rangemap_next_node(vm->vmaps, &m->node);
    }
    process_vm_unlock(vm);
    process_vm_release(vm);
}

static void procfs_octal(buffer b, u64 v)
{
    push_u8(b, '0');
    print_number(b, v, 8, 0, false);
}

static fdesc procfs_get_fdesc(process p, int fd, u32 *fd_flags)
{
    process_lock(p);
    fdtable fdt = p->fdtable;
    if (fdt)
        fdtable_reserve(fdt);
    process_unlock(p);
    if (!fdt)
        return 0;
    spin_lock(&fdt->lock);
    fdesc f = vector_get(fdt->files, fd);
    if (f)
        fetch_and_add(&f->refcnt, 1);
    spin_unlock(&fdt->lock);
    if (f && fd_flags)
        *fd_flags = fdtable_get_fd_flags(fdt, fd);
    fdtable_release(fdt);
    return f;
}

static boolean fdesc_is_file(fdesc f)
{
    switch (f->type) {
    case FDESC_TYPE_REGULAR:
    case FDESC_TYPE_DIRECTORY:
    case FDESC_TYPE_SPECIAL:
    case FDESC_TYPE_SYMLINK:
        return true;
    default:
        return false;
    }
}

static void procfs_fdinfo(buffer b, process p, int fd)
{
    u32 fd_flags = 0;
    fdesc f = procfs_get_fdesc(p, fd, &fd_flags);
    if (!f)
        return;
    u64 pos = fdesc_is_file(f) ? ((file)f)->offset : 0;
    u64 flags = f->flags | ((fd_flags & FD_CLOEXEC) ? O_CLOEXEC : 0);
    bprintf(b, "pos:\t%ld\nflags:\t", pos);
    procfs_octal(b, flags);
    buffer_write_cstring(b, "\nmnt_id:\t0\n");
    fdesc_put(f);
}

static void userns_map_read(procfs_file pf, buffer b)
{
    user_namespace ns = pf->ns;
    if (!ns)
        return;
    boolean group = (pf->kind == PROCFS_GID_MAP);
    struct id_map map;
    spin_lock(&ns->lock);
    map = group ? ns->gid_map : ns->uid_map;
    spin_unlock(&ns->lock);
    user_namespace opener = process_user_ns(current->p);
    for (u32 i = 0; i < map.nr; i++) {
        struct id_extent *e = &map.e[i];
        u32 lower = e->lower_first;
        if (opener != ns) {
            u32 k;
            if (ns->parent &&
                (group ? user_ns_to_kgid(ns->parent, e->lower_first, &k)
                       : user_ns_to_kuid(ns->parent, e->lower_first, &k)))
                lower = group ? user_ns_from_kgid(opener, k) : user_ns_from_kuid(opener, k);
            else
                lower = USER_NS_OVERFLOW_ID;
        }
        bprintf(b, "%u %u %u\n", e->first, lower, e->count);
    }
    user_ns_release(opener);
}

static sysreturn userns_map_parse(char *s, u64 len, struct id_map *m)
{
    u32 nr = 0;
    char *p = s, *end = s + len;
    while (p < end) {
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\n'))
            p++;
        if (p == end)
            break;
        if (nr == USER_NS_MAP_EXTENTS)
            return -EINVAL;
        u32 v[3];
        for (int i = 0; i < 3; i++) {
            if (p == end || *p < '0' || *p > '9')
                return -EINVAL;
            u64 x = 0;
            while (p < end && *p >= '0' && *p <= '9') {
                x = x * 10 + (*p - '0');
                if (x > U32_MAX)
                    return -EINVAL;
                p++;
            }
            v[i] = x;
            if (i < 2) {
                if (p == end || (*p != ' ' && *p != '\t'))
                    return -EINVAL;
                while (p < end && (*p == ' ' || *p == '\t'))
                    p++;
            }
        }
        if (p < end && *p != '\n' && *p != ' ' && *p != '\t')
            return -EINVAL;
        if (v[2] == 0 || ((u64)v[0] + v[2] > (u64)U32_MAX + 1) ||
            ((u64)v[1] + v[2] > (u64)U32_MAX + 1))
            return -EINVAL;
        m->e[nr++] = (struct id_extent){ v[0], v[1], v[2] };
    }
    if (!nr)
        return -EINVAL;
    for (u32 i = 0; i < nr; i++)
        for (u32 j = i + 1; j < nr; j++) {
            struct id_extent *a = &m->e[i], *c = &m->e[j];
            if (((u64)a->first < (u64)c->first + c->count &&
                 (u64)c->first < (u64)a->first + a->count) ||
                ((u64)a->lower_first < (u64)c->lower_first + c->count &&
                 (u64)c->lower_first < (u64)a->lower_first + a->count))
                return -EINVAL;
        }
    m->nr = nr;
    return 0;
}

static sysreturn userns_map_write(procfs_file pf, const u8 *src, u64 len, u64 offset)
{
    user_namespace ns = pf->ns;
    if (!ns || !ns->parent)
        return -EPERM;
    if (offset != 0)
        return -EINVAL;
    boolean group = (pf->kind == PROCFS_GID_MAP);
    struct id_map *m = group ? &ns->gid_map : &ns->uid_map;
    spin_lock(&ns->lock);
    boolean written = m->written;
    spin_unlock(&ns->lock);
    if (written)
        return -EPERM;
    if (len == 0)
        return 0;
    if (len >= PAGESIZE)
        return -EINVAL;
    heap h = procfs_heap();
    char *buf = allocate(h, len + 1);
    if (buf == INVALID_ADDRESS)
        return -ENOMEM;
    if (!copy_from_user(src, buf, len)) {
        deallocate(h, buf, len + 1);
        return -EFAULT;
    }
    buf[len] = '\0';
    struct id_map newmap;
    zero(&newmap, sizeof(newmap));
    sysreturn rv = userns_map_parse(buf, len, &newmap);
    deallocate(h, buf, len + 1);
    if (rv)
        return rv;
    process p = current->p;
    process_lock(p);
    user_namespace cur = p->creds.user_ns;
    u32 euid = p->creds.euid;
    process_unlock(p);
    if (cur != ns && cur != ns->parent)
        return -EPERM;
    if (!ns_capable(p, ns, group ? CAP_SETGID : CAP_SETUID))
        return -EPERM;
    boolean privileged = ns_capable(p, ns->parent, group ? CAP_SETGID : CAP_SETUID);
    if (!privileged) {
        if (newmap.nr != 1 || newmap.e[0].count != 1)
            return -EPERM;
        u32 lower;
        if (!(group ? user_ns_to_kgid(ns->parent, newmap.e[0].lower_first, &lower)
                    : user_ns_to_kuid(ns->parent, newmap.e[0].lower_first, &lower)))
            return -EPERM;
        if (lower != euid)
            return -EPERM;
        spin_lock(&ns->lock);
        boolean groups_allowed = ns->setgroups_allowed;
        spin_unlock(&ns->lock);
        if (group && groups_allowed)
            return -EPERM;
    }
    for (u32 i = 0; i < newmap.nr; i++) {
        struct id_extent *e = &newmap.e[i];
        u32 k;
        if (!(group ? user_ns_to_kgid(ns->parent, e->lower_first, &k)
                    : user_ns_to_kuid(ns->parent, e->lower_first, &k)))
            return -EPERM;
        u32 last = e->lower_first + e->count - 1;
        if (!(group ? user_ns_to_kgid(ns->parent, last, &k)
                    : user_ns_to_kuid(ns->parent, last, &k)))
            return -EPERM;
    }
    spin_lock(&ns->lock);
    if (m->written) {
        spin_unlock(&ns->lock);
        return -EPERM;
    }
    *m = newmap;
    m->written = true;
    spin_unlock(&ns->lock);
    return len;
}

static sysreturn userns_setgroups_write(procfs_file pf, const u8 *src, u64 len, u64 offset)
{
    user_namespace ns = pf->ns;
    if (!ns || !ns->parent)
        return -EPERM;
    if (offset != 0)
        return -EINVAL;
    char buf[16];
    if (len == 0 || len >= sizeof(buf))
        return -EINVAL;
    u64 count = len;
    if (!copy_from_user(src, buf, len))
        return -EFAULT;
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == ' ' || buf[len - 1] == '\t'))
        len--;
    if (len == 4 && !runtime_memcmp(buf, "deny", 4)) {
        spin_lock(&ns->lock);
        if (ns->gid_map.written) {
            spin_unlock(&ns->lock);
            return -EPERM;
        }
        ns->setgroups_allowed = false;
        spin_unlock(&ns->lock);
        return count;
    }
    if (len == 5 && !runtime_memcmp(buf, "allow", 5)) {
        spin_lock(&ns->lock);
        if (!ns->setgroups_allowed) {
            spin_unlock(&ns->lock);
            return -EPERM;
        }
        spin_unlock(&ns->lock);
        return count;
    }
    return -EINVAL;
}

closure_func_basic(file_io, sysreturn, procfs_file_write,
                   void *src, u64 len, u64 offset, context ctx, boolean bh, io_completion completion)
{
    procfs_file pf = struct_from_closure(procfs_file, write);
    file f = &pf->w.f;
    boolean is_file_offset = (offset == infinity);
    if (is_file_offset)
        offset = f->offset;
    sysreturn rv = (pf->kind == PROCFS_SETGROUPS) ?
        userns_setgroups_write(pf, src, len, offset) : userns_map_write(pf, src, len, offset);
    if ((rv > 0) && is_file_offset)
        f->offset += rv;
    return io_complete(completion, rv);
}

static sysreturn procfs_generate(procfs_file pf, buffer b)
{
    process p = process_get(pf->pid);
    if (!p)
        return -ESRCH;
    sysreturn rv = 0;
    if (process_reaped(p)) {
        rv = -ESRCH;
        goto out;
    }
    switch (pf->kind) {
    case PROCFS_STATUS:
        procfs_status(b, p, p->pid);
        break;
    case PROCFS_TID_STATUS:
        procfs_status(b, p, pf->n);
        break;
    case PROCFS_CMDLINE:
        process_lock(p);
        if (p->cmdline)
            buffer_write(b, buffer_ref(p->cmdline, 0), buffer_length(p->cmdline));
        process_unlock(p);
        break;
    case PROCFS_STAT:
        procfs_stat(b, p);
        break;
    case PROCFS_MAPS:
        procfs_maps(b, p);
        break;
    case PROCFS_FDINFO:
        procfs_fdinfo(b, p, pf->n);
        break;
    case PROCFS_UID_MAP:
    case PROCFS_GID_MAP:
        userns_map_read(pf, b);
        break;
    case PROCFS_SETGROUPS:
        spin_lock(&pf->ns->lock);
        if (pf->ns->setgroups_allowed)
            buffer_write_cstring(b, "allow\n");
        else
            buffer_write_cstring(b, "deny\n");
        spin_unlock(&pf->ns->lock);
        break;
    default:
        rv = -EINVAL;
    }
  out:
    process_release(p);
    return rv;
}

closure_func_basic(file_io, sysreturn, procfs_file_read,
                   void *dest, u64 len, u64 offset, context ctx, boolean bh, io_completion completion)
{
    procfs_file pf = struct_from_closure(procfs_file, read);
    file f = &pf->w.f;
    boolean is_file_offset = (offset == infinity);
    buffer b = allocate_buffer(procfs_heap(), 512);
    sysreturn nr;
    if (b == INVALID_ADDRESS) {
        nr = -ENOMEM;
        goto out;
    }
    nr = procfs_generate(pf, b);
    if (nr == 0) {
        context c = get_current_context(current_cpu());
        if (!context_set_err(c)) {
            nr = buffer_read_at(b, is_file_offset ? f->offset : offset, dest, len);
            context_clear_err(c);
        } else {
            nr = -EFAULT;
        }
        if ((nr > 0) && is_file_offset)
            f->offset += nr;
    }
    deallocate_buffer(b);
  out:
    return io_complete(completion, nr);
}

closure_func_basic(fdesc_events, u32, procfs_file_events,
                   thread t)
{
    return EPOLLIN;
}

static boolean procfs_kind_is_ns(enum procfs_kind kind)
{
    switch (kind) {
    case PROCFS_NS_USER:
    case PROCFS_NS_PID:
    case PROCFS_NS_NET:
    case PROCFS_NS_IPC:
    case PROCFS_NS_MNT:
    case PROCFS_NS_UTS:
        return true;
    default:
        return false;
    }
}

static enum namespace_kind procfs_ns_namespace_kind(enum procfs_kind kind)
{
    switch (kind) {
    case PROCFS_NS_PID: return NAMESPACE_PID;
    case PROCFS_NS_NET: return NAMESPACE_NET;
    case PROCFS_NS_IPC: return NAMESPACE_IPC;
    case PROCFS_NS_MNT: return NAMESPACE_MNT;
    case PROCFS_NS_UTS: return NAMESPACE_UTS;
    default: return NAMESPACE_USER;
    }
}

static const struct {
    sstring name;
    enum procfs_kind kind;
} procfs_ns_entries[] = {
    { ss_static_init("user"), PROCFS_NS_USER },
    { ss_static_init("pid"), PROCFS_NS_PID },
    { ss_static_init("net"), PROCFS_NS_NET },
    { ss_static_init("ipc"), PROCFS_NS_IPC },
    { ss_static_init("mnt"), PROCFS_NS_MNT },
    { ss_static_init("uts"), PROCFS_NS_UTS },
};

closure_func_basic(fdesc_close, sysreturn, procfs_file_close,
                   context ctx, io_completion completion)
{
    procfs_file pf = struct_from_closure(procfs_file, close);
    if (pf->ns)
        user_ns_release(pf->ns);
    file_release(&pf->w.f);
    return io_complete(completion, 0);
}

closure_func_basic(spec_file_open, sysreturn, procfs_node_open,
                   file f)
{
    procfs_node node = struct_from_closure(procfs_node, open);
    procfs_file pf = (procfs_file)f;
    pf->kind = node->kind;
    pf->pid = node->pid;
    pf->n = node->n;
    pf->ns = 0;
    f->f.read = init_closure_func(&pf->read, file_io, procfs_file_read);
    f->f.events = init_closure_func(&pf->events, fdesc_events, procfs_file_events);
    f->f.close = init_closure_func(&pf->close, fdesc_close, procfs_file_close);
    switch (node->kind) {
    case PROCFS_UID_MAP:
    case PROCFS_GID_MAP:
    case PROCFS_SETGROUPS: {
        process p = process_get(node->pid);
        if (!p)
            return -ESRCH;
        user_namespace ns = process_user_ns(p);
        process_release(p);
        pf->ns = ns;
        if (node->kind == PROCFS_SETGROUPS) {
            if (!ns_capable(current->p, ns, CAP_SYS_ADMIN)) {
                user_ns_release(ns);
                pf->ns = 0;
                return -EACCES;
            }
        }
        f->f.write = init_closure_func(&pf->write, file_io, procfs_file_write);
        break;
    }
    default:
        break;
    }
    return 0;
}

static const struct {
    sstring name;
    enum procfs_kind kind;
} procfs_pid_entries[] = {
    { ss_static_init("status"), PROCFS_STATUS },
    { ss_static_init("cmdline"), PROCFS_CMDLINE },
    { ss_static_init("stat"), PROCFS_STAT },
    { ss_static_init("maps"), PROCFS_MAPS },
    { ss_static_init("exe"), PROCFS_EXE },
    { ss_static_init("fd"), PROCFS_FD_DIR },
    { ss_static_init("fdinfo"), PROCFS_FDINFO_DIR },
    { ss_static_init("task"), PROCFS_TASK_DIR },
    { ss_static_init("root"), PROCFS_ROOT_LINK },
    { ss_static_init("uid_map"), PROCFS_UID_MAP },
    { ss_static_init("gid_map"), PROCFS_GID_MAP },
    { ss_static_init("setgroups"), PROCFS_SETGROUPS },
    { ss_static_init("ns"), PROCFS_NS_DIR },
};

static procfs_node procfs_node_new(procfs_node parent, symbol name, enum procfs_kind kind,
                                   int pid, int n)
{
    heap h = procfs_heap();
    procfs_node node = allocate(h, sizeof(*node));
    assert(node != INVALID_ADDRESS);
    node->md = allocate_tuple();
    assert(node->md != INVALID_ADDRESS);
    node->ino = procfs.next_ino++;
    node->kind = kind;
    node->pid = pid;
    node->n = n;
    table_set(procfs.by_md, node->md, node);
    table_set(procfs.by_ino, pointer_from_u64(node->ino), node);
    if (procfs_kind_is_dir(kind)) {
        set(node->md, sym(children), allocate_tuple());
        set(node->md, sym_this(".."), parent ? parent->md : node->md);
    }
    if (procfs_kind_is_generated_file(kind)) {
        set(node->md, sym(special), init_closure_func(&node->open, spec_file_open,
                                                      procfs_node_open));
        set(node->md, sym(special_alloc_size), pointer_from_u64(sizeof(struct procfs_file)));
        if (kind != PROCFS_UID_MAP && kind != PROCFS_GID_MAP && kind != PROCFS_SETGROUPS)
            set(node->md, sym(readonly), null_value);
    }
    if (kind == PROCFS_FD || procfs_kind_is_ns(kind))
        set(node->md, sym(procfd), null_value);
    if (kind == PROCFS_SELF || kind == PROCFS_THREAD_SELF) {
        buffer b = allocate_string(1);
        assert(b != INVALID_ADDRESS);
        push_u8(b, '0');
        set(node->md, sym(linktarget), b);
    }
    if (kind == PROCFS_ROOT_LINK) {
        buffer b = allocate_string(2);
        assert(b != INVALID_ADDRESS);
        push_u8(b, '/');
        set(node->md, sym(linktarget), b);
    }
    if (parent)
        set(children(parent->md), name, node->md);
    if (kind == PROCFS_PID || kind == PROCFS_TID) {
        int count = (kind == PROCFS_PID) ? _countof(procfs_pid_entries) : 1;
        for (int i = 0; i < count; i++)
            procfs_node_new(node, sym_sstring(procfs_pid_entries[i].name),
                            procfs_pid_entries[i].kind == PROCFS_STATUS && kind == PROCFS_TID ?
                            PROCFS_TID_STATUS : procfs_pid_entries[i].kind, pid, n);
    }
    if (kind == PROCFS_NS_DIR) {
        for (int i = 0; i < _countof(procfs_ns_entries); i++)
            procfs_node_new(node, sym_sstring(procfs_ns_entries[i].name),
                            procfs_ns_entries[i].kind, pid, n);
    }
    if (kind != PROCFS_SELF && kind != PROCFS_THREAD_SELF)
        procfs_refresh(node);
    return node;
}

static tuple procfs_lookup(filesystem fs, tuple parent, string name)
{
    procfs_node pn = procfs_node_of(parent);
    if (!pn || !procfs_node_alive(pn))
        return 0;
    procfs_refresh(pn);
    tuple t = lookup(parent, intern(name));
    procfs_node node = procfs_node_of(t);
    if (!node || !procfs_node_alive(node))
        return 0;
    if (node != pn)
        procfs_refresh(node);
    return t;
}

static inode procfs_get_inode(filesystem fs, tuple md)
{
    procfs_node node = procfs_node_of(md);
    return node ? node->ino : 0;
}

static tuple procfs_get_meta(filesystem fs, inode n)
{
    procfs_node node = table_find(procfs.by_ino, pointer_from_u64(n));
    if (!node || !procfs_node_alive(node))
        return 0;
    if (procfs_kind_is_dir(node->kind))
        procfs_refresh(node);
    return node->md;
}

static int procfs_get_fsfile(filesystem fs, tuple md, fsfile *f)
{
    *f = 0;
    return procfs_node_of(md) ? 0 : -ENOENT;
}

static int procfs_create(filesystem fs, tuple parent, string name, tuple md, fsfile *f)
{
    return -EACCES;
}

static int procfs_unlink(filesystem fs, tuple parent, string name, tuple md, boolean *destruct_md)
{
    return -EACCES;
}

static int procfs_rename(filesystem fs, tuple old_parent, string old_name, tuple old_md,
                         tuple new_parent, string new_name, tuple new_md, boolean exchange,
                         boolean *destruct_md)
{
    return -EXDEV;
}

static u64 procfs_get_freeblocks(filesystem fs)
{
    return 0;
}

boolean procfs_fd_link(tuple n, int *pid, int *fd)
{
    procfs_node node = procfs_node_of(n);
    if (!node || node->kind != PROCFS_FD || !get(n, sym(procfd)))
        return false;
    *pid = node->pid;
    *fd = node->n;
    return true;
}

boolean procfs_node_path(tuple n, buffer b)
{
    procfs_node node = procfs_node_of(n);
    if (!node)
        return false;
    switch (node->kind) {
    case PROCFS_ROOT:
        buffer_write_cstring(b, "/proc");
        return true;
    case PROCFS_PID:
        bprintf(b, "/proc/%d", node->pid);
        return true;
    case PROCFS_STATUS:
        bprintf(b, "/proc/%d/status", node->pid);
        return true;
    case PROCFS_CMDLINE:
        bprintf(b, "/proc/%d/cmdline", node->pid);
        return true;
    case PROCFS_STAT:
        bprintf(b, "/proc/%d/stat", node->pid);
        return true;
    case PROCFS_MAPS:
        bprintf(b, "/proc/%d/maps", node->pid);
        return true;
    case PROCFS_EXE:
        bprintf(b, "/proc/%d/exe", node->pid);
        return true;
    case PROCFS_FD_DIR:
        bprintf(b, "/proc/%d/fd", node->pid);
        return true;
    case PROCFS_FD:
        bprintf(b, "/proc/%d/fd/%d", node->pid, node->n);
        return true;
    case PROCFS_FDINFO_DIR:
        bprintf(b, "/proc/%d/fdinfo", node->pid);
        return true;
    case PROCFS_FDINFO:
        bprintf(b, "/proc/%d/fdinfo/%d", node->pid, node->n);
        return true;
    case PROCFS_TASK_DIR:
        bprintf(b, "/proc/%d/task", node->pid);
        return true;
    case PROCFS_TID:
        bprintf(b, "/proc/%d/task/%d", node->pid, node->n);
        return true;
    case PROCFS_TID_STATUS:
        bprintf(b, "/proc/%d/task/%d/status", node->pid, node->n);
        return true;
    case PROCFS_UID_MAP:
        bprintf(b, "/proc/%d/uid_map", node->pid);
        return true;
    case PROCFS_GID_MAP:
        bprintf(b, "/proc/%d/gid_map", node->pid);
        return true;
    case PROCFS_SETGROUPS:
        bprintf(b, "/proc/%d/setgroups", node->pid);
        return true;
    case PROCFS_ROOT_LINK:
        bprintf(b, "/proc/%d/root", node->pid);
        return true;
    case PROCFS_NS_DIR:
        bprintf(b, "/proc/%d/ns", node->pid);
        return true;
    case PROCFS_NS_USER:
    case PROCFS_NS_PID:
    case PROCFS_NS_NET:
    case PROCFS_NS_IPC:
    case PROCFS_NS_MNT:
    case PROCFS_NS_UTS: {
        const char *name = namespace_kind_name(procfs_ns_namespace_kind(node->kind));
        bprintf(b, "/proc/%d/ns/%s", node->pid, sstring_from_cstring(name, 8));
        return true;
    }
    default:
        return false;
    }
}

boolean procfs_ns_link(tuple n, char *buf, u64 bufsiz, sysreturn *rv)
{
    procfs_node node = procfs_node_of(n);
    if (!node || !procfs_kind_is_ns(node->kind))
        return false;
    process p = process_get(node->pid);
    if (!p) {
        *rv = -ESRCH;
        return true;
    }
    enum namespace_kind kind = procfs_ns_namespace_kind(node->kind);
    u32 inum = namespace_inum(p, kind);
    process_release(p);
    buffer tmp = little_stack_buffer(32);
    bprintf(tmp, "%s:[%u]", sstring_from_cstring(namespace_kind_name(kind), 8), inum);
    u64 len = MIN(bufsiz, buffer_length(tmp));
    runtime_memcpy(buf, buffer_ref(tmp, 0), len);
    *rv = len;
    return true;
}

static fdesc procfs_fd_target(int pid, int fd, sysreturn *rv)
{
    process self = current->p;
    if (pid != self->pid && !capable(self, CAP_SYS_PTRACE)) {
        *rv = -EACCES;
        return 0;
    }
    process p = process_get(pid);
    if (!p) {
        *rv = -ENOENT;
        return 0;
    }
    fdesc f = procfs_get_fdesc(p, fd, 0);
    process_release(p);
    if (!f)
        *rv = -ENOENT;
    return f;
}

sysreturn procfs_fd_open(int pid, int fd, int flags)
{
    if ((flags & O_NOFOLLOW) && !(flags & O_PATH))
        return -ELOOP;
    sysreturn rv;
    fdesc target = procfs_fd_target(pid, fd, &rv);
    if (!target)
        return rv;
    if (target->type != FDESC_TYPE_REGULAR && target->type != FDESC_TYPE_DIRECTORY) {
        rv = -ENXIO;
        goto out;
    }
    file tf = (file)target;
    filesystem fs = tf->fs;
    filesystem_lock(fs);
    tuple md = fs->get_meta(fs, tf->n);
    if (!md && target->type == FDESC_TYPE_REGULAR && tf->n == fs->get_inode(fs, fs->root))
        md = fs->root;
    if (!md) {
        filesystem_unlock(fs);
        rv = -ENOENT;
        goto out;
    }
    int accmode = flags & O_ACCMODE;
    if (accmode == 3) {
        rv = -EINVAL;
    } else if (accmode != O_RDONLY && target->type == FDESC_TYPE_DIRECTORY) {
        rv = -EISDIR;
    } else if (accmode != O_RDONLY && !(file_meta_perms(current->p, md) & ACCESS_PERM_WRITE)) {
        rv = -EACCES;
    } else {
        fsfile fsf = tf->fsf;
        if (fsf)
            fsfile_reserve(fsf);
        rv = unix_file_new(fs, md, target->type, flags & ~(O_CREAT | O_EXCL | O_TRUNC | O_TMPFILE),
                           fsf);
        if (rv < 0 && fsf)
            fsfile_release(fsf);
    }
    filesystem_put_meta(fs, md);
  out:
    fdesc_put(target);
    return rv;
}

sysreturn procfs_fd_stat(int pid, int fd, struct stat *s)
{
    sysreturn rv;
    fdesc target = procfs_fd_target(pid, fd, &rv);
    if (!target)
        return rv;
    rv = fdesc_stat(target, s);
    fdesc_put(target);
    return rv;
}

sysreturn procfs_fd_readlink(int pid, int fd, buffer b)
{
    sysreturn rv;
    fdesc target = procfs_fd_target(pid, fd, &rv);
    if (!target)
        return rv;
    rv = 0;
    u64 id = u64_from_pointer(target) >> 6;
    switch (target->type) {
    case FDESC_TYPE_REGULAR:
    case FDESC_TYPE_DIRECTORY:
    case FDESC_TYPE_SPECIAL:
    case FDESC_TYPE_SYMLINK: {
        file f = (file)target;
        tuple md = filesystem_get_meta(f->fs, f->n);
        boolean unnamed = (target->type == FDESC_TYPE_REGULAR) && (!md || is_dir(md));
        if (md)
            filesystem_put_meta(f->fs, md);
        if (unnamed) {
            buffer_write_cstring(b, "/memfd: (deleted)");
            break;
        }
        if (!buffer_extend(b, PATH_MAX)) {
            rv = -ENOMEM;
            break;
        }
        int len = file_get_path(f->fs, f->n, buffer_end(b), buffer_space(b));
        if (len > 0)
            buffer_produce(b, len - 1);
        else
            rv = -ENOENT;
        break;
    }
    case FDESC_TYPE_SOCKET:
        bprintf(b, "socket:[%ld]", id);
        break;
    case FDESC_TYPE_PIPE:
        bprintf(b, "pipe:[%ld]", id);
        break;
    case FDESC_TYPE_STDIO:
        buffer_write_cstring(b, "/dev/console");
        break;
    case FDESC_TYPE_EPOLL:
        buffer_write_cstring(b, "anon_inode:[eventpoll]");
        break;
    case FDESC_TYPE_EVENTFD:
        buffer_write_cstring(b, "anon_inode:[eventfd]");
        break;
    case FDESC_TYPE_SIGNALFD:
        buffer_write_cstring(b, "anon_inode:[signalfd]");
        break;
    case FDESC_TYPE_TIMERFD:
        buffer_write_cstring(b, "anon_inode:[timerfd]");
        break;
    case FDESC_TYPE_IORING:
        buffer_write_cstring(b, "anon_inode:[io_uring]");
        break;
    case FDESC_TYPE_INOTIFY:
        buffer_write_cstring(b, "anon_inode:inotify");
        break;
    default:
        bprintf(b, "anon_inode:[%ld]", id);
    }
    fdesc_put(target);
    return rv;
}

boolean procfs_add_static(sstring name, spec_file_open open, u64 alloc_size)
{
    filesystem_lock(&procfs.fs);
    procfs_node node = procfs_node_new(procfs.root, sym_sstring(name), PROCFS_STATIC, 0, 0);
    set(node->md, sym(special), open);
    set(node->md, sym(special_alloc_size), pointer_from_u64(alloc_size));
    filesystem_unlock(&procfs.fs);
    return true;
}

void procfs_init(filesystem root_fs)
{
    heap h = procfs_heap();
    status s = filesystem_init(&procfs.fs, h, 0, 1, true);
    assert(is_ok(s));
    procfs.fs.ro = false;
    procfs.by_md = allocate_table(h, identity_key, pointer_equal);
    procfs.by_ino = allocate_table(h, identity_key, pointer_equal);
    assert(procfs.by_md != INVALID_ADDRESS && procfs.by_ino != INVALID_ADDRESS);
    procfs.next_ino = 1;
    procfs.fs.lookup = procfs_lookup;
    procfs.fs.get_inode = procfs_get_inode;
    procfs.fs.get_meta = procfs_get_meta;
    procfs.fs.get_fsfile = procfs_get_fsfile;
    procfs.fs.create = procfs_create;
    procfs.fs.unlink = procfs_unlink;
    procfs.fs.rename = procfs_rename;
    procfs.fs.get_freeblocks = procfs_get_freeblocks;
    procfs.root = procfs_node_new(0, 0, PROCFS_ROOT, 0, 0);
    procfs.fs.root = procfs.root->md;
    procfs_node_new(procfs.root, sym(self), PROCFS_SELF, 0, 0);
    procfs_node_new(procfs.root, sym_this("thread-self"), PROCFS_THREAD_SELF, 0, 0);

    int fss = filesystem_mkdirpath(root_fs, 0, ss("/proc"), true);
    assert(fss == 0 || fss == -EEXIST);
    tuple proc_dir;
    filesystem fs = root_fs;
    fss = filesystem_get_node(&fs, root_fs->get_inode(root_fs, filesystem_getroot(root_fs)),
                              ss("/proc"), FS_NODE_FOLLOW, &proc_dir, 0, 0);
    assert(fss == 0);
    inode mount_dir = fs->get_inode(fs, proc_dir);
    filesystem_put_node(fs, proc_dir);
    assert(fs == root_fs);
    fss = filesystem_mount(root_fs, mount_dir, &procfs.fs);
    assert(fss == 0);
    storage_set_procfs_mount(procfs.fs.root, mount_dir);
}
