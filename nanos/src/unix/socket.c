#include <unix_internal.h>
#include <filesystem.h>
#include <net_system_structs.h>
#include <socket.h>

typedef struct unix_cred {
    process p;
    u32 uid, gid;
} *unix_cred;

typedef struct unixsock_scm {
    struct unix_cred cred;
    boolean has_cred;
    u16 nfds;
    fdesc fds[];
} *unixsock_scm;

typedef struct unixsock_msg {
    buffer b;
    struct sockaddr_un from_addr;
    unixsock_scm scm;
} *unixsock_msg;

#ifndef SCM_RIGHTS
#define SCM_RIGHTS      1
#endif
#ifndef SCM_CREDENTIALS
#define SCM_CREDENTIALS 2
#endif
#ifndef SO_PASSCRED
#define SO_PASSCRED     16
#endif
#ifndef SO_PEERCRED
#define SO_PEERCRED     17
#endif
#ifndef MSG_CTRUNC
#define MSG_CTRUNC      0x00000008
#endif
#ifndef MSG_CMSG_CLOEXEC
#define MSG_CMSG_CLOEXEC 0x40000000
#endif

#define SCM_MAX_FD      253

typedef struct unix_cmsghdr {
    u32 cmsg_len;
    u32 __pad1;
    s32 cmsg_level;
    s32 cmsg_type;
} unix_cmsghdr;

typedef struct unix_ucred {
    s32 pid;
    u32 uid;
    u32 gid;
} unix_ucred;

#define SCM_CMSG_ALIGN(len)   (((len) + 7ull) & ~7ull)
#define SCM_CMSG_SPACE(len)   (SCM_CMSG_ALIGN(sizeof(unix_cmsghdr)) + SCM_CMSG_ALIGN(len))
#define SCM_CMSG_LEN(len)     (SCM_CMSG_ALIGN(sizeof(unix_cmsghdr)) + (len))

#define UNIXSOCK_BUF_MAX_SIZE   PAGESIZE
#define UNIXSOCK_QUEUE_MAX_LEN  64

#define UNIXSOCK_RCV_SHUTDOWN   1
#define UNIXSOCK_SEND_SHUTDOWN  2
#define UNIXSOCK_SHUTDOWN_MASK  (UNIXSOCK_RCV_SHUTDOWN | UNIXSOCK_SEND_SHUTDOWN)

typedef struct unixsock {
    struct sock sock; /* must be first */
    queue data;
    filesystem fs;
    inode fs_entry;
    struct sockaddr_un local_addr;
    queue conn_q;
    struct unixsock *peer;
    u8 shutdown;
    boolean passcred;
    struct unix_cred peercred;
    notify_entry notify_handle;
    closure_struct(file_io, read);
    closure_struct(file_io, write);
    closure_struct(file_iov, readv);
    closure_struct(file_iov, writev);
    closure_struct(fdesc_events, events);
    closure_struct(fdesc_ioctl, ioctl);
    closure_struct(fdesc_close, close);
    closure_struct(event_handler, event_handler);
    closure_struct(thunk, free);
    struct refcount refcount;
} *unixsock;

#define unixsock_lock(s)    spin_lock(&(s)->sock.f.lock)
#define unixsock_unlock(s)  spin_unlock(&(s)->sock.f.lock)

int process_visible_pid(process target, process viewer)
{
    (void)viewer;
    if (!target || target->pid <= 0)
        return 0;
    return target->pid;
}

static void scm_release(unixsock_scm scm)
{
    if (!scm)
        return;
    for (u16 i = 0; i < scm->nfds; i++)
        fdesc_put(scm->fds[i]);
    if (scm->has_cred && scm->cred.p)
        process_release(scm->cred.p);
    heap h = heap_locked(get_kernel_heaps());
    deallocate(h, scm, sizeof(*scm) + scm->nfds * sizeof(fdesc));
}

static inline void unixsock_msg_dealloc(unixsock_msg shb)
{
    heap h = shb->b->h;
    if (shb->scm) {
        scm_release(shb->scm);
        shb->scm = 0;
    }
    deallocate_buffer(shb->b);
    deallocate(h, shb, sizeof(*shb));
}

static boolean unixsock_type_is_supported(int type)
{
    switch (type & SOCK_TYPE_MASK) {
    case SOCK_STREAM:
    case SOCK_DGRAM:
    case SOCK_SEQPACKET:
        return true;
    default:
        return false;
    }
}

static boolean unixsock_is_conn_oriented(unixsock s)
{
    return (s->sock.type != SOCK_DGRAM);
}

closure_func_basic(event_handler, u64, unixsock_event_handler,
                   u64 events, void *arg)
{
    unixsock s = struct_from_closure(unixsock, event_handler);
    if (events == NOTIFY_EVENTS_RELEASE)    /* the peer socket is being closed */
        s->notify_handle = INVALID_ADDRESS;
    fdesc_notify_events(&s->sock.f);
    return 0;
}

closure_func_basic(thunk, void, unixsock_free)
{
    unixsock s = struct_from_closure(unixsock, free);
    if (s->peercred.p)
        process_release(s->peercred.p);
    socket_deinit(&s->sock);
    deallocate(s->sock.h, s, sizeof(*s));
}

static void unixsock_peercred_set(unixsock s, process p, u32 uid, u32 gid)
{
    if (s->peercred.p)
        process_release(s->peercred.p);
    s->peercred.p = p;
    if (p)
        process_reserve(p);
    s->peercred.uid = uid;
    s->peercred.gid = gid;
}

static void unixsock_peercred_set_current(unixsock s, process p)
{
    struct creds c;
    creds_snapshot(p, &c);
    unixsock_peercred_set(s, p, c.euid, c.egid);
}

static unixsock_msg unixsock_msg_alloc(heap h, u64 len)
{
    unixsock_msg shb = allocate_zero(h, sizeof(*shb));
    if (shb == INVALID_ADDRESS)
        return shb;
    shb->b = allocate_buffer(h, len);
    if (shb->b == INVALID_ADDRESS) {
        deallocate(h, shb, sizeof(*shb));
        return INVALID_ADDRESS;
    }
    return shb;
}

static inline boolean unixsock_is_connected(unixsock s)
{
    return (s->peer && s->peer->data);
}

static void unixsock_conn_internal(unixsock s, unixsock peer)
{
    refcount_reserve(&peer->refcount);
    s->peer = peer;
}

static void unixsock_disconnect(unixsock s)
{
    if (s->peer) {
        refcount_release(&s->peer->refcount);
        s->peer = 0;
    }
}

static unixsock unixsock_alloc(heap h, int type, u32 flags, boolean alloc_fd);

/* Called with lock acquired, returns with lock released. */
static void unixsock_dealloc(unixsock s)
{
    heap locked = heap_locked(get_kernel_heaps());
    vector drained = allocate_vector(locked, 8);
    if (drained != INVALID_ADDRESS && s->data) {
        unixsock_msg shb;
        while ((shb = dequeue(s->data)) != INVALID_ADDRESS)
            vector_push(drained, shb);
        deallocate_queue(s->data);
        s->data = 0;
    } else {
        deallocate_queue(s->data);
        s->data = 0;
    }
    unixsock_unlock(s);
    if (drained != INVALID_ADDRESS) {
        unixsock_msg shb;
        vector_foreach(drained, shb)
            unixsock_msg_dealloc(shb);
        deallocate_vector(drained);
    }
    unixsock peer = unixsock_is_conn_oriented(s) ? s->peer : 0;
    if (peer) {
        blockq_flush(peer->sock.rxbq);
        fdesc_notify_events(&peer->sock.f);
    }
    blockq_flush(s->sock.txbq); /* unblock any sockets connecting or writing to this socket */
    if (s->notify_handle != INVALID_ADDRESS)
        notify_remove(s->peer->sock.f.ns, s->notify_handle, false);
    unixsock_disconnect(s);
    notify_release(s->sock.f.ns);
    refcount_release(&s->refcount);
}

static inline void unixsock_notify_reader(unixsock s)
{
    blockq_wake_one(s->sock.rxbq);
    fdesc_notify_events(&s->sock.f);
}

/* The argument refers to the destination socket, not to the sending socket. */
static inline void unixsock_notify_writer(unixsock s)
{
    blockq_wake_one(s->sock.txbq);
    fdesc_notify_events(&s->sock.f);
}

static sysreturn scm_parse(const struct msghdr *m, unixsock sender, unixsock dest, unixsock_scm *out)
{
    *out = 0;
    process sender_p;
    if (!sender)
        return -EBADF;
    thread cur = get_current_thread();
    if (!cur)
        return -ESRCH;
    sender_p = cur->p;
    u64 controllen = 0;
    void *control = 0;
    if (m) {
        control = m->msg_control;
        controllen = m->msg_controllen;
        if (controllen > 2147483647ull)
            return -ENOBUFS;
    }
    fdesc tmp_fds[SCM_MAX_FD];
    u16 tmp_nfds = 0;
    boolean has_explicit = false;
    unix_ucred explicit = { 0, 0, 0 };
    process explicit_p = 0;
    sysreturn parse_err = 0;
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx)) {
        for (u16 i = 0; i < tmp_nfds; i++)
            fdesc_put(tmp_fds[i]);
        if (explicit_p)
            process_release(explicit_p);
        return -EFAULT;
    }
    if (control && controllen) {
        u64 off = 0;
        while (off < controllen && !parse_err) {
            if (off + sizeof(unix_cmsghdr) > controllen)
                break;
            u8 *cp = (u8 *)control + off;
            u32 cmsg_len = *(u32 *)cp;
            s32 level = *(s32 *)(cp + 8);
            s32 type = *(s32 *)(cp + 12);
            if (cmsg_len < sizeof(unix_cmsghdr) || cmsg_len > controllen - off) {
                parse_err = -EINVAL;
                break;
            }
            if (level != SOL_SOCKET) {
            } else if (type == SCM_RIGHTS) {
                u64 data_len = cmsg_len - sizeof(unix_cmsghdr);
                if (data_len % sizeof(int)) {
                    parse_err = -EINVAL;
                    break;
                }
                u64 count = data_len / sizeof(int);
                if (tmp_nfds + count > SCM_MAX_FD) {
                    parse_err = -EINVAL;
                    break;
                }
                for (u64 i = 0; i < count; i++) {
                    int fd = *(int *)(cp + sizeof(unix_cmsghdr) + i * sizeof(int));
                    fdesc f = fdesc_get(sender_p, fd);
                    if (!f) {
                        parse_err = -EBADF;
                        break;
                    }
                    tmp_fds[tmp_nfds++] = f;
                }
            } else if (type == SCM_CREDENTIALS) {
                if (cmsg_len < sizeof(unix_cmsghdr) + sizeof(unix_ucred)) {
                    parse_err = -EINVAL;
                    break;
                }
                u8 *data = cp + sizeof(unix_cmsghdr);
                unix_ucred uc;
                uc.pid = *(s32 *)data;
                uc.uid = *(u32 *)(data + 4);
                uc.gid = *(u32 *)(data + 8);
                struct creds scon;
                creds_snapshot(sender_p, &scon);
                boolean is_admin = capable(sender_p, CAP_SYS_ADMIN);
                if (uc.pid != sender_p->pid && !is_admin) {
                    parse_err = -EPERM;
                    break;
                }
                user_namespace sender_ns = process_user_ns(sender_p);
                boolean uid_ok = (uc.uid == user_ns_from_kuid(sender_ns, scon.uid) ||
                                  uc.uid == user_ns_from_kuid(sender_ns, scon.euid) ||
                                  uc.uid == user_ns_from_kuid(sender_ns, scon.suid));
                boolean gid_ok = (uc.gid == user_ns_from_kgid(sender_ns, scon.gid) ||
                                  uc.gid == user_ns_from_kgid(sender_ns, scon.egid) ||
                                  uc.gid == user_ns_from_kgid(sender_ns, scon.sgid));
                user_ns_release(sender_ns);
                boolean uid_priv = is_admin || capable(sender_p, CAP_SETUID);
                if (!uid_ok && !uid_priv) {
                    parse_err = -EPERM;
                    break;
                }
                boolean gid_priv = is_admin || capable(sender_p, CAP_SETGID);
                if (!gid_ok && !gid_priv) {
                    parse_err = -EPERM;
                    break;
                }
                if (has_explicit && explicit_p)
                    process_release(explicit_p);
                {
                    user_namespace ns2 = process_user_ns(sender_p);
                    u32 kid_uid, kid_gid;
                    if (!user_ns_to_kuid(ns2, uc.uid, &kid_uid))
                        kid_uid = USER_NS_OVERFLOW_ID;
                    if (!user_ns_to_kgid(ns2, uc.gid, &kid_gid))
                        kid_gid = USER_NS_OVERFLOW_ID;
                    user_ns_release(ns2);
                    uc.uid = kid_uid;
                    uc.gid = kid_gid;
                }
                explicit = uc;
                has_explicit = true;
                if (uc.pid == sender_p->pid) {
                    explicit_p = sender_p;
                    process_reserve(explicit_p);
                } else {
                    process p2 = process_get(uc.pid);
                    explicit_p = p2;
                }
            } else {
                parse_err = -EINVAL;
                break;
            }
            u64 adv = (cmsg_len + 7ull) & ~7ull;
            if (!adv) {
                parse_err = -EINVAL;
                break;
            }
            off += adv;
        }
    }
    context_clear_err(ctx);
    if (parse_err) {
        for (u16 i = 0; i < tmp_nfds; i++)
            fdesc_put(tmp_fds[i]);
        if (explicit_p)
            process_release(explicit_p);
        return parse_err;
    }
    if (!has_explicit) {
        boolean dest_pass = false;
        if (dest) {
            unixsock_lock(dest);
            dest_pass = dest->passcred;
            unixsock_unlock(dest);
        }
        if (dest_pass) {
            struct creds scon;
            creds_snapshot(sender_p, &scon);
            explicit.pid = sender_p->pid;
            explicit.uid = scon.uid;
            explicit.gid = scon.gid;
            has_explicit = true;
            explicit_p = sender_p;
            process_reserve(explicit_p);
        }
    }
    if (!has_explicit && tmp_nfds == 0)
        return 0;
    heap h = heap_locked(get_kernel_heaps());
    u64 size = sizeof(struct unixsock_scm) + tmp_nfds * sizeof(fdesc);
    unixsock_scm scm = allocate(h, size);
    if (!scm) {
        for (u16 i = 0; i < tmp_nfds; i++)
            fdesc_put(tmp_fds[i]);
        if (explicit_p)
            process_release(explicit_p);
        return -ENOMEM;
    }
    scm->has_cred = has_explicit;
    scm->cred.p = explicit_p;
    scm->cred.uid = explicit.uid;
    scm->cred.gid = explicit.gid;
    scm->nfds = tmp_nfds;
    for (u16 i = 0; i < tmp_nfds; i++)
        scm->fds[i] = tmp_fds[i];
    *out = scm;
    return 0;
}

static sysreturn scm_deliver(unixsock_scm scm, struct msghdr *m, int recv_flags, process receiver,
                             int *installed_fds, u16 *installed_count, vector dropped, boolean *ctrunc)
{
    *ctrunc = false;
    if (!scm)
        return 0;
    if (!m) {
        for (u16 i = 0; i < scm->nfds; i++)
            vector_push(dropped, scm->fds[i]);
        if (scm->has_cred && scm->cred.p)
            process_release(scm->cred.p);
        heap h = heap_locked(get_kernel_heaps());
        deallocate(h, scm, sizeof(*scm) + scm->nfds * sizeof(fdesc));
        return 0;
    }
    context ctx = get_current_context(current_cpu());
    int local_installed[SCM_MAX_FD];
    u16 local_count = 0;
    u64 off = 0;
    boolean truncated = false;
    u64 controllen = 0;
    void *control = 0;
    sysreturn err = 0;
    if (context_set_err(ctx)) {
        for (u16 i = 0; i < local_count; i++)
            deallocate_fd(receiver, local_installed[i]);
        for (u16 i = 0; i < scm->nfds; i++)
            vector_push(dropped, scm->fds[i]);
        if (scm->has_cred && scm->cred.p)
            process_release(scm->cred.p);
        heap h = heap_locked(get_kernel_heaps());
        deallocate(h, scm, sizeof(*scm) + scm->nfds * sizeof(fdesc));
        if (installed_count)
            *installed_count = 0;
        *ctrunc = false;
        return -EFAULT;
    }
    controllen = m->msg_controllen;
    control = m->msg_control;
    if (!control)
        controllen = 0;
    if (scm->has_cred) {
        u64 need = SCM_CMSG_SPACE(sizeof(unix_ucred));
        if (controllen - off < need) {
            truncated = true;
        } else {
            u8 *cp = (u8 *)control + off;
            s32 pid = process_visible_pid(scm->cred.p, receiver);
            user_namespace receiver_ns = process_user_ns(receiver);
            u32 local_uid = user_ns_from_kuid(receiver_ns, scm->cred.uid);
            u32 local_gid = user_ns_from_kgid(receiver_ns, scm->cred.gid);
            user_ns_release(receiver_ns);
            *(u32 *)cp = (u32)SCM_CMSG_LEN(sizeof(unix_ucred));
            *(u32 *)(cp + 4) = 0;
            *(s32 *)(cp + 8) = SOL_SOCKET;
            *(s32 *)(cp + 12) = SCM_CREDENTIALS;
            *(s32 *)(cp + 16) = pid;
            *(u32 *)(cp + 20) = local_uid;
            *(u32 *)(cp + 24) = local_gid;
            for (u64 i = 28; i < need; i++)
                cp[i] = 0;
            off += need;
        }
    }
    if (scm->nfds) {
        if (controllen - off < sizeof(unix_cmsghdr)) {
            truncated = true;
        } else {
            u64 remaining = controllen - off;
            u64 slot = remaining - sizeof(unix_cmsghdr);
            u64 max_by_space = (slot / 8) * 2;
            u64 k = MIN((u64)scm->nfds, max_by_space);
            if (max_by_space == 0 && scm->nfds > 0)
                truncated = true;
            for (u16 i = 0; i < k; i++) {
                u64 newfd = allocate_fd(receiver, scm->fds[i], (recv_flags & MSG_CMSG_CLOEXEC) ? FD_CLOEXEC : 0);
                if (newfd == INVALID_PHYSICAL) {
                    truncated = true;
                    break;
                }
                local_installed[local_count++] = (int)newfd;
            }
            if (local_count < scm->nfds)
                truncated = true;
            if (local_count) {
                u8 *cp = (u8 *)control + off;
                *(u32 *)cp = (u32)(sizeof(unix_cmsghdr) + local_count * sizeof(int));
                *(u32 *)(cp + 4) = 0;
                *(s32 *)(cp + 8) = SOL_SOCKET;
                *(s32 *)(cp + 12) = SCM_RIGHTS;
                for (u16 i = 0; i < local_count; i++)
                    *(int *)(cp + sizeof(unix_cmsghdr) + i * sizeof(int)) = local_installed[i];
                u64 need = SCM_CMSG_SPACE(local_count * sizeof(int));
                for (u64 i = sizeof(unix_cmsghdr) + local_count * sizeof(int); i < need; i++)
                    cp[i] = 0;
                off += need;
            }
        }
    }
    m->msg_controllen = off;
    err = 0;
    context_clear_err(ctx);
    for (u16 i = local_count; i < scm->nfds; i++)
        vector_push(dropped, scm->fds[i]);
    if (scm->has_cred && scm->cred.p)
        process_release(scm->cred.p);
    for (u16 i = 0; i < local_count; i++) {
        if (installed_fds)
            installed_fds[i] = local_installed[i];
    }
    if (installed_count)
        *installed_count = local_count;
    *ctrunc = truncated;
    heap h = heap_locked(get_kernel_heaps());
    deallocate(h, scm, sizeof(*scm) + scm->nfds * sizeof(fdesc));
    return err;
}

static fdesc fdesc_peek_noref(process p, int fd)
{
    if (fd < 0)
        return 0;
    fdtable fdt = p ? p->fdtable : 0;
    if (!fdt)
        return 0;
    spin_lock(&fdt->lock);
    fdesc f = vector_get(fdt->files, fd);
    spin_unlock(&fdt->lock);
    return f;
}

static void scm_drop_to_vector(unixsock_scm scm, vector dropped)
{
    if (!scm)
        return;
    if (dropped) {
        for (u16 i = 0; i < scm->nfds; i++)
            vector_push(dropped, scm->fds[i]);
    } else {
        for (u16 i = 0; i < scm->nfds; i++)
            fdesc_put(scm->fds[i]);
    }
    if (scm->has_cred && scm->cred.p)
        process_release(scm->cred.p);
    heap h = heap_locked(get_kernel_heaps());
    deallocate(h, scm, sizeof(*scm) + scm->nfds * sizeof(fdesc));
}

static void unixsock_addr_copy(struct sockaddr_un *dest, struct sockaddr_un *src, socklen_t *len)
{
    sstring addr = sstring_from_cstring(src->sun_path, sizeof(src->sun_path));
    socklen_t actual_len = __builtin_offsetof(struct sockaddr_un, sun_path) + addr.len;
    if ((addr.len > 0) && (actual_len < sizeof(struct sockaddr_un)))
        actual_len++;   /* include the string terminator for the path name */
    runtime_memcpy(dest, src, MIN(*len, actual_len));
    *len = actual_len;
}

closure_function(9, 1, sysreturn, unixsock_read_bh,
                 unixsock, s, void *, dest, struct iovec *, iov, u64, length, io_completion, completion, struct sockaddr_un *, from_addr, socklen_t *, from_length,
                 int, msgflags, struct msghdr *, msg,
                 u64 flags)
{
    unixsock s = bound(s);
    void *dest = bound(dest);
    struct iovec *iov = bound(iov);
    u64 length = bound(length);

    unixsock_msg shb;
    sysreturn rv;
    vector dropped = 0;
    int installed_fds[SCM_MAX_FD];
    u16 installed_count = 0;
    boolean ctrunc = false;
    boolean first_set = false;
    boolean first_has_cred = false;
    struct unix_cred first_cred = { 0, 0, 0 };
    boolean seen_rights = false;
    boolean truncated = false;
    boolean read_done = false;
    context ctx = context_from_closure(closure_self());
    process receiver = is_syscall_context(ctx) ? ((syscall_context)ctx)->t->p : ((process_context)ctx)->p;

    unixsock_lock(s);
    boolean disconnected = unixsock_is_conn_oriented(s) && !(s->peer && s->peer->data);
    boolean end_of_data = disconnected || (s->shutdown & UNIXSOCK_RCV_SHUTDOWN);
    if ((flags & BLOCKQ_ACTION_NULLIFY) && !end_of_data) {
        rv = -ERESTARTSYS;
        goto out;
    }
    shb = queue_peek(s->data);
    if (shb == INVALID_ADDRESS) {
        if (end_of_data) {
            rv = 0;
            goto out;
        } else if ((s->sock.f.flags & SOCK_NONBLOCK) || (bound(msgflags) & MSG_DONTWAIT)) {
            rv = -EAGAIN;
            goto out;
        }
        unixsock_unlock(s);
        return blockq_block_required((unix_context)ctx, flags);
    }
    dropped = allocate_vector(heap_locked(get_kernel_heaps()), 8);
    if (dropped == INVALID_ADDRESS)
        dropped = 0;
    rv = 0;
    if (context_set_err(ctx)) {
        if (rv == 0)
            rv = -EFAULT;
        else
            read_done = true;
        if (rv == -EFAULT) {
            for (u16 i = 0; i < installed_count; i++) {
                fdesc f = fdesc_peek_noref(receiver, installed_fds[i]);
                deallocate_fd(receiver, installed_fds[i]);
                if (f)
                    vector_push(dropped, f);
            }
            installed_count = 0;
            if (shb != INVALID_ADDRESS && queue_peek(s->data) == shb) {
                unixsock_msg tofree = dequeue(s->data);
                u64 rlen = buffer_length(tofree->b);
                s->sock.rx_len -= MIN(s->sock.rx_len, rlen);
                if (tofree->scm) {
                    unixsock_scm scm = tofree->scm;
                    tofree->scm = 0;
                    scm_drop_to_vector(scm, dropped);
                }
                unixsock_msg_dealloc(tofree);
                shb = INVALID_ADDRESS;
            }
        }
        goto out;
    }
    void *iov_base;
    u64 iov_len;
    boolean iov_validated;
    if (!dest) {
        iov_base = iov->iov_base;
        iov_len = iov->iov_len;
        iov_validated = false;
    }
    u64 buf_offset = 0;
    do {
        if (first_set) {
            if (seen_rights)
                break;
            if (s->passcred) {
                boolean cur_has = (shb->scm && shb->scm->has_cred);
                boolean differs = (cur_has != first_has_cred);
                if (!differs && cur_has && first_has_cred) {
                    if (shb->scm->cred.p != first_cred.p || shb->scm->cred.uid != first_cred.uid ||
                        shb->scm->cred.gid != first_cred.gid)
                        differs = true;
                }
                if (differs)
                    break;
            }
        }
        buffer b = shb->b;
        u64 msg_len = buffer_length(b);
        u64 xfer;
        if (dest) {
            xfer = MIN(buffer_length(b), length);
            buffer_read(b, dest + buf_offset, xfer);
            buf_offset += xfer;
            length -= xfer;
        } else {
            xfer = 0;
            do {
                u64 partial_xfer;
                do {
                    partial_xfer = MIN(buffer_length(b), iov_len - buf_offset);
                    if (partial_xfer == 0) {
                        iov++;
                        length--;
                        if (length) {
                            iov_base = iov->iov_base;
                            iov_len = iov->iov_len;
                            iov_validated = false;
                        }
                        buf_offset = 0;
                    }
                } while ((partial_xfer == 0) && length);
                if (!length)
                    break;
                if (!iov_validated && !memory_is_user(iov_base, iov_len))
                    page_fault();
                iov_validated = true;
                buffer_read(b, iov_base + buf_offset, partial_xfer);
                buf_offset += partial_xfer;
                xfer += partial_xfer;
            } while (buffer_length(b));
        }
        rv += xfer;
        s->sock.rx_len -= xfer;
        if ((s->sock.type != SOCK_STREAM) && buffer_length(b)) {
            truncated = true;
            if (bound(msgflags) & MSG_TRUNC)
                rv = msg_len;
        }
        {
            unixsock_scm scm = shb->scm;
            shb->scm = 0;
            boolean had_rights = (scm && scm->nfds);
            if (!first_set) {
                first_set = true;
                first_has_cred = (scm && scm->has_cred);
                if (first_has_cred)
                    first_cred = scm->cred;
            }
            if (scm) {
                boolean this_ctrunc = false;
                u16 per_call = 0;
                sysreturn d = scm_deliver(scm, bound(msg), bound(msgflags), receiver,
                                          installed_fds + installed_count, &per_call, dropped, &this_ctrunc);
                if (this_ctrunc)
                    ctrunc = true;
                if (d == -EFAULT) {
                    if (queue_peek(s->data) == shb) {
                        assert(dequeue(s->data) == shb);
                        s->sock.rx_len -= buffer_length(b);
                        unixsock_msg_dealloc(shb);
                        shb = INVALID_ADDRESS;
                    }
                    rv = -EFAULT;
                    break;
                }
                installed_count += per_call;
                if (context_set_err(ctx)) {
                    if (rv == 0)
                        rv = -EFAULT;
                    else
                        read_done = true;
                    if (rv == -EFAULT) {
                        for (u16 i = 0; i < installed_count; i++) {
                            fdesc f = fdesc_peek_noref(receiver, installed_fds[i]);
                            deallocate_fd(receiver, installed_fds[i]);
                            if (f)
                                vector_push(dropped, f);
                        }
                        installed_count = 0;
                        if (shb != INVALID_ADDRESS && queue_peek(s->data) == shb) {
                            unixsock_msg tofree = dequeue(s->data);
                            u64 rlen = buffer_length(tofree->b);
                            s->sock.rx_len -= MIN(s->sock.rx_len, rlen);
                            if (tofree->scm) {
                                unixsock_scm scm2 = tofree->scm;
                                tofree->scm = 0;
                                scm_drop_to_vector(scm2, dropped);
                            }
                            unixsock_msg_dealloc(tofree);
                            shb = INVALID_ADDRESS;
                        }
                    }
                    goto out;
                }
            }
            if (had_rights)
                seen_rights = true;
        }
        if (!buffer_length(b) || (s->sock.type != SOCK_STREAM)) {
            if (s->sock.type == SOCK_DGRAM) {
                struct sockaddr_un *from_addr = bound(from_addr);
                socklen_t *from_length = bound(from_length);
                if (from_addr && from_length) {
                    unixsock_addr_copy(from_addr, &shb->from_addr, from_length);
                }
            }
            assert(dequeue(s->data) == shb);
            s->sock.rx_len -= buffer_length(b);
            unixsock_msg_dealloc(shb);
            shb = queue_peek(s->data);
            if (shb == INVALID_ADDRESS) { /* no more data available to read */
                break;
            }
        }
    } while ((s->sock.type == SOCK_STREAM) && (length > 0));
    if (bound(msg))
        bound(msg)->msg_flags = (truncated ? MSG_TRUNC : 0) | (ctrunc ? MSG_CTRUNC : 0);
    context_clear_err(ctx);
    read_done = true;
out:
    unixsock_unlock(s);
    if (dropped) {
        fdesc f;
        vector_foreach(dropped, f)
            fdesc_put(f);
        deallocate_vector(dropped);
    }
    if (read_done)
        unixsock_notify_writer(s);
    apply(bound(completion), rv);
    closure_finish();
    return rv;
}

static sysreturn unixsock_read_with_addr(unixsock s, void *dest, u64 length, u64 offset_arg,
                                         context ctx, boolean bh, io_completion completion,
                                         void *addr, socklen_t *addrlen, int msgflags)
{
    if ((s->sock.type == SOCK_STREAM) && (length == 0))
        return io_complete(completion, 0);

    blockq_action ba = closure_from_context(ctx, unixsock_read_bh, s, dest, 0, length,
                                            completion, addr, addrlen, msgflags, 0);
    return blockq_check(s->sock.rxbq, ba, bh);
}

closure_func_basic(file_io, sysreturn, unixsock_read,
                 void *dest, u64 length, u64 offset_arg, context ctx, boolean bh, io_completion completion)
{
    unixsock s = struct_from_field(closure_self(), unixsock, read);
    return unixsock_read_with_addr(s, dest, length, offset_arg, ctx, bh, completion, 0, 0, 0);
}

static sysreturn unixsock_write_check(unixsock s, u64 len)
{
    if ((s->sock.type == SOCK_STREAM) && (len == 0))
        return 0;
    if ((s->sock.type != SOCK_STREAM) && (len > (u64)so_rcvbuf))
        return -EMSGSIZE;
    return 1;   /* any value > 0 will do */
}

static sysreturn unixsock_validate_send_flags(unixsock s, int flags)
{
    int allowed = MSG_NOSIGNAL | MSG_DONTWAIT;
    if (s->sock.type == SOCK_SEQPACKET)
        allowed |= MSG_EOR;
    if (flags & ~allowed)
        return -EOPNOTSUPP;
    return 0;
}

static sysreturn unixsock_write_to(void *src, struct iovec *iov, u64 length,
                                   unixsock dest, unixsock from, unixsock_scm *scm)
{
    if ((dest->sock.rx_len >= so_rcvbuf) || queue_full(dest->data)) {
        return -EAGAIN;
    }

    context ctx = get_current_context(current_cpu());
    u64 buf_offset = 0;
    sysreturn rv = 0;
    unixsock_msg shb = INVALID_ADDRESS;
    if (context_set_err(ctx)) {
        if (shb != INVALID_ADDRESS)
            unixsock_msg_dealloc(shb);
        return (rv == 0) ? -EFAULT : rv;
    }
    void *iov_base;
    u64 iov_len;
    boolean iov_validated;
    if (!src) {
        iov_base = iov->iov_base;
        iov_len = iov->iov_len;
        iov_validated = false;
    }
    do {
        u64 xfer = src ? length : iov_total_len(iov, length);
        sysreturn check_rv = unixsock_write_check(from, xfer);
        if (check_rv <= 0) {
            if (rv == 0)
                rv = check_rv;
            break;
        }
        if (from->sock.type == SOCK_STREAM) {
            xfer = MIN(UNIXSOCK_BUF_MAX_SIZE, xfer);
            xfer = MIN(xfer, so_rcvbuf - dest->sock.rx_len);
        } else {
            xfer = MIN((u64)so_rcvbuf, xfer);
        }
        shb = unixsock_msg_alloc(dest->sock.h, xfer);
        if (shb != INVALID_ADDRESS && scm && *scm) {
            shb->scm = *scm;
            *scm = 0;
        }
        if (shb == INVALID_ADDRESS) {
            if (rv == 0) {
                rv = -ENOMEM;
            }
            break;
        }
        if (from && from->sock.type == SOCK_DGRAM)
            runtime_memcpy(&shb->from_addr, &from->local_addr, sizeof(struct sockaddr_un));
        if (src) {
            assert(buffer_write(shb->b, src + buf_offset, xfer));
            buf_offset += xfer;
            length -= xfer;
        } else {
            u64 xfer_limit = xfer;
            do {
                u64 partial_xfer;
                do {
                    partial_xfer = MIN(xfer_limit, iov_len - buf_offset);
                    if (partial_xfer == 0) {
                        length--;
                        if (length == 0)
                            break;
                        iov++;
                        iov_base = iov->iov_base;
                        iov_len = iov->iov_len;
                        iov_validated = false;
                        buf_offset = 0;
                    }
                } while (partial_xfer == 0);
                if (partial_xfer == 0)
                    break;
                if (!iov_validated && !memory_is_user(iov_base, iov_len))
                    page_fault();
                iov_validated = true;
                buffer_write(shb->b, iov_base + buf_offset, partial_xfer);
                buf_offset += partial_xfer;
                xfer_limit -= partial_xfer;
            } while (xfer_limit);
            if (buf_offset == iov_len) {
                length--;
                if (length > 0) {
                    iov++;
                    iov_base = iov->iov_base;
                    iov_len = iov->iov_len;
                    iov_validated = false;
                    buf_offset = 0;
                }
            }
        }
        assert(enqueue(dest->data, shb));
        dest->sock.rx_len += xfer;
        rv += xfer;
        shb = INVALID_ADDRESS;
    } while ((length > 0) && (dest->sock.rx_len < so_rcvbuf) && !queue_full(dest->data));
    context_clear_err(ctx);
    return rv;
}

static sysreturn unixsock_get_path(sstring *path, struct sockaddr *addr, socklen_t addrlen)
{
    if (addrlen <= __builtin_offsetof(struct sockaddr_un, sun_path))
        return -EINVAL;
    if (!fault_in_user_memory(addr, addrlen, false))
        return -EFAULT;
    struct sockaddr_un *unix_addr = (struct sockaddr_un *)addr;
    if (unix_addr->sun_family != AF_UNIX)
        return -EINVAL;
    *path = sstring_from_cstring(unix_addr->sun_path,
                                 addrlen - __builtin_offsetof(struct sockaddr_un, sun_path));
    return 0;
}

static sysreturn lookup_socket(unixsock *s, struct sockaddr *addr, socklen_t addrlen)
{
    sstring path;
    sysreturn rv = unixsock_get_path(&path, addr, addrlen);
    if (rv)
        return rv;
    process p = current->p;
    filesystem fs = p->cwd_fs;
    tuple n;
    int fss = filesystem_get_socket(&fs, p->cwd, path, &n, (void **)s);
    if (fss == -EINVAL)
        return -ECONNREFUSED;
    if (fss == 0) {
        refcount_reserve(&(*s)->refcount);
        filesystem_put_node(fs, n);
    }
    return fss;
}

closure_function(8, 1, sysreturn, unixsock_write_bh,
                 unixsock, s, void *, src, struct iovec *, iov, u64, length, io_completion, completion, unixsock, dest,
                 int, msgflags, unixsock_scm, scm,
                 u64 flags)
{
    unixsock s = bound(s);
    void *src = bound(src);
    u64 length = bound(length);
    unixsock dest;
    boolean full = false;
    unixsock_scm scm = bound(scm);

    sysreturn rv;

    unixsock_lock(s);
    boolean send_shut = (s->shutdown & UNIXSOCK_SEND_SHUTDOWN) != 0;
    unixsock_unlock(s);
    dest = bound(dest);
    unixsock_lock(dest);
    if (send_shut || (dest->data && (dest->shutdown & UNIXSOCK_RCV_SHUTDOWN))) {
        rv = -EPIPE;
        goto out;
    }
    if ((flags & BLOCKQ_ACTION_NULLIFY) && dest->data) {
        rv = -ERESTARTSYS;
        goto out;
    }
    if (!dest->data) {
        rv = unixsock_is_conn_oriented(s) ? -EPIPE : -ECONNREFUSED;
        goto out;
    }

    rv = unixsock_write_to(src, bound(iov), length, dest, s, &scm);
    if ((rv == -EAGAIN) && !(s->sock.f.flags & SOCK_NONBLOCK) && !(bound(msgflags) & MSG_DONTWAIT)) {
        unixsock_unlock(dest);
        return blockq_block_required((unix_context)context_from_closure(closure_self()), flags);
    }
    full = (dest->sock.rx_len >= so_rcvbuf) || queue_full(dest->data);
out:
    unixsock_unlock(dest);
    if (scm)
        scm_release(scm);
    if ((rv > 0) || ((rv == 0) && (dest->sock.type != SOCK_STREAM)))
        unixsock_notify_reader(dest);
    if (full)   /* no more space available to write */
        fdesc_notify_events(&s->sock.f);
    if ((rv == -EPIPE) && (s->sock.type == SOCK_STREAM) && !(bound(msgflags) & MSG_NOSIGNAL))
        raise_sigpipe(context_from_closure(closure_self()));
    apply(bound(completion), rv);
    refcount_release(&dest->refcount);
    closure_finish();
    return rv;
}

static sysreturn unixsock_write_with_addr(unixsock s, void *src, u64 length, u64 offset, context ctx,
                                          boolean bh, io_completion completion, unixsock addr,
                                          int msgflags, const struct msghdr *msghdr)
{
    sysreturn rv = unixsock_validate_send_flags(s, msgflags);
    if (rv) {
        refcount_release(&addr->refcount);
        return io_complete(completion, rv);
    }
    unixsock_scm scm = 0;
    rv = scm_parse(msghdr, s, addr, &scm);
    if (rv) {
        refcount_release(&addr->refcount);
        return io_complete(completion, rv);
    }
    blockq_action ba = closure_from_context(ctx, unixsock_write_bh, s, src, 0, length,
                                            completion, addr, msgflags, scm);
    if (ba == INVALID_ADDRESS) {
        scm_release(scm);
        refcount_release(&addr->refcount);
        return io_complete(completion, -ENOMEM);
    }
    return blockq_check(addr->sock.txbq, ba, bh);
}

closure_func_basic(file_io, sysreturn, unixsock_write,
                   void *src, u64 length, u64 offset, context ctx, boolean bh, io_completion completion)
{
    unixsock s = struct_from_field(closure_self(), unixsock, write);
    unixsock_lock(s);
    unixsock dest = s->peer;
    if (dest)
        refcount_reserve(&dest->refcount);
    unixsock_unlock(s);
    if (!dest)
        return io_complete(completion, -ENOTCONN);
    return unixsock_write_with_addr(s, src, length, offset, ctx, bh, completion, dest, 0, 0);
}

closure_func_basic(file_iov, sysreturn, unixsock_readv,
                   struct iovec *iov, int count, u64 offset, context ctx, boolean bh, io_completion completion)
{
    unixsock s = struct_from_field(closure_self(), unixsock, readv);
    blockq_action ba = closure_from_context(ctx, unixsock_read_bh, s, 0, iov, count,
                                            completion, 0, 0, 0, 0);
    if (ba == INVALID_ADDRESS)
        return io_complete(completion, -ENOMEM);
    return blockq_check(s->sock.rxbq, ba, bh);
}

static sysreturn unixsock_writev_flags(unixsock s, struct iovec *iov, int count, context ctx,
                                      boolean bh, io_completion completion, int msgflags, const struct msghdr *msghdr)
{
    sysreturn rv = unixsock_validate_send_flags(s, msgflags);
    if (rv)
        return io_complete(completion, rv);
    unixsock_lock(s);
    unixsock dest = s->peer;
    if (dest)
        refcount_reserve(&dest->refcount);
    unixsock_unlock(s);
    if (!dest)
        return io_complete(completion, -ENOTCONN);
    unixsock_scm scm = 0;
    rv = scm_parse(msghdr, s, dest, &scm);
    if (rv) {
        refcount_release(&dest->refcount);
        return io_complete(completion, rv);
    }
    blockq_action ba = closure_from_context(ctx, unixsock_write_bh, s,
                                            0, iov, count, completion, dest, msgflags, scm);
    if (ba == INVALID_ADDRESS) {
        scm_release(scm);
        refcount_release(&dest->refcount);
        return io_complete(completion, -ENOMEM);
    }
    return blockq_check(dest->sock.txbq, ba, bh);
}

closure_func_basic(file_iov, sysreturn, unixsock_writev,
                   struct iovec *iov, int count, u64 offset, context ctx, boolean bh, io_completion completion)
{
    unixsock s = struct_from_field(closure_self(), unixsock, writev);
    return unixsock_writev_flags(s, iov, count, ctx, bh, completion, 0, 0);
}

static u32 unixsock_shutdown_events(u8 shutdown)
{
    u32 events = 0;
    if (shutdown & UNIXSOCK_RCV_SHUTDOWN)
        events |= EPOLLIN | EPOLLRDHUP;
    if (shutdown == UNIXSOCK_SHUTDOWN_MASK)
        events |= EPOLLHUP;
    return events;
}

closure_func_basic(fdesc_events, u32, unixsock_events,
                   thread t /* ignore */)
{
    unixsock s = struct_from_field(closure_self(), unixsock, events);
    u32 events = 0;
    unixsock_lock(s);
    if (!s->data) {
        unixsock_unlock(s);
        return 0;
    }
    if (s->conn_q) {    /* listening state */
        if (!queue_empty(s->conn_q)) {
            events |= EPOLLIN;
        }
    } else {
        if (!queue_empty(s->data)) {
            events |= EPOLLIN;
        }
        u8 shutdown = s->shutdown;
        unixsock peer = s->peer;
        if (peer) {
            refcount_reserve(&peer->refcount);
            unixsock_unlock(s);
            unixsock_lock(peer);
            if (!peer->data) {
                events |= EPOLLOUT;
                if (unixsock_is_conn_oriented(s))
                    shutdown = UNIXSOCK_SHUTDOWN_MASK;
            } else if ((peer->sock.rx_len < so_rcvbuf) && !queue_full(peer->data)) {
                events |= EPOLLOUT;
            }
            unixsock_unlock(peer);
            refcount_release(&peer->refcount);
            return events | unixsock_shutdown_events(shutdown);
        } else {
            events |= EPOLLOUT | unixsock_shutdown_events(shutdown);
            if (unixsock_is_conn_oriented(s))
                events |= EPOLLHUP;
        }
    }
    unixsock_unlock(s);
    return events;
}

closure_func_basic(fdesc_ioctl, sysreturn, unixsock_ioctl,
                   unsigned long request, vlist ap)
{
    unixsock s = struct_from_field(closure_self(), unixsock, ioctl);
    return socket_ioctl(&s->sock, request, ap);
}

closure_func_basic(fdesc_close, sysreturn, unixsock_close,
                   context ctx, io_completion completion)
{
    unixsock s = struct_from_field(closure_self(), unixsock, close);
    unixsock_lock(s);
    if (s->conn_q) {
        /* Deallocate any sockets in the connection queue. */
        unixsock child;
        while ((child = dequeue(s->conn_q)) != INVALID_ADDRESS)
            apply(child->sock.f.close, 0, io_completion_ignore);

        deallocate_queue(s->conn_q);
        s->conn_q = 0;
    }
    if (s->fs_entry) {
        filesystem_clear_socket(s->fs, s->fs_entry);
    }
    unixsock_dealloc(s);
    return io_complete(completion, 0);
}

static sysreturn unixsock_bind(struct sock *sock, struct sockaddr *addr,
        socklen_t addrlen)
{
    unixsock s = (unixsock) sock;
    unixsock_lock(s);
    sysreturn ret;
    if (s->fs_entry) {
        ret = -EADDRINUSE;
        goto out;
    }

    sstring path;
    ret = unixsock_get_path(&path, addr, addrlen);
    if (ret)
        goto out;

    process p = current->p;
    s->fs = p->cwd_fs;
    int fss = filesystem_mk_socket(&s->fs, p->cwd, path, s, &s->fs_entry);
    if (fss != 0) {
        ret = (fss == -EEXIST) ? -EADDRINUSE : fss;
        goto out;
    }
    runtime_memcpy(&s->local_addr, addr, addrlen);
    ret = 0;
out:
    unixsock_unlock(s);
    socket_release(sock);
    return ret;
}

static sysreturn unixsock_listen(struct sock *sock, int backlog)
{
    unixsock s = (unixsock) sock;
    sysreturn ret = 0;
    process cur = get_current_thread() ? get_current_thread()->p : 0;
    unixsock_lock(s);
    if (cur)
        unixsock_peercred_set_current(s, cur);
    switch (sock->type) {
    case SOCK_STREAM:
    case SOCK_SEQPACKET:
        if (!s->conn_q) {
            s->conn_q = allocate_queue(sock->h, backlog);
            if (s->conn_q == INVALID_ADDRESS) {
                msg_err("%s: failed to allocate connection queue", func_ss);
                s->conn_q = 0;
                ret = -ENOMEM;
            }
        }
        break;
    default:
        ret = -EOPNOTSUPP;
    }
    unixsock_unlock(s);
    socket_release(sock);
    return ret;
}

closure_function(3, 1, sysreturn, connect_bh,
                 unixsock, s, thread, t, unixsock, listener,
                 u64 bqflags)
{
    unixsock s = bound(s);
    thread t = bound(t);
    unixsock listener = bound(listener);
    sysreturn rv;

    unixsock_lock(s);
    if (unixsock_is_connected(s)) {
        rv = -EISCONN;
        goto out;
    }
    if ((bqflags & BLOCKQ_ACTION_NULLIFY) && listener->conn_q) {
        rv = -ERESTARTSYS;
        goto out;
    }
    if (!listener->conn_q) {    /* the listening socket has been shut down */
        rv = -ECONNREFUSED;
        goto out;
    }
    if (queue_full(listener->conn_q)) {
        if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        unixsock_unlock(s);
        return blockq_block_required(&t->syscall->uc, bqflags);
    }
    unixsock peer = unixsock_alloc(s->sock.h, s->sock.type, 0, false);
    if (!peer) {
        rv = -ENOMEM;
        goto out;
    }
    {
        struct creds scon;
        creds_snapshot(t->p, &scon);
        unixsock_peercred_set(peer, t->p, scon.euid, scon.egid);
        process lp = listener->peercred.p;
        u32 luid = listener->peercred.uid;
        u32 lgid = listener->peercred.gid;
        unixsock_peercred_set(s, lp, luid, lgid);
    }
    unixsock_conn_internal(s, peer);
    unixsock_conn_internal(peer, s);
    assert(enqueue(listener->conn_q, peer));
    rv = 0;
out:
    unixsock_unlock(s);
    if (rv == 0)
        unixsock_notify_reader(listener);
    socket_release(&s->sock);
    syscall_return(t, rv);
    closure_finish();
    return rv;
}

static sysreturn unixsock_connect(struct sock *sock, struct sockaddr *addr,
        socklen_t addrlen)
{
    unixsock s = (unixsock) sock;
    sysreturn rv;

    unixsock listener = 0;
    rv = lookup_socket(&listener, addr, addrlen);
    if (rv != 0)
        goto out;
    if (listener->sock.type != s->sock.type) {
        rv = -EPROTOTYPE;
        goto out;
    }
    if (unixsock_is_conn_oriented(s)) {
        blockq_action ba = contextual_closure(connect_bh, s, current, listener);
        if (ba == INVALID_ADDRESS)
            rv = -ENOMEM;
        return blockq_check(listener->sock.txbq, ba, false);
    } else {
        if (s->notify_handle != INVALID_ADDRESS)
            notify_remove(s->peer->sock.f.ns, s->notify_handle, false);
        unixsock_lock(s);
        unixsock_disconnect(s);
        s->notify_handle = notify_add(listener->sock.f.ns, EPOLLOUT | EPOLLERR | EPOLLHUP,
                                      init_closure_func(&s->event_handler, event_handler,
                                                        unixsock_event_handler));
        if (s->notify_handle == INVALID_ADDRESS)
            rv = -ENOMEM;
        else {
            unixsock_conn_internal(s, listener);
            unixsock_peercred_set(s, listener->peercred.p, listener->peercred.uid, listener->peercred.gid);
        }
        unixsock_unlock(s);
    }
out:
    if (listener)
        refcount_release(&listener->refcount);
    socket_release(sock);
    return rv;
}

closure_function(5, 1, sysreturn, accept_bh,
                 unixsock, s, struct sockaddr *, addr, socklen_t *, addrlen, int, flags, io_completion, completion,
                 u64 bqflags)
{
    unixsock s = bound(s);
    struct sockaddr *addr = bound(addr);
    sysreturn rv;

    if (bqflags & BLOCKQ_ACTION_NULLIFY) {
        rv = -ERESTARTSYS;
        goto out;
    }
    unixsock_lock(s);
    unixsock child = dequeue(s->conn_q);
    boolean empty = queue_empty(s->conn_q);
    unixsock_unlock(s);
    context ctx = context_from_closure(closure_self());
    if (child == INVALID_ADDRESS) {
        if (s->sock.f.flags & SOCK_NONBLOCK) {
            rv = -EAGAIN;
            goto out;
        }
        return blockq_block_required((unix_context)ctx, bqflags);
    }

    process p = is_syscall_context(ctx) ? ((syscall_context)ctx)->t->p : ((process_context)ctx)->p;
    child->sock.fd = allocate_fd(p, child, fd_flags_from_open_flags(bound(flags)));
    if (child->sock.fd == INVALID_PHYSICAL) {
        apply(child->sock.f.close, 0, io_completion_ignore);
        rv = -ENFILE;
        goto out;
    }

    if (empty) {
        fdesc_notify_events(&s->sock.f);
    }
    child->sock.f.flags |= bound(flags);
    rv = child->sock.fd;
    if (addr) {
        if (context_set_err(ctx)) {
            rv = -EFAULT;
            goto out;
        }
        unixsock_addr_copy((struct sockaddr_un *)addr, &child->peer->local_addr, bound(addrlen));
        context_clear_err(ctx);
    }
    unixsock_notify_writer(s);
out:
    apply(bound(completion), rv);
    closure_finish();
    return rv;
}

static sysreturn unixsock_accept4(struct sock *sock, struct sockaddr *addr,
                                  socklen_t *addrlen, int flags, context ctx, boolean in_bh,
                                  io_completion completion)
{
    unixsock s = (unixsock) sock;
    sysreturn rv;
    if (!unixsock_is_conn_oriented(s)) {
        rv = -EOPNOTSUPP;
        goto out;
    }
    if (!s->conn_q || (flags & ~SOCK_FLAGS_MASK)) {
        rv = -EINVAL;
        goto out;
    }
    blockq_action ba = closure_from_context(ctx, accept_bh, s, addr, addrlen, flags, completion);
    if (ba == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto out;
    }
    return blockq_check(sock->rxbq, ba, in_bh);
out:
    return io_complete(completion, rv);
}

static sysreturn unixsock_getsockname(struct sock *sock, struct sockaddr *addr, socklen_t *addrlen)
{
    unixsock s = (unixsock)sock;
    unixsock_lock(s);
    unixsock_addr_copy((struct sockaddr_un *)addr, &s->local_addr, addrlen);
    unixsock_unlock(s);
    socket_release(sock);
    return 0;
}

static sysreturn unixsock_setsockopt(struct sock *sock, int level,
                                     int optname, void *optval, socklen_t optlen)
{
    sysreturn rv;
    unixsock s = (unixsock)sock;
    switch (level) {
    case SOL_SOCKET:
        switch (optname) {
        case SO_REUSEADDR:
            rv = 0; /* to mimic Linux behavior, return 0 even if not actually implemented */
            break;
        case SO_PASSCRED: {
            if (optlen != sizeof(int)) {
                rv = -EINVAL;
                break;
            }
            int val = 0;
            if (!copy_from_user(optval, &val, sizeof(val))) {
                rv = -EFAULT;
                break;
            }
            unixsock_lock(s);
            s->passcred = (val != 0);
            unixsock_unlock(s);
            rv = 0;
            break;
        }
        default:
            rv = -EOPNOTSUPP;
        }
        break;
    default:
        rv = -EOPNOTSUPP;
    }
    socket_release(sock);
    return rv;
}

static sysreturn unixsock_getsockopt(struct sock *sock, int level,
                                     int optname, void *optval, socklen_t *optlen)
{
    sysreturn rv;
    union {
        int val;
        struct linger {
            int l_onoff;
            int l_linger;
        } linger;
        struct unix_ucred cred;
    } ret_optval;
    int ret_optlen;
    unixsock s = (unixsock)sock;

    switch (level) {
    case SOL_SOCKET:
        switch (optname) {
        case SO_TYPE:
            ret_optval.val = sock->type;
            ret_optlen = sizeof(ret_optval.val);
            break;
        case SO_PASSCRED: {
            unixsock_lock(s);
            ret_optval.val = s->passcred ? 1 : 0;
            unixsock_unlock(s);
            ret_optlen = sizeof(ret_optval.val);
            break;
        }
        case SO_PEERCRED: {
            unixsock_lock(s);
            process p = s->peercred.p;
            u32 uid = s->peercred.uid;
            u32 gid = s->peercred.gid;
            unixsock_unlock(s);
            process cur = get_current_thread() ? get_current_thread()->p : 0;
            user_namespace viewer_ns = cur ? process_user_ns(cur) : 0;
            if (viewer_ns) {
                uid = user_ns_from_kuid(viewer_ns, uid);
                gid = user_ns_from_kgid(viewer_ns, gid);
                user_ns_release(viewer_ns);
            }
            ret_optval.cred.pid = process_visible_pid(p, cur);
            ret_optval.cred.uid = uid;
            ret_optval.cred.gid = gid;
            ret_optlen = sizeof(ret_optval.cred);
            break;
        }
        default:
            goto unimplemented;
        }
        break;
    default:
        goto unimplemented;
    }
    rv = sockopt_copy_to_user(optval, optlen, &ret_optval, ret_optlen);
    goto out;
unimplemented:
    msg_err("getsockopt unimplemented: fd %d, level %d, optname %d",
            sock->fd, level, optname);
    rv = -ENOPROTOOPT;
out:
    socket_release(sock);
    return rv;
}

sysreturn unixsock_sendto(struct sock *sock, void *buf, u64 len, int flags,
                          struct sockaddr *dest_addr, socklen_t addrlen, context ctx,
                          boolean in_bh, io_completion completion)
{
    unixsock s = (unixsock) sock;
    unixsock dest;
    sysreturn rv;
    /* Linux ignores destination address in SEQPACKET sockets. */
    if ((sock->type != SOCK_SEQPACKET) && (dest_addr || addrlen)) {
        if (sock->type == SOCK_STREAM) {
            if (s->peer)
                rv = -EISCONN;
            else
                rv = -EOPNOTSUPP;
            goto out;
        }
        rv = lookup_socket(&dest, dest_addr, addrlen);
        if (rv != 0)
            goto out;
    } else {
        unixsock_lock(s);
        dest = s->peer;
        if (dest)
            refcount_reserve(&dest->refcount);
        unixsock_unlock(s);
    }
    if (!dest) {
        rv = -ENOTCONN;
        goto out;
    }
    return unixsock_write_with_addr(s, buf, len, 0, ctx, in_bh, completion, dest, flags, 0);
out:
    return io_complete(completion, rv);
}

sysreturn unixsock_recvfrom(struct sock *sock, void *buf, u64 len, int flags,
                            struct sockaddr *src_addr, socklen_t *addrlen, context ctx,
                            boolean in_bh, io_completion completion)
{
    if (src_addr || addrlen) {
        if (!(src_addr && addrlen)) {
            return io_complete(completion, -EFAULT);
        }
    }
    return unixsock_read_with_addr((unixsock)sock, buf, len, 0, ctx, in_bh, completion,
                                   src_addr, addrlen, flags);
}

sysreturn unixsock_sendmsg(struct sock *sock, const struct msghdr *msg,
                           int flags, boolean in_bh, io_completion completion)
{
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx)) {
        return io_complete(completion, -EFAULT);
    }
    struct iovec *iov = msg->msg_iov;
    u64 len = msg->msg_iovlen;
    if (!memory_is_user(iov, len * sizeof(*iov)))
        page_fault();
    context_clear_err(ctx);
    return unixsock_writev_flags((unixsock)sock, iov, len, ctx, in_bh, completion, flags, msg);
}

sysreturn unixsock_recvmsg(struct sock *sock, struct msghdr *msg, int flags, boolean in_bh,
                           io_completion completion)
{
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx)) {
        return io_complete(completion, -EFAULT);
    }
    struct iovec *iov = msg->msg_iov;
    u64 len = msg->msg_iovlen;
    struct sockaddr_un *addr = msg->msg_name;
    if (!memory_is_user(iov, len * sizeof(*iov)) || (addr && !memory_is_user(addr, sizeof(*addr))))
        page_fault();
    context_clear_err(ctx);
    blockq_action ba = closure_from_context(ctx, unixsock_read_bh, (unixsock)sock, 0, iov, len,
                                            completion, addr, &msg->msg_namelen, flags, msg);
    if (ba == INVALID_ADDRESS) {
        return io_complete(completion, -ENOMEM);
    }
    return blockq_check(sock->rxbq, ba, in_bh);
}

static sysreturn unixsock_shutdown(struct sock *sock, int how)
{
    unixsock s = (unixsock)sock;
    u8 mode;
    switch (how) {
    case SHUT_RD:
        mode = UNIXSOCK_RCV_SHUTDOWN;
        break;
    case SHUT_WR:
        mode = UNIXSOCK_SEND_SHUTDOWN;
        break;
    case SHUT_RDWR:
        mode = UNIXSOCK_SHUTDOWN_MASK;
        break;
    default:
        socket_release(sock);
        return -EINVAL;
    }
    u8 peer_mode = ((mode & UNIXSOCK_RCV_SHUTDOWN) ? UNIXSOCK_SEND_SHUTDOWN : 0) |
                   ((mode & UNIXSOCK_SEND_SHUTDOWN) ? UNIXSOCK_RCV_SHUTDOWN : 0);
    unixsock_lock(s);
    s->shutdown |= mode;
    unixsock peer = unixsock_is_conn_oriented(s) ? s->peer : 0;
    if (peer)
        refcount_reserve(&peer->refcount);
    unixsock_unlock(s);
    if (peer) {
        unixsock_lock(peer);
        peer->shutdown |= peer_mode;
        unixsock_unlock(peer);
    }
    socket_flush_q(&s->sock);
    fdesc_notify_events(&s->sock.f);
    if (peer) {
        socket_flush_q(&peer->sock);
        fdesc_notify_events(&peer->sock.f);
        refcount_release(&peer->refcount);
    }
    socket_release(sock);
    return 0;
}

static unixsock unixsock_alloc(heap h, int type, u32 flags, boolean alloc_fd)
{
    unixsock s = allocate(h, sizeof(*s));
    if (s == INVALID_ADDRESS) {
        msg_err("unixsock: failed to allocate socket structure");
        return 0;
    }
    s->data = allocate_queue(h, UNIXSOCK_QUEUE_MAX_LEN);
    if (s->data == INVALID_ADDRESS) {
        msg_err("unixsock: failed to allocate data buffer");
        goto err_queue;
    }
    if (socket_init(h, AF_UNIX, type, flags, &s->sock) < 0) {
        msg_err("unixsock: failed to initialize socket");
        goto err_socket;
    }
    s->sock.f.read = init_closure_func(&s->read, file_io, unixsock_read);
    s->sock.f.write = init_closure_func(&s->write, file_io, unixsock_write);
    s->sock.f.readv = init_closure_func(&s->readv, file_iov, unixsock_readv);
    s->sock.f.writev = init_closure_func(&s->writev, file_iov, unixsock_writev);
    s->sock.f.events = init_closure_func(&s->events, fdesc_events, unixsock_events);
    s->sock.f.ioctl = init_closure_func(&s->ioctl, fdesc_ioctl, unixsock_ioctl);
    s->sock.f.close = init_closure_func(&s->close, fdesc_close, unixsock_close);
    s->sock.bind = unixsock_bind;
    s->sock.listen = unixsock_listen;
    s->sock.connect = unixsock_connect;
    s->sock.accept4 = unixsock_accept4;
    s->sock.getsockname = unixsock_getsockname;
    s->sock.setsockopt = unixsock_setsockopt;
    s->sock.getsockopt = unixsock_getsockopt;
    s->sock.sendto = unixsock_sendto;
    s->sock.recvfrom = unixsock_recvfrom;
    s->sock.sendmsg = unixsock_sendmsg;
    s->sock.recvmsg = unixsock_recvmsg;
    s->sock.shutdown = unixsock_shutdown;
    s->fs_entry = 0;
    s->local_addr.sun_family = AF_UNIX;
    s->local_addr.sun_path[0] = '\0';
    s->conn_q = 0;
    s->peer = 0;
    s->shutdown = 0;
    s->passcred = false;
    s->peercred.p = 0;
    s->peercred.uid = 0;
    s->peercred.gid = 0;
    s->notify_handle = INVALID_ADDRESS;
    init_closure_func(&s->free, thunk, unixsock_free);
    init_refcount(&s->refcount, 1, (thunk)&s->free);
    if (alloc_fd) {
        s->sock.fd = allocate_fd(current->p, s, fd_flags_from_open_flags(s->sock.f.flags));
        if (s->sock.fd == INVALID_PHYSICAL) {
            apply(s->sock.f.close, 0, io_completion_ignore);
            return 0;
        }
    } else {
        s->sock.fd = -1;
    }
    return s;
err_socket:
    deallocate_queue(s->data);
err_queue:
    deallocate(h, s, sizeof(*s));
    return 0;
}

sysreturn unixsock_open(int type, int protocol) {
    heap h = heap_locked(get_kernel_heaps());
    unixsock s;

    if (!unixsock_type_is_supported(type))
        return -ESOCKTNOSUPPORT;
    s = unixsock_alloc(h, type & SOCK_TYPE_MASK, type & ~SOCK_TYPE_MASK, true);
    if (!s) {
        return -ENOMEM;
    }
    return s->sock.fd;
}

sysreturn socketpair(int domain, int type, int protocol, int sv[2]) {
    heap h = heap_locked(get_kernel_heaps());
    unixsock s1, s2;

    if (domain != AF_UNIX) {
        return set_syscall_error(current, EAFNOSUPPORT);
    }
    if (!unixsock_type_is_supported(type))
        return -ESOCKTNOSUPPORT;
    if (!fault_in_user_memory(sv, 2 * sizeof(int), true))
        return -EFAULT;
    s1 = unixsock_alloc(h, type & SOCK_TYPE_MASK, type & ~SOCK_TYPE_MASK, true);
    if (!s1) {
        return -ENOMEM;
    }
    s2 = unixsock_alloc(h, type & SOCK_TYPE_MASK, type & ~SOCK_TYPE_MASK, true);
    if (!s2) {
        unixsock_dealloc(s1);
        return -ENOMEM;
    }
    s1->peer = s2;
    s2->peer = s1;
    refcount_reserve(&s1->refcount);
    refcount_reserve(&s2->refcount);
    {
        process cur = current->p;
        struct creds c;
        creds_snapshot(cur, &c);
        unixsock_peercred_set(s1, cur, c.euid, c.egid);
        unixsock_peercred_set(s2, cur, c.euid, c.egid);
    }
    sv[0] = s1->sock.fd;
    sv[1] = s2->sock.fd;
    return 0;
}
