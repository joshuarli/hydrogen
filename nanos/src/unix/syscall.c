#include <unix_internal.h>
#include <seccomp.h>
#include <filesystem.h>
#include <lwip.h>
#include <storage.h>

static buffer hostname;

BSS_RO_AFTER_INIT static boolean do_missing_files;
BSS_RO_AFTER_INIT static vector missing_files;

sysreturn close(int fd);

BSS_RO_AFTER_INIT io_completion syscall_io_complete;
BSS_RO_AFTER_INIT io_completion io_completion_ignore;

struct iov_progress {
    heap h;
    fdesc f;
    boolean write;
    struct iovec *iov;
    int iovcnt;
    boolean initialized;
    boolean blocking;
    u64 file_offset;
    int curr;
    void *curr_base;
    u64 curr_len;
    u64 total_len;
    context ctx;
    io_completion completion;
    closure_struct(io_completion, each_complete);
    closure_struct(thunk, bh);
};

static void iov_op_each(struct iov_progress *p)
{
    file_io op = p->write ? p->f->write : p->f->read;
    boolean blocking = p->blocking;
    p->blocking = false;

    /* Issue the next request. */
    thread_log(current, "   op: curr %d, @ %p, len %ld, blocking %d",
               p->curr, p->curr_base, p->curr_len, blocking);
    apply(op, p->curr_base, p->curr_len, p->file_offset, p->ctx, !blocking,
          (io_completion)&p->each_complete);
}

closure_func_basic(io_completion, void, iov_op_each_complete,
                   sysreturn rv)
{
    io_completion c;
    struct iov_progress *p = struct_from_closure(struct iov_progress *, each_complete);
    int iovcnt = p->iovcnt;
    fdesc f = p->f;
    boolean write = p->write;
    thread t = current;
    thread_log(t, "%s: rv %ld, curr %d, iovcnt %d", func_ss, rv, p->curr, iovcnt);

    file_io op = write ? f->write : f->read;
    if (!op)
        rv = -EOPNOTSUPP;

    /* If these ops were truly atomic, we would have to rewind file
       state on failure... */
    if (rv < 0) {
        goto out_complete;
    }

    /* Increment offset and total by io op retval, advancing to next
       (non-zero-len) buffer if needed. */
    struct iovec *iov = p->iov;
    p->total_len += rv;
    p->curr_base += rv;
    p->curr_len -= rv;
    if (p->curr_len == 0) {
        context ctx = p->ctx;
        if (context_set_err(ctx)) {
            rv = p->total_len;
            if (rv == 0)
                rv = -EFAULT;
            goto out_complete;
        }
        do {
            p->curr++;
        } while (p->curr < iovcnt && (p->curr_len = iov[p->curr].iov_len) == 0);
        if (p->curr < iovcnt) {
            p->curr_base = iov[p->curr].iov_base;
            if (!memory_is_user(p->curr_base, p->curr_len))
                page_fault();
        }
        context_clear_err(ctx);
    }

    /* If we're done, return the total length... */
    if ((p->curr == iovcnt) || ((rv == 0) && p->initialized) ||
            ((p->total_len != 0) && f->events &&
            !(apply(f->events, t) & (write ? EPOLLOUT : EPOLLIN)))) {
        rv = p->total_len;
        goto out_complete;
    }

    if (!p->initialized) {
        p->initialized = true;
        iov_op_each(p);
    } else {
        if (p->file_offset != infinity)
            p->file_offset += rv;
        async_apply((thunk)&p->bh);
    }
    return;
  out_complete:
    c = p->completion;
    deallocate(p->h, p, sizeof(*p));
    apply(c, rv);
}

closure_func_basic(thunk, void, iov_bh)
{
    iov_op_each(struct_from_field(closure_self(), struct iov_progress *, bh));
}

void iov_op(fdesc f, boolean write, struct iovec *iov, int iovcnt, u64 offset,
            context ctx, boolean blocking, io_completion completion)
{
    sysreturn rv;
    if ((write && !fdesc_is_writable(f)) || (!write && !fdesc_is_readable(f))) {
        rv = -EBADF;
        goto out;
    }
    if (iovcnt < 0 || iovcnt > IOV_MAX) {
        rv = -EINVAL;
        goto out;
    }
    if (iovcnt == 0) {
        rv = 0;
        goto out;
    }

    heap h = heap_locked(get_kernel_heaps());
    if (write ? (f->writev != 0) : (f->readv != 0)) {
        apply(write ? f->writev : f->readv, iov, iovcnt, offset, ctx, !blocking, completion);
        return;
    }
    struct iov_progress *p = allocate(h, sizeof(struct iov_progress));
    if (p == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto out;
    }
    p->h = h;
    p->f = f;
    p->write = write;
    p->iov = iov;
    p->iovcnt = iovcnt;
    p->initialized = false;
    p->blocking = blocking;
    p->file_offset = offset;
    p->curr = -1;
    p->curr_len = 0;
    p->total_len = 0;
    p->ctx = ctx;
    p->completion = completion;
    init_closure_func(&p->bh, thunk, iov_bh);
    closure_set_context(&p->bh, ctx);
    init_closure_func(&p->each_complete, io_completion, iov_op_each_complete);
    io_completion each = (io_completion)&p->each_complete;
    apply(each, 0);
    return;
out:
    apply(completion, rv);
}

static sysreturn iov_internal(int fd, boolean write, struct iovec *iov, int iovcnt, u64 offset)
{
    if (!memory_is_user(iov, iovcnt * sizeof(*iov)))
        return -EFAULT;
    fdesc f = resolve_fd(current->p, fd);
    context ctx = get_current_context(current_cpu());
    iov_op(f, write, iov, iovcnt, offset, ctx, true, (io_completion)&f->io_complete);
    return thread_maybe_sleep_uninterruptible(current);
}

sysreturn read(int fd, u8 *dest, bytes length)
{
    if (!memory_is_user(dest, length))
        return -EFAULT;
    fdesc f = resolve_fd(current->p, fd);
    sysreturn rv;
    if (!fdesc_is_readable(f)) {
        rv = -EBADF;
        goto out;
    }
    if (!f->read) {
        rv = -EINVAL;
        goto out;
    }

    /* use (and update) file offset */
    context ctx = get_current_context(current_cpu());
    return apply(f->read, dest, length, infinity, ctx, false, (io_completion)&f->io_complete);

  out:
    fdesc_put(f);
    return rv;
}

sysreturn pread(int fd, u8 *dest, bytes length, s64 offset)
{
    if (!memory_is_user(dest, length))
        return -EFAULT;
    fdesc f = resolve_fd(current->p, fd);
    sysreturn rv;
    if (!fdesc_is_readable(f)) {
        rv = -EBADF;
        goto out;
    }
    if (!f->read || offset < 0) {
        rv = -EINVAL;
        goto out;
    }

    /* use given offset with no file offset update */
    context ctx = get_current_context(current_cpu());
    return apply(f->read, dest, length, offset, ctx, false, (io_completion)&f->io_complete);

  out:
    fdesc_put(f);
    return rv;
}

sysreturn readv(int fd, struct iovec *iov, int iovcnt)
{
    return iov_internal(fd, false, iov, iovcnt, infinity);
}

sysreturn preadv(int fd, struct iovec *iov, int iovcnt, s64 offset)
{
    if (offset < 0)
        return -EINVAL;
    return iov_internal(fd, false, iov, iovcnt, offset);
}

sysreturn write(int fd, u8 *body, bytes length)
{
    if (!memory_is_user(body, length))
        return -EFAULT;
    fdesc f = resolve_fd(current->p, fd);
    sysreturn rv;
    if (!fdesc_is_writable(f)) {
        rv = -EBADF;
        goto out;
    }
    if (!f->write) {
        rv = -EINVAL;
        goto out;
    }

    /* use (and update) file offset */
    context ctx = get_current_context(current_cpu());
    return apply(f->write, body, length, infinity, ctx, false, (io_completion)&f->io_complete);

  out:
    fdesc_put(f);
    return rv;
}

sysreturn pwrite(int fd, u8 *body, bytes length, s64 offset)
{
    if (!memory_is_user(body, length))
        return -EFAULT;
    fdesc f = resolve_fd(current->p, fd);
    sysreturn rv;
    if (!fdesc_is_writable(f)) {
        rv = -EBADF;
        goto out;
    }
    if (!f->write || offset < 0) {
        rv = -EINVAL;
        goto out;
    }

    context ctx = get_current_context(current_cpu());
    return apply(f->write, body, length, offset, ctx, false, (io_completion)&f->io_complete);
  out:
    fdesc_put(f);
    return rv;
}

sysreturn writev(int fd, struct iovec *iov, int iovcnt)
{
    return iov_internal(fd, true, iov, iovcnt, infinity);
}

sysreturn pwritev(int fd, struct iovec *iov, int iovcnt, s64 offset)
{
    if (offset < 0)
        return -EINVAL;
    return iov_internal(fd, true, iov, iovcnt, offset);
}

closure_function(9, 1, void, copy_file_range_bh,
                 fdesc, in, fdesc, out, long *, in_off, long *, out_off,
                 sg_list, sg, sg_buf, cur_buf, bytes, readlen, bytes, written, boolean, bh,
                 sysreturn rv)
{
    thread t = current;
    thread_log(t, "%s: readlen %ld, written %ld, bh %d, rv %ld",
               func_ss, bound(readlen), bound(written), bound(bh), rv);

    long *out_off = bound(out_off);
    u64 write_offset = infinity;
    sg_list sg = bound(sg);

    /* !bh means read complete (rv is actually a status variable, the number of bytes read can be
     * retrieved from the SG list). */
    if (!bound(bh)) {
        status s = (status)rv;
        if (!is_ok(s)) {
            rv = sysreturn_from_fs_status_value(s);
            timm_dealloc(s);
        } else if (out_off) {
            if (!get_user_value(out_off, &write_offset))
                rv = -EFAULT;
            else if ((s64)write_offset < 0)
                rv = -EOVERFLOW;
        }
        if (rv < 0)
            goto out_complete;
        bound(bh) = true;
        bound(readlen) = sg->count;

        bound(cur_buf) = sg_list_head_remove(sg); /* initial dequeue */
        if (bound(cur_buf) == INVALID_ADDRESS)  /* nothing was read from input file */
            goto out_complete;
        bound(cur_buf)->offset = 0; /* offset for our use */
        thread_log(t, "   read %ld bytes\n", rv);
    } else {
        if ((rv > 0) && out_off) {
            context ctx = get_current_context(current_cpu());
            if (!context_set_err(ctx)) {
                write_offset = *out_off + rv;
                *out_off = write_offset;
                context_clear_err(ctx);
            } else {
                rv = -EFAULT;
            }
        }
        if (rv <= 0) {
            if (bound(written) != 0)
                rv = bound(written);
            sg_buf_release(bound(cur_buf));
            goto out_complete;
        }
        bound(written) += rv;
        bound(cur_buf)->offset += rv;
        if (bound(cur_buf)->offset == bound(cur_buf)->size) {
            sg_buf_release(bound(cur_buf));
            if (bound(written) == bound(readlen)) {
                rv = bound(written);
                goto out_complete;
            }
            bound(cur_buf) = sg_list_head_remove(sg);
            assert(bound(cur_buf) != INVALID_ADDRESS);
            bound(cur_buf)->offset = 0; /* offset for our use */
        }
        assert(bound(cur_buf)->offset < bound(cur_buf)->size);
    }

    /* issue next write */
    assert(bound(cur_buf));
    void *buf = bound(cur_buf)->buf + bound(cur_buf)->offset;
    u32 n = sg_buf_len(bound(cur_buf));
    thread_log(t, "   writing %d bytes from %p", n, buf);
    context ctx = get_current_context(current_cpu());
    apply(bound(out)->write, buf, n, write_offset, ctx, true, (io_completion)closure_self());
    return;
out_complete:
    sg_list_release(sg);
    deallocate_sg_list(sg);
    if (rv > 0) {
        long *offset = bound(in_off);
        if (offset) {
            context ctx = get_current_context(current_cpu());
            if (!context_set_err(ctx)) {
                *offset += rv;
                context_clear_err(ctx);
            } else {
                rv = -EFAULT;
            }
        } else {
            file f_in = (file)bound(in);
            f_in->offset += rv;
        }
    }
    fdesc_put(bound(in));
    fdesc_put(bound(out));
    syscall_return(t, rv);
    closure_finish();
}

/* Should be determined more intelligently based on available
   buffering on output side, modulated by link capacity
   (e.g. bandwidth delay product). Right now assuming the common mode
   is tcp output with 64kB max window size... */

#define SENDFILE_READ_MAX (64 * KB)

/* requires infile to be a regular file - so sendfile from special files isn't supported */
static sysreturn copy_file_range(int in_fd, long *in_off, int out_fd, long *out_off, bytes count,
                                 unsigned int flags)
{
    u64 read_offset;
    if (in_off) {
        if (!get_user_value(in_off, &read_offset))
            return -EFAULT;
        if ((s64)read_offset < 0)
            return -EINVAL;
    }
    /* Allow copying from a file to itself, but only if at least one of the two offsets is non-NULL.
     */
    if ((in_fd == out_fd) && !in_off && !out_off)
        return -EINVAL;
    if (flags)
        return -EINVAL;
    fdesc infile = resolve_fd(current->p, in_fd);
    fdesc outfile = fdesc_get(current->p, out_fd);
    if (!outfile) {
        fdesc_put(infile);
        return -EBADF;
    }
    sysreturn rv;
    if (!fdesc_is_readable(infile) || !fdesc_is_writable(outfile)) {
        rv = -EBADF;
        goto out;
    }
    if ((infile->type != FDESC_TYPE_REGULAR) || !outfile->write) {
        rv = -EINVAL;
        goto out;
    }

    sg_list sg = allocate_sg_list();
    if (sg == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto out;
    }

    file f = (file)infile;
    if (!in_off)
        read_offset = f->offset;
    u64 n = MIN(count, SENDFILE_READ_MAX);
    io_completion read_complete = contextual_closure(copy_file_range_bh, infile, outfile,
                                                     in_off, out_off, sg, 0, 0,
                                                     0, false);
    if (read_complete == INVALID_ADDRESS) {
        deallocate_sg_list(sg);
        rv = -ENOMEM;
        goto out;
    }
    pagecache_node pn = fsfile_get_cachenode(f->fsf);
    pagecache_node_fetch_pages(pn, irangel(read_offset, n), sg, (status_handler)read_complete);
    return thread_maybe_sleep_uninterruptible(current);
  out:
    fdesc_put(infile);
    fdesc_put(outfile);
    return rv;
}

static sysreturn sendfile(int out_fd, int in_fd, long *offset, bytes count)
{
    return copy_file_range(in_fd, offset, out_fd, NULL, count, 0);
}

static void file_io_complete(file f, range r, boolean is_file_offset, sg_list sg,
                             io_completion completion, status s)
{
    sysreturn rv;
    if (is_ok(s)) {
        u64 len = range_span(r);
        len -= sg_total_len(sg);
        u64 file_len = fsfile_get_length(f->fsf);
        if (r.start >= file_len)
            len = 0;
        else if (r.start + len > file_len)   /* can happen with direct I/O */
            len = file_len - r.start;
        if (is_file_offset) /* vs specified offset (pread/pwrite) */
            f->offset += len;
        rv = len;
    } else {
        rv = sysreturn_from_fs_status_value(s);
        timm_dealloc(s);
    }
    sg_list_release(sg);
    deallocate_sg_list(sg);
    apply(completion, rv);
}

static sysreturn file_read_check(file f, u64 offset, struct iovec *iov, int count, boolean user_iov,
                                 sg_list *sgp)
{
    if (fdesc_type(&f->f) == FDESC_TYPE_DIRECTORY)
        return -EISDIR;
    else if (!f->fsf)
        return -EBADF;
    return file_io_init_sg(f, offset, iov, count, user_iov, sgp);
}

static void begin_file_read(file f, u64 length)
{
    if (length == 0)
        return;
    tuple md = filesystem_get_meta(f->fs, f->n);
    if (md) {
        if (!(f->f.flags & O_NOATIME))
            filesystem_update_relatime(f->fs, md);
        fs_notify_event(md, 0, IN_ACCESS);
        filesystem_put_meta(f->fs, md);
    }
}

static void file_do_read(file f, sg_list sg, range q, status_handler sh)
{
    u64 len = range_span(q);
    begin_file_read(f, len);
    apply(f->fs_read, sg, q, sh);
    if (!(f->f.flags & O_DIRECT))
        file_readahead(f, q.start, len);
}

closure_function(5, 1, void, file_read_complete,
                 sg_list, sg, range, r, file, f, boolean, is_file_offset, io_completion, completion,
                 status s)
{
    if (!is_ok(s)) {
        sstring err_string = string_from_errno(-sysreturn_from_fs_status_value(s));
        msg_info("file read error: %s, status %v", err_string, s);
    }
    file_io_complete(bound(f), bound(r), bound(is_file_offset), bound(sg), bound(completion),
                     s);
    closure_finish();
}

closure_func_basic(file_io, sysreturn, file_read,
                   void *dest, u64 length, u64 offset_arg, context ctx, boolean bh, io_completion completion)
{
    file f = struct_from_field(closure_self(), file, read);
    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;
    thread t = current;
    thread_log(t, "%s: f %p, dest %p, offset %ld (%s), length %ld, file length %ld",
               func_ss, f, dest, offset, is_file_offset ? ss("file") : ss("specified"),
               length, f->fsf ? fsfile_get_length(f->fsf) : 0);

    struct iovec iov = {
        .iov_base = dest,
        .iov_len = length,
    };
    sg_list sg;
    sysreturn rv = file_read_check(f, offset, &iov, 1, false, &sg);
    if (rv < 0)
        return io_complete(completion, rv);
    range r = irangel(offset, length);
    status_handler sh = closure_from_context(ctx, file_read_complete, sg, r, f, is_file_offset,
                                             completion);
    if (sh == INVALID_ADDRESS) {
        deallocate_sg_list(sg);
        return io_complete(completion, -ENOMEM);
    }
    file_do_read(f, sg, r, sh);
    /* possible direct return in top half */
    return bh ? SYSRETURN_CONTINUE_BLOCKING : thread_maybe_sleep_uninterruptible(t);
}

closure_func_basic(file_iov, sysreturn, file_readv,
                   struct iovec *iov, int count, u64 offset_arg, context ctx, boolean bh, io_completion completion)
{
    file f = struct_from_field(closure_self(), file, readv);

    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;
    thread t = current;
    thread_log(t, "%s: f %p, iov %p, count %d, offset %ld (%s), file length %ld",
               func_ss, f, iov, count, offset, is_file_offset ? ss("file") : ss("specified"),
               f->fsf ? fsfile_get_length(f->fsf) : 0);

    sg_list sg;
    sysreturn rv = file_read_check(f, offset, iov, count, true, &sg);
    if (rv < 0)
        return io_complete(completion, rv);
    range r = irangel(offset, sg->count);
    status_handler sh = closure_from_context(ctx, file_read_complete, sg, r, f, is_file_offset,
                                             completion);
    if (sh == INVALID_ADDRESS) {
        deallocate_sg_list(sg);
        return io_complete(completion, -ENOMEM);
    }
    file_do_read(f, sg, r, sh);

    /* possible direct return in top half */
    return bh ? SYSRETURN_CONTINUE_BLOCKING : thread_maybe_sleep_uninterruptible(t);
}

static sysreturn file_write_check(file f, u64 offset, struct iovec *iov, int count,
                                  boolean user_iov, sg_list *sgp)
{
    fsfile fsf = f->fsf;
    if (!fsf)
        return -EBADF;
    sysreturn rv = file_io_init_sg(f, offset, iov, count, user_iov, sgp);
    if (rv < 0)
        return rv;
    filesystem fs = f->fs;
    if (fs->get_seals) {
        u64 len = (*sgp)->count;
        u64 seals;
        if ((len > 0) && (fs->get_seals(fs, fsf, &seals) == 0)) {
            if ((seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE)) ||
                ((seals & F_SEAL_GROW) && (offset + len > fsfile_get_length(fsf))))
                return -EPERM;
        }
    }
    return 0;
}

static void begin_file_write(file f, u64 len)
{
    if (len > 0) {
        tuple md = filesystem_get_meta(f->fs, f->n);
        if (md) {
            filesystem_update_mtime(f->fs, md);
            fs_notify_event(md, 0, IN_MODIFY);
            filesystem_put_meta(f->fs, md);
        }
    }
}

closure_function(6, 1, void, file_write_complete,
                 file, f, sg_list, sg, range, r, boolean, is_file_offset, io_completion, completion, boolean, flush,
                 status s)
{
    file f = bound(f);
    if (!bound(flush)) {
        if (f->f.flags & O_DSYNC) {
            bound(flush) = true;
            fsfile_flush(f->fsf, !(f->f.flags & _O_SYNC), (status_handler)closure_self());
            return;
        }
    }
    sg_list sg = bound(sg);
    io_completion completion = bound(completion);
    if (!is_ok(s)) {
        sstring err_string = string_from_errno(-sysreturn_from_fs_status_value(s));
        msg_info("file write error: %s, status %v", err_string, s);
    }
    file_io_complete(f, bound(r), bound(is_file_offset), sg, completion, s);
    closure_finish();
}

closure_func_basic(file_io, sysreturn, file_write,
                   void *src, u64 length, u64 offset_arg, context ctx, boolean bh, io_completion completion)
{
    file f = struct_from_field(closure_self(), file, write);
    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;
    thread t = current;
    thread_log(t, "%s: f %p, src %p, offset %ld (%s), length %ld, file length %ld",
               func_ss, f, src, offset, is_file_offset ? ss("file") : ss("specified"),
               length, f->fsf ? fsfile_get_length(f->fsf) : 0);

    struct iovec iov = {
        .iov_base = src,
        .iov_len = length,
    };
    sg_list sg;
    sysreturn rv = file_write_check(f, offset, &iov, 1, false, &sg);
    if (rv < 0)
        return io_complete(completion, rv);

    range r = irangel(offset, length);
    status_handler sh = closure_from_context(ctx, file_write_complete, f, sg, r, is_file_offset,
                                             completion, false);
    if (sh == INVALID_ADDRESS)
        goto no_mem;
    begin_file_write(f, length);
    apply(f->fs_write, sg, r, sh);
    /* possible direct return in top half */
    return bh ? SYSRETURN_CONTINUE_BLOCKING : thread_maybe_sleep_uninterruptible(t);
  no_mem:
    deallocate_sg_list(sg);
    return io_complete(completion, -ENOMEM);
}

closure_func_basic(file_iov, sysreturn, file_writev,
                   struct iovec *iov, int count, u64 offset_arg, context ctx, boolean bh, io_completion completion)
{
    file f = struct_from_field(closure_self(), file, writev);
    sysreturn rv;

    boolean is_file_offset = offset_arg == infinity;
    u64 offset = is_file_offset ? f->offset : offset_arg;
    thread t = current;
    thread_log(t, "%s: f %p, iov %p, count %d, offset %ld (%s), file length %ld",
               func_ss, f, iov, count, offset, is_file_offset ? ss("file") : ss("specified"),
               f->fsf ? fsfile_get_length(f->fsf) : 0);
    sg_list sg;
    rv = file_write_check(f, offset, iov, count, true, &sg);
    if (rv < 0)
        goto out;
    u64 len = sg->count;
    range r = irangel(offset, len);
    status_handler sg_complete = closure_from_context(ctx, file_write_complete, f, sg, r,
                                                      is_file_offset, completion, false);
    if (sg_complete == INVALID_ADDRESS) {
        deallocate_sg_list(sg);
        rv = -ENOMEM;
        goto out;
    }
    begin_file_write(f, len);
    apply(f->fs_write, sg, r, sg_complete);
    return bh ? SYSRETURN_CONTINUE_BLOCKING : thread_maybe_sleep_uninterruptible(t);
  out:
    return io_complete(completion, rv);
}

closure_func_basic(fdesc_close, sysreturn, file_close,
                   context ctx, io_completion completion)
{
    file f = struct_from_field(closure_self(), file, close);
    tuple md = filesystem_get_meta(f->fs, f->n);
    if (md) {
        fs_notify_event(md, 0, ((f->f.flags & O_ACCMODE) == O_RDONLY) ?
                        IN_CLOSE_NOWRITE : IN_CLOSE_WRITE);
        filesystem_put_meta(f->fs, md);
    }
    fsfile fsf = f->fsf;
    if (fsf)
        fsfile_release(fsf);
    file_release(f);
    return io_complete(completion, 0);
}

closure_func_basic(fdesc_events, u32, file_events,
                   thread t /* ignore */)
{
    file f = struct_from_field(closure_self(), file, events);
    u32 events;
    switch (fdesc_type(&f->f)) {
    case FDESC_TYPE_REGULAR:
    case FDESC_TYPE_DIRECTORY:
        events = EPOLLIN | EPOLLOUT;
        break;
    default:
        events = EPOLLNVAL;
    }
    return events;
}

int file_type_from_tuple(tuple n)
{
    if (is_dir(n))
        return FDESC_TYPE_DIRECTORY;
    else if (is_symlink(n) || get(n, sym(procfd)))
        return FDESC_TYPE_SYMLINK;
    else if (is_special(n))
        return FDESC_TYPE_SPECIAL;
    else if (is_socket(n))
        return FDESC_TYPE_SOCKET;
    else
        return FDESC_TYPE_REGULAR;
}

static int dt_from_tuple(tuple n)
{
    if (is_dir(n))
        return DT_DIR;
    else if (is_symlink(n) || get(n, sym(procfd)))
        return DT_LNK;
    else if (is_socket(n))
        return DT_SOCK;
    else
        return DT_REG;
}

int unix_file_new(filesystem fs, tuple md, int type, int flags, fsfile fsf)
{
    thread t = current;
    unix_heaps uh = get_unix_heaps();
    file f = type == FDESC_TYPE_SPECIAL ? spec_allocate(md) : unix_cache_alloc(uh, file);
    if (f == INVALID_ADDRESS) {
        return -ENOMEM;
    }
    heap h = heap_locked(get_kernel_heaps());
    init_fdesc(h, &f->f, type);
    f->f.flags = flags;
    f->fs = fs;
    f->fsf = fsf;
    u64 length;
    if (fsf) {
        if (flags & O_DIRECT) {
            f->fs_read = fsfile_get_reader(fsf);
            f->fs_write = fsfile_get_writer(fsf);
        } else {
            pagecache_node pn = fsfile_get_cachenode(fsf);
            f->fs_read = pagecache_node_get_reader(pn);
            f->fs_write = pagecache_node_get_writer(pn);
        }
        assert(f->fs_read);
        assert(f->fs_write);
        f->fadv = POSIX_FADV_NORMAL;
        length = fsfile_get_length(fsf);
    } else {
        length = 0;
    }
    f->n = fs->get_inode(fs, md);
    f->offset = (flags & O_APPEND) ? length : 0;

    if (type == FDESC_TYPE_SPECIAL) {
        int spec_ret = spec_open(f, md);
        if (spec_ret != 0) {
            assert(spec_ret < 0);
            spec_deallocate(f);
            return spec_ret;
        }
    } else {
        f->f.read = init_closure_func(&f->read, file_io, file_read);
        f->f.write = init_closure_func(&f->write, file_io, file_write);
        f->f.readv = init_closure_func(&f->readv, file_iov, file_readv);
        f->f.writev = init_closure_func(&f->writev, file_iov, file_writev);
        f->f.close = init_closure_func(&f->close, fdesc_close, file_close);
        f->f.events = init_closure_func(&f->events, fdesc_events, file_events);
    }
    filesystem_reserve(fs);
    process p = t->p;
    int fd = allocate_fd(p, f, fd_flags_from_open_flags(flags));
    if (fd == INVALID_PHYSICAL) {
        file_release(f);
        return -EMFILE;
    }
    thread_log(t, "file fd %d, length %ld, offset %ld", fd, length, f->offset);
    return fd;
}

int file_open(filesystem fs, tuple n, tuple parent, int flags, fsfile fsf)
{
    thread t = current;
    process p = t->p;
    int type = file_type_from_tuple(n);

    if (flags & O_TMPFILE)
        flags |= O_DIRECTORY;

    switch (flags & O_ACCMODE) {
    case O_RDONLY:
        if ((flags & O_TMPFILE)) {
            return -EINVAL;
        }
        break;
    case O_WRONLY:
    case O_RDWR:
        if ((type == FDESC_TYPE_REGULAR) && filesystem_is_readonly(fs)) {
            return -EROFS;
        }
        if (!(file_meta_perms(p, n) & ACCESS_PERM_WRITE)) {
            return -EACCES;
        }
        if ((type == FDESC_TYPE_DIRECTORY) && !(flags & O_TMPFILE)) {
            return -EISDIR;
        }
        break;
    default:
        return -EINVAL;
    }
    if ((flags & (O_CREAT|O_DIRECTORY)) == O_DIRECTORY && (type != FDESC_TYPE_DIRECTORY)) {
        return -ENOTDIR;
    }

    if (flags & O_TMPFILE) {
        int fss = filesystem_creat_unnamed(fs, &fsf);
        if (fss != 0)
            return fss;
        type = FDESC_TYPE_REGULAR;
    } else {
        if (type == FDESC_TYPE_REGULAR) {
            assert(fsf);
            if (flags & O_TRUNC)
                truncate_file_maps(fsf, 0);
        }
    }

    int fd = unix_file_new(fs, n, type, flags, fsf);
    if (fd >= 0)
        fs_notify_event(n, parent, IN_OPEN);
    else if (flags & O_TMPFILE)
        fsfile_release(fsf);
    return fd;
}

sysreturn open_internal(filesystem fs, inode cwd, sstring name, int flags,
                        int mode)
{
    tuple n;
    tuple parent;
    int ret;
    buffer b = 0;

    fsfile fsf = 0;
    u8 fs_flags = 0;
    if (!(flags & O_NOFOLLOW))
        fs_flags |= FS_NODE_FOLLOW;
    if (flags & O_CREAT)
        fs_flags |= FS_NODE_CREATE;
    if (flags & O_EXCL)
        fs_flags |= FS_NODE_EXCL;
    if (flags & O_TRUNC)
        fs_flags |= FS_NODE_TRUNC;
    ret = filesystem_get_node(&fs, cwd, name, fs_flags, &n, &parent, &fsf);
    if (ret == -EFAULT)
        return ret;
    int proc_pid, proc_fd;
    if ((ret == 0) && !(flags & O_PATH) && procfs_fd_link(n, &proc_pid, &proc_fd)) {
        filesystem_put_node(fs, n);
        if (fsf)
            fsfile_release(fsf);
        return set_syscall_return(current, procfs_fd_open(proc_pid, proc_fd, flags));
    }
    if ((ret == 0) && (flags & O_NOFOLLOW) && is_symlink(n) && !(flags & O_PATH)) {
        filesystem_put_node(fs, n);
        ret = -ELOOP;
    }

    if (do_missing_files) {
        b = wrap_string_sstring(name);
        assert(b != INVALID_ADDRESS);
        b = buffer_basename(b);
    }
    if (ret) {
        if (do_missing_files) {
            boolean found = false;
            for (int i = 0; i < vector_length(missing_files); i++) {
                buffer lb = vector_get(missing_files, i);
                if (buffer_compare(b, lb)) {
                    found = true;
                    break;
                }
            }
            if (!found)
                vector_push(missing_files, b);
            else
                deallocate_buffer(b);
        }
        return set_syscall_return(current, ret);
    }

    ret = file_open(fs, n, parent, flags, fsf);
    if (ret < 0)
        goto out;

    if (do_missing_files) {
        for (int i = 0; i < vector_length(missing_files); i++) {
            buffer mf = vector_get(missing_files, i);
            if (buffer_compare(b, mf)) {
                vector_delete(missing_files, i);
                deallocate_buffer(mf);
                break;
            }
        }
        deallocate_buffer(b);
    }
  out:
    filesystem_put_node(fs, n);
    if ((ret < 0) && fsf)
        fsfile_release(fsf);
    return ret;
}

#ifdef __x86_64__
sysreturn open(const char *name, int flags, int mode)
{
    sstring name_ss;
    if (!fault_in_user_string(name, &name_ss))
        return -EFAULT;
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = open_internal(cwd_fs, cwd, name_ss, flags, mode);
    filesystem_release(cwd_fs);
    return rv;
}
#endif

sysreturn dup(int fd)
{
    fdesc f = resolve_fd(current->p, fd);

    int newfd = allocate_fd(current->p, f, 0);
    if (newfd == INVALID_PHYSICAL) {
        fdesc_put(f);
        return set_syscall_error(current, EMFILE);
    }

    return newfd;
}

static sysreturn dup_to(int oldfd, int newfd, u32 fd_flags)
{
    process p = current->p;
    fdesc f = resolve_fd(p, oldfd);
    if (newfd == oldfd) {
        fdesc_put(f);
        return newfd;
    }
    fdesc newf = fdtable_replace(p->fdtable, newfd, f, fd_flags);
    if (newf) {
        if (fetch_and_add(&newf->refcnt, -1) == 1) {
            if (newf->close)
                apply(newf->close, get_current_context(current_cpu()), io_completion_ignore);
        }
    } else {
        newfd = allocate_fd_gte(p, newfd, f, fd_flags);
        if (newfd == INVALID_PHYSICAL) {
            fdesc_put(f);
            return -EMFILE;
        }
    }
    return newfd;
}

sysreturn dup2(int oldfd, int newfd)
{
    return dup_to(oldfd, newfd, 0);
}

sysreturn dup3(int oldfd, int newfd, int flags)
{
    if ((newfd == oldfd) || (flags & ~O_CLOEXEC)) {
        return -EINVAL;
    }
    return dup_to(oldfd, newfd, fd_flags_from_open_flags(flags));
}

sysreturn mkdir(const char *pathname, int mode)
{
    sstring pathname_ss;
    if (!fault_in_user_string(pathname, &pathname_ss))
        return -EFAULT;
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = filesystem_mkdir(cwd_fs, cwd, pathname_ss);
    filesystem_release(cwd_fs);
    return rv;
}

/*
If the pathname given in pathname is relative, then it is interpreted
relative to the directory referred to by the file descriptor dirfd
(rather than relative to the current working directory of the calling
process, as is done by open() for a relative pathname).

If pathname is relative and dirfd is the special value AT_FDCWD, then
pathname is interpreted relative to the current working directory of
the calling process (like open()).

If pathname is absolute, then dirfd is ignore
*/
sysreturn mkdirat(int dirfd, char *pathname, int mode)
{
    sstring pathname_ss;
    filesystem fs;
    inode cwd;
    cwd = resolve_dir(fs, dirfd, pathname, pathname_ss);

    sysreturn rv = filesystem_mkdir(fs, cwd, pathname_ss);
    filesystem_release(fs);
    return rv;
}

sysreturn creat(const char *pathname, int mode)
{
    sstring pathname_ss;
    if (!fault_in_user_string(pathname, &pathname_ss))
        return -EFAULT;
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = open_internal(cwd_fs, cwd, pathname_ss,
        O_CREAT|O_WRONLY|O_TRUNC, mode);
    filesystem_release(cwd_fs);
    return rv;
}

/* small enough to not exhaust entropy resources without scheduling */
#define GETRANDOM_MAX_BUFLEN (1ull << 20)

static inline boolean fill_random(void *buf, u64 buflen)
{
    context ctx = get_current_context(current_cpu());
    if (context_set_err(ctx)) {
        random_buffer_aborted();
        return false;
    }
    random_buffer(alloca_wrap_buffer(buf, buflen));
    context_clear_err(ctx);
    return true;
}

closure_function(3, 0, void, getrandom_deferred,
                 void *, buf, u64, buflen, u64, written)
{
    u64 len = MIN(GETRANDOM_MAX_BUFLEN, bound(buflen) - bound(written));
    if (fill_random(bound(buf) + bound(written), len)) {
        bound(written) += len;
        if (bound(written) < bound(buflen)) {
            async_apply((thunk)closure_self());
            kern_yield();
        }
    }
    syscall_return(current, bound(written));
    closure_finish();
}

sysreturn getrandom(void *buf, u64 buflen, unsigned int flags)
{
    if (!buflen)
        return set_syscall_error(current, EINVAL);

    if (flags & ~(GRND_NONBLOCK | GRND_RANDOM))
        return set_syscall_error(current, EINVAL);

    u64 n = MIN(GETRANDOM_MAX_BUFLEN, buflen);
    if (!memory_is_user(buf, buflen) || !fill_random(buf, n))
        return -EFAULT;

    if (n < buflen) {
        thunk t = contextual_closure(getrandom_deferred, buf, buflen, n);
        assert(t != INVALID_ADDRESS);
        async_apply(t);
        /* not really sleeping */
        thread_maybe_sleep_uninterruptible(current);
    }
    return buflen;
}

#define MEMBARRIER_CMD_QUERY                        0
#define MEMBARRIER_CMD_PRIVATE_EXPEDITED            (1 << 3)
#define MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED   (1 << 4)

static sysreturn membarrier(int cmd, unsigned int flags, int cpu_id)
{
    if (flags)
        return -EINVAL;
    process_vm vm = current->p->vm;
    switch (cmd) {
    case MEMBARRIER_CMD_QUERY:
        return MEMBARRIER_CMD_PRIVATE_EXPEDITED | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED;
    case MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED:
        vm->membarrier_private_expedited = true;
        return 0;
    case MEMBARRIER_CMD_PRIVATE_EXPEDITED:
        if (!vm->membarrier_private_expedited)
            return -EPERM;
        processors_rendezvous();
        return 0;
    default:
        return -EINVAL;
    }
}

static int try_write_dirent(void *dirp, boolean dirent64, string p,
        int *read_sofar, int *written_sofar, u64 *f_offset,
        unsigned int *count, filesystem fs, tuple n)
{
    int len = buffer_length(p);
    *read_sofar += len;
    if (*read_sofar > *f_offset) {
        int reclen = dirent64 ? (offsetof(struct linux_dirent64 *, d_name) + len + 1) :
                     (offsetof(struct linux_dirent *, d_name) + len + 2);
        reclen = pad(reclen, 8);    /* so that all dirent structures have natural alignment */
        // include this element in the getdents output
        if (reclen > *count) {
            // can't include, there's no space
            *read_sofar -= len;
            return -1;
        } else {
            // include the entry in the buffer
            if (dirent64) {
                struct linux_dirent64 *dp = dirp;
                dp->d_ino = fs->get_inode(fs, n);
                dp->d_reclen = reclen;
                runtime_memcpy(dp->d_name, buffer_ref(p, 0), len);
                dp->d_name[len] = '\0';
                dp->d_off = reclen + *written_sofar;
                dp->d_type = dt_from_tuple(n);
            } else {
                struct linux_dirent *dp = dirp;
                dp->d_ino = fs->get_inode(fs, n);
                dp->d_reclen = reclen;
                runtime_memcpy(dp->d_name, buffer_ref(p, 0), len);
                zero(dp->d_name + len, reclen - (((void *)dp->d_name) - dirp) - len - 1);
                dp->d_off = reclen + *written_sofar;
                ((char *)dirp)[reclen - 1] = dt_from_tuple(n);
            }

            // advance dirp
            *written_sofar += reclen;
            *count -= reclen;
            return reclen;
        }
    }
    return 0;
}

closure_function(8, 2, boolean, getdents_each,
                 file, f, void **, dirp, boolean, dirent64, int *, read_sofar, int *, written_sofar, unsigned int *, count, int *, r, filesystem, fs,
                 value k, value v)
{
    assert(is_symbol(k));
    string p = symbol_string(k);
    *bound(r) = try_write_dirent(*bound(dirp), bound(dirent64), p,
                                 bound(read_sofar), bound(written_sofar), &bound(f)->offset, bound(count),
                                 bound(fs), v);
    if (*bound(r) < 0)
        return false;

    *bound(dirp) = *bound(dirp) + *bound(r);
    return true;
}

static sysreturn getdents_internal(int fd, void *dirp, unsigned int count, boolean dirent64)
{
    file f = resolve_fd(current->p, fd);
    tuple md = 0;
    sysreturn rv;
    if (!fault_in_user_memory(dirp, count, true)) {
        rv = -EFAULT;
        goto out;
    }
    md = filesystem_get_meta(f->fs, f->n);
    tuple c;
    if (!md || !(c = children(md))) {
        rv = -ENOTDIR;
        goto out;
    }

    int r = 0;
    int read_sofar = 0, written_sofar = 0;
    binding_handler h = stack_closure(getdents_each, f, &dirp, dirent64,
                                      &read_sofar, &written_sofar, &count, &r, f->fs);
    symbol parent_sym = sym_this("..");
    if (apply(h, sym_this("."), md) && apply(h, parent_sym, get_tuple(md, parent_sym)))
        iterate(c, h);
    fs_notify_event(md, 0, IN_ACCESS);
    filesystem_update_relatime(f->fs, md);
    f->offset = read_sofar;
    if (r < 0 && written_sofar == 0)
        rv = -EINVAL;
    else
        rv = written_sofar;
  out:
    if (md)
        filesystem_put_meta(f->fs, md);
    fdesc_put(&f->f);
    return rv;
}

sysreturn getdents(int fd, struct linux_dirent *dirp, unsigned int count)
{
    return getdents_internal(fd, dirp, count, false);
}

sysreturn getdents64(int fd, struct linux_dirent64 *dirp, unsigned int count)
{
    return getdents_internal(fd, dirp, count, true);
}

sysreturn chdir(const char *path)
{
    sstring path_ss;
    if (!fault_in_user_string(path, &path_ss))
        return -EFAULT;
    return filesystem_chdir(current->p, path_ss);
}

sysreturn fchdir(int dirfd)
{
    process p = current->p;
    file f = resolve_fd(p, dirfd);
    tuple cwd = filesystem_get_meta(f->fs, f->n);
    sysreturn rv;
    if (!cwd || !is_dir(cwd)) {
        rv = -ENOTDIR;
        goto out;
    }

    process_lock(p);
    if (f->fs != p->cwd_fs) {
        filesystem_release(p->cwd_fs);
        filesystem_reserve(f->fs);
        p->cwd_fs = f->fs;
    }
    p->cwd = f->n;
    process_unlock(p);
    rv = 0;
  out:
    if (cwd)
        filesystem_put_meta(f->fs, cwd);
    fdesc_put(&f->f);
    return rv;
}

static sysreturn truncate_internal(filesystem fs, fsfile fsf, inode n, inode parent, long length)
{
    if (length < 0) {
        return set_syscall_error(current, EINVAL);
    }
    u64 cur_len = fsfile_get_length(fsf);
    if (length == cur_len)
        return 0;
    if (fs->get_seals) {
        u64 seals;
        if (fs->get_seals(fs, fsf, &seals) == 0) {
            if (((seals & F_SEAL_SHRINK) && (length < cur_len)) ||
                ((seals & F_SEAL_GROW) && (length > cur_len)))
                return -EPERM;
        }
    }
    int s = filesystem_truncate(fs, fsf, length);
    if (s == 0) {
        truncate_file_maps(fsf, length);
        tuple md = filesystem_get_meta(fs, n);
        if (md) {
          fs_notify_event(md, parent ? fs->get_meta(fs, parent) : 0, IN_MODIFY);
          filesystem_put_meta(fs, md);
        }
    }
    return s;
}

sysreturn truncate(const char *path, long length)
{
    sstring path_ss;
    if (!fault_in_user_string(path, &path_ss))
        return -EFAULT;
    tuple t;
    tuple parent;
    filesystem fs;
    inode cwd;
    process_get_cwd(current->p, &fs, &cwd);
    filesystem cwd_fs = fs;
    fsfile fsf;
    sysreturn rv = filesystem_get_node(&fs, cwd, path_ss, FS_NODE_FOLLOW, &t, &parent, &fsf);
    if (rv != 0)
        goto out;
    if (!(file_meta_perms(current->p, t) & ACCESS_PERM_WRITE))
        rv = -EACCES;
    else if (is_dir(t))
        rv = -EISDIR;
    else if (!fsf)
        rv = -EINVAL;
    else
        rv = 0;
    inode n = fs_get_inode(fs, t);
    inode parent_n = fs_get_inode(fs, parent);
    filesystem_put_node(fs, t);
    if (rv == 0)
        rv = truncate_internal(fs, fsf, n, parent_n, length);
    if (fsf)
        fsfile_release(fsf);
  out:
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn ftruncate(int fd, long length)
{
    file f = resolve_fd(current->p, fd);
    sysreturn rv;
    if (!(f->f.flags & (O_RDWR | O_WRONLY)) ||
            (f->f.type != FDESC_TYPE_REGULAR)) {
        rv = -EINVAL;
    } else {
        rv = truncate_internal(f->fs, f->fsf, f->n, 0, length);
    }
    fdesc_put(&f->f);
    return rv;
}

closure_function(1, 1, void, sync_complete,
                 fdesc, f,
                 status s)
{
    assert(is_syscall_context(get_current_context(current_cpu())));
    thread t = current;
    thread_log(current, "%s: status %v", func_ss, s);
    fdesc f = bound(f);
    if (f)
        fdesc_put(f);
    syscall_return(t, is_ok(s) ? 0 : -EIO);
    closure_finish();
}

sysreturn sync(void)
{
    status_handler sh = contextual_closure(sync_complete, 0);
    if (sh == INVALID_ADDRESS)
        return -ENOMEM;
    storage_sync(sh);
    return thread_maybe_sleep_uninterruptible(current);
}

sysreturn syncfs(int fd)
{
    /* Resolve to check validity of fd.
       When multiple volume support is added, we could grab the fs from the fsfile... */
    fdesc_put(resolve_fd(current->p, fd));
    return sync();
}

static sysreturn fsync_internal(int fd, boolean datasync)
{
    fdesc f = resolve_fd(current->p, fd);
    sysreturn rv;
    switch (f->type) {
    case FDESC_TYPE_REGULAR:
        assert(((file)f)->fsf);
        break;
    case FDESC_TYPE_DIRECTORY:
        if (datasync) {
            rv = 0;
            goto done;
        }
        break;
    case FDESC_TYPE_SYMLINK:
        rv = -EBADF;
        goto done;
    default:
        rv = -EINVAL;
        goto done;
    }
    status_handler completion = contextual_closure(sync_complete, f);
    if (completion == INVALID_ADDRESS) {
        rv = -ENOMEM;
        goto done;
    }
    if (((file)f)->fsf)
        fsfile_flush(((file)f)->fsf, datasync, completion);
    else
        filesystem_flush(((file)f)->fs, completion);
    return thread_maybe_sleep_uninterruptible(current);
  done:
    fdesc_put(f);
    return rv;
}

sysreturn fsync(int fd)
{
    return fsync_internal(fd, false);
}

sysreturn fdatasync(int fd)
{
    return fsync_internal(fd, true);
}

static sysreturn access_internal(filesystem fs, inode cwd, sstring pathname, int mode)
{
    tuple m = 0;
    int fss = filesystem_get_node(&fs, cwd, pathname, FS_NODE_FOLLOW, &m, 0, 0);
    if (fss != 0)
        return fss;
    u32 perms = file_meta_perms(current->p, m);
    filesystem_put_node(fs, m);
    if (mode == F_OK)
        return 0;
    if (((mode & R_OK) && !(perms & ACCESS_PERM_READ)) ||
            ((mode & W_OK) && !(perms & ACCESS_PERM_WRITE)) ||
            ((mode & X_OK) && !(perms & ACCESS_PERM_EXEC)))
        return -EACCES;
    return 0;
}

sysreturn access(const char *pathname, int mode)
{
    sstring pathname_ss;
    if (!fault_in_user_string(pathname, &pathname_ss))
        return -EFAULT;
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = access_internal(cwd_fs, cwd, pathname_ss, mode);
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn faccessat(int dirfd, const char *pathname, int mode)
{
    sstring pathname_ss;
    filesystem fs;
    inode cwd = resolve_dir(fs, dirfd, pathname, pathname_ss);
    sysreturn rv = access_internal(fs, cwd, pathname_ss, mode);
    filesystem_release(fs);
    return rv;
}

/*
If the pathname given in pathname is relative, then it is interpreted
relative to the directory referred to by the file descriptor dirfd
(rather than relative to the current working directory of the calling
process, as is done by open() for a relative pathname).

If pathname is relative and dirfd is the special value AT_FDCWD, then
pathname is interpreted relative to the current working directory of
the calling process (like open()).

If pathname is absolute, then dirfd is ignore
*/
sysreturn openat(int dirfd, const char *name, int flags, int mode)
{
    if (name == 0)
        return set_syscall_error(current, EINVAL);

    sstring name_ss;
    filesystem fs;
    inode cwd;
    cwd = resolve_dir(fs, dirfd, name, name_ss);

    sysreturn rv = open_internal(fs, cwd, name_ss, flags, mode);
    filesystem_release(fs);
    return rv;
}

static void fill_stat(int type, filesystem fs, fsfile f, tuple n, struct stat *s)
{
    zero(s, sizeof(struct stat));
    s->st_mode = stat_mode(current->p, type, n);

    struct creds c;
    creds_snapshot(current->p, &c);
    s->st_uid = c.fsuid;
    s->st_gid = c.fsgid;
    switch (type) {
    case FDESC_TYPE_REGULAR:
        if (f) {
            s->st_size = fsfile_get_length(f);
            s->st_blocks = fsfile_get_blocks(f);
        }
        s->st_blksize = PAGESIZE;   /* "preferred" block size for efficient filesystem I/O */
        break;
    case FDESC_TYPE_STDIO:
        /* Describing stdout as a pseudo-tty makes glibc apply line buffering (instead of full
         * buffering) when the process writes to stdout. */
        s->st_rdev = makedev(UNIX98_PTY_SLAVE_MAJOR, 0);
        break;
    case FDESC_TYPE_SPECIAL:
        s->st_rdev = filesystem_get_rdev(fs, n);
        break;
    case FDESC_TYPE_SYMLINK:
        if (n && linktarget(n))
            s->st_size = buffer_length(linktarget(n));
        break;
    }
    if (n) {
        u64 nlink;
        if (get_u64(n, sym(nlink), &nlink))
            s->st_nlink = nlink;
        s->st_ino = fs->get_inode(fs, n);
        struct timespec ts;
        timespec_from_time(&ts, filesystem_get_atime(fs, n));
        s->st_atime = ts.tv_sec;
        s->st_atime_nsec = ts.tv_nsec;
        timespec_from_time(&ts, filesystem_get_mtime(fs, n));
        s->st_mtime = ts.tv_sec;
        s->st_mtime_nsec = ts.tv_nsec;
    }
}

sysreturn fdesc_stat(fdesc f, struct stat *s)
{
    filesystem fs;
    tuple n;
    fsfile fsf = 0;
    switch (f->type) {
    case FDESC_TYPE_REGULAR:
        fsf = ((file)f)->fsf;
        /* no break */
    case FDESC_TYPE_DIRECTORY:
    case FDESC_TYPE_SPECIAL:
    case FDESC_TYPE_SYMLINK:
        fs = ((file)f)->fs;
        n = filesystem_get_meta(fs, ((file)f)->n);
        break;
    default:
        fs = 0;
        n = 0;
        break;
    }
    fill_stat(f->type, fs, fsf, n, s);
    if (n)
        filesystem_put_meta(fs, n);
    return 0;
}

static sysreturn fstat(int fd, struct stat *s)
{
    fdesc f = resolve_fd(current->p, fd);
    sysreturn rv = fault_in_user_memory(s, sizeof(struct stat), true) ? fdesc_stat(f, s) : -EFAULT;
    fdesc_put(f);
    return rv;
}

static sysreturn stat_internal(filesystem fs, inode cwd, sstring name, boolean follow,
        struct stat *buf)
{
    tuple n;
    fsfile fsf;

    if (!fault_in_user_memory(buf, sizeof(struct stat), true))
        return -EFAULT;

    int fss = filesystem_get_node(&fs, cwd, name, follow ? FS_NODE_FOLLOW : 0, &n, 0, &fsf);
    if (fss != 0)
        return fss;

    int pid, fd;
    if (follow && procfs_fd_link(n, &pid, &fd)) {
        filesystem_put_node(fs, n);
        if (fsf)
            fsfile_release(fsf);
        return procfs_fd_stat(pid, fd, buf);
    }
    fill_stat(file_type_from_tuple(n), fs, fsf, n, buf);
    filesystem_put_node(fs, n);
    if (fsf)
        fsfile_release(fsf);
    return 0;
}

#ifdef __x86_64__

static sysreturn stat_cwd(const char *name, boolean follow, struct stat *buf)
{
    sstring name_ss;
    if (!fault_in_user_string(name, &name_ss))
        return -EFAULT;
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = stat_internal(cwd_fs, cwd, name_ss, follow, buf);
    filesystem_release(cwd_fs);
    return rv;
}

static sysreturn stat(const char *name, struct stat *buf)
{
    return stat_cwd(name, true, buf);
}

static sysreturn lstat(const char *name, struct stat *buf)
{
    return stat_cwd(name, false, buf);
}
#endif

static sysreturn newfstatat(int dfd, const char *name, struct stat *s, int flags)
{
    // if relative, but AT_EMPTY_PATH set, works just like fstat()
    if (flags & AT_EMPTY_PATH)
        return fstat(dfd, s);

    // Else, if we have a fd of a directory, resolve name to it.
    sstring name_ss;
    filesystem fs;
    inode n = resolve_dir(fs, dfd, name, name_ss);
    sysreturn rv = stat_internal(fs, n, name_ss, !(flags & AT_SYMLINK_NOFOLLOW), s);
    filesystem_release(fs);
    return rv;
}

sysreturn lseek(int fd, s64 offset, int whence)
{
    file f = resolve_fd(current->p, fd);
    s64 new;
    sysreturn rv;

    switch (whence) {
        case SEEK_SET:
            new = offset;
            break;
        case SEEK_CUR:
            new = f->offset + offset;
            break;
        case SEEK_END:
            new = (f->fsf ? fsfile_get_length(f->fsf) : S64_MAX) + offset;
            break;
        default:
            new = -1;
    }

    if (new < 0)
        rv = -EINVAL;
    else
        rv = f->offset = new;
    fdesc_put(&f->f);
    return rv;
}


sysreturn uname(struct utsname *v)
{
    char machine[] =
#ifdef __x86_64__
        "x86_64";
#endif
#ifdef __aarch64__
        "aarch64";
#endif
#ifdef __riscv
        "riscv64";
#endif

    if (!fault_in_user_memory(v, sizeof(struct utsname), true))
        return -EFAULT;

    tuple cfg = get_tuple(get_root_tuple(), sym_this("uname"));
    string sysname;
    if (cfg)
        sysname = get_string(cfg, sym_this("sysname"));
    else
        sysname = 0;
    if (!sysname)
        sysname = alloca_wrap_cstring("Nanos");
    bytes sysname_len = MIN(buffer_length(sysname), sizeof(v->sysname) - 1);
    runtime_memcpy(v->sysname, buffer_ref(sysname, 0), sysname_len);
    v->sysname[sysname_len] = '\0';
    if (hostname) {
        bytes length = MIN(buffer_length(hostname), sizeof(v->nodename) - 1);
        runtime_memcpy(v->nodename, buffer_ref(hostname, 0), length);
        v->nodename[length] = '\0';
    } else {
        v->nodename[0] = 0;
        struct netif *netif_default = netif_get_default();
        if (netif_default) {
            /* Derive nodename from the IP address of the default network interface. */
            const ip4_addr_t *addr = netif_ip4_addr(netif_default);
            if (!ip4_addr_isany_val(*addr))
                rsnprintf(v->nodename, sizeof(v->nodename), "%d-%d-%d-%d",
                          ip4_addr1(addr), ip4_addr2(addr), ip4_addr3(addr), ip4_addr4(addr));
            netif_unref(netif_default);
        }
        if (!v->nodename[0])
            runtime_memcpy(v->nodename, sysname, sizeof(sysname));
    }
    runtime_memcpy(v->machine, machine, sizeof(machine));

    /* gitversion shouldn't exceed the field, but just in case... */
    bytes len = MIN(gitversion.len, sizeof(v->version) - 1);
    runtime_memcpy(v->version, gitversion.ptr, len);
    v->version[len] = '\0';     /* TODO: append build seq / time */

    /* The "5.0-" dummy prefix placates the glibc dynamic loader. */
    tuple env = get_environment();
    string release;
    if (cfg)
        release = get_string(cfg, sym_this("release"));
    else
        release = 0;
    if (!release) {
        release = little_stack_buffer(sizeof(v->release) - 1);
        bprintf(release, "5.0-%v_aaa", get_string(env, sym(NANOS_VERSION)));
    }
    len = MIN(buffer_length(release), sizeof(v->release) - 1);
    runtime_memcpy(v->release, buffer_ref(release, 0), len);
    v->release[len] = '\0';
    return 0;
}

sysreturn setrlimit(int resource, const struct rlimit *rlim)
{
    context ctx = get_current_context(current_cpu());
    if (!memory_is_user(rlim, sizeof(struct rlimit)) || context_set_err(ctx))
        return -EFAULT;
    sysreturn rv = 0;
    process p = current->p;
    switch (resource) {
    case RLIMIT_STACK:
        current->p->rlimit_stack = rlim->rlim_cur;
        break;
    case RLIMIT_NPROC:
        if (rlim->rlim_cur > rlim->rlim_max)
            rv = -EINVAL;
        else if ((rlim->rlim_max > p->rlimit_nproc_max) && !capable(p, CAP_SYS_RESOURCE))
            rv = -EPERM;
        else {
            p->rlimit_nproc_cur = rlim->rlim_cur;
            p->rlimit_nproc_max = rlim->rlim_max;
        }
        break;
    case RLIMIT_NOFILE:
        if (rlim->rlim_cur > rlim->rlim_max)
            rv = -EINVAL;
        else if ((rlim->rlim_max > p->rlimit_nofile_max) && !capable(p, CAP_SYS_RESOURCE))
            rv = -EPERM;
        else {
            p->rlimit_nofile_cur = rlim->rlim_cur;
            p->rlimit_nofile_max = rlim->rlim_max;
        }
        break;
    }
    context_clear_err(ctx);
    return rv;
}

sysreturn getrlimit(int resource, struct rlimit *rlim)
{
    context ctx = get_current_context(current_cpu());
    if (!memory_is_user(rlim, sizeof(struct rlimit)) || context_set_err(ctx))
        return -EFAULT;

    sysreturn rv = 0;
    switch (resource) {
    case RLIMIT_DATA:
        /* not entirely accurate, but a reasonable approximation */
        rlim->rlim_cur = rlim->rlim_max =
                heap_total(heap_physical(get_kernel_heaps()));
        break;
    case RLIMIT_STACK:
        rlim->rlim_cur = current->p->rlimit_stack;
        rlim->rlim_max = infinity;
        break;
    case RLIMIT_CORE:
        rlim->rlim_cur = rlim->rlim_max = 0;    // core dump not supported
        break;
    case RLIMIT_NOFILE:
        rlim->rlim_cur = current->p->rlimit_nofile_cur;
        rlim->rlim_max = current->p->rlimit_nofile_max;
        break;
    case RLIMIT_AS:
        rlim->rlim_cur = rlim->rlim_max = heap_total(current->p->vm->virtual);
        break;
    case RLIMIT_NPROC:
        rlim->rlim_cur = current->p->rlimit_nproc_cur;
        rlim->rlim_max = current->p->rlimit_nproc_max;
        break;
    default:
        rv = -EINVAL;
    }

    context_clear_err(ctx);
    return rv;
}

sysreturn prlimit64(int pid, int resource, const struct rlimit *new_limit, struct rlimit *old_limit)
{
    if (old_limit) {
        sysreturn ret = getrlimit(resource, old_limit);
        if (ret < 0)
            return ret;
    }

    if (new_limit)
        return setrlimit(resource, new_limit);
    return 0;
}

static sysreturn getrusage(int who, struct rusage *usage)
{
    context ctx = get_current_context(current_cpu());
    if (!memory_is_user(usage, sizeof(*usage)) || context_set_err(ctx))
        return -EFAULT;
    zero(usage, sizeof(*usage));
    sysreturn rv = 0;
    switch (who) {
        case RUSAGE_SELF:
            timeval_from_time(&usage->ru_utime, proc_utime(current->p));
            timeval_from_time(&usage->ru_stime, proc_stime(current->p));
            break;
        case RUSAGE_CHILDREN:
            timeval_from_time(&usage->ru_utime, current->p->cutime);
            timeval_from_time(&usage->ru_stime, current->p->cstime);
            break;
        case RUSAGE_THREAD:
            timeval_from_time(&usage->ru_utime, thread_utime(current));
            timeval_from_time(&usage->ru_stime, thread_stime(current));
            break;
        default:
            rv = -EINVAL;
    }
    context_clear_err(ctx);
    return rv;
}

static sysreturn getcwd(char *buf, u64 length)
{
    if (!fault_in_user_memory(buf, length, true))
        return -EFAULT;
    process p = current->p;
    int cwd_len = file_get_path(p->cwd_fs, p->cwd, buf, length);

    if (cwd_len < 0)
        return set_syscall_error(current, ERANGE);

    return cwd_len;
}

static sysreturn brk(void *addr)
{
    process p = current->p;
    process_lock(p);

    /* on failure, return the current break */
    if (!addr || p->vm->brk == addr)
        goto out;

    u64 old_end = pad(u64_from_pointer(p->vm->brk), PAGESIZE);
    u64 new_end = pad(u64_from_pointer(addr), PAGESIZE);
    if (old_end > new_end) {
        if (u64_from_pointer(addr) < p->vm->heap_base ||
            !adjust_process_heap(p, irange(p->vm->heap_base, new_end)))
            goto out;
        smp_write_barrier();
        address_space_unmap_and_free_phys(p->vm->as, new_end, old_end - new_end);
    } else if (new_end > old_end) {
        u64 alloc = new_end - old_end;
        if (!memory_is_user(pointer_from_u64(old_end), alloc) ||
            !adjust_process_heap(p, irange(p->vm->heap_base, new_end)))
            goto out;
    }
    p->vm->brk = addr;
  out:
    addr = p->vm->brk;
    process_unlock(p);
    return sysreturn_from_pointer(addr);
}

static sysreturn readlink_internal(filesystem fs, inode cwd, sstring pathname, char *buf,
        u64 bufsiz)
{
    if (!fault_in_user_memory(buf, bufsiz, true)) {
        return set_syscall_error(current, EFAULT);
    }
    tuple n;
    int fss = filesystem_get_node(&fs, cwd, pathname, 0, &n, 0, 0);
    if (fss != 0)
        return fss;
    sysreturn rv;
    int pid, fd;
    if (procfs_fd_link(n, &pid, &fd)) {
        filesystem_put_node(fs, n);
        buffer target = allocate_buffer(heap_locked(get_kernel_heaps()), 64);
        if (target == INVALID_ADDRESS)
            return -ENOMEM;
        rv = procfs_fd_readlink(pid, fd, target);
        if (rv == 0) {
            rv = MIN(bufsiz, buffer_length(target));
            runtime_memcpy(buf, buffer_ref(target, 0), rv);
        }
        deallocate_buffer(target);
        return rv;
    }
    if (is_symlink(n)) {
        buffer target = linktarget(n);
        bytes len = buffer_length(target);
        if (bufsiz < len)
            len = bufsiz;
        runtime_memcpy(buf, buffer_ref(target, 0), len);
        rv = len;
    } else {
        rv = -EINVAL;
    }
    filesystem_put_node(fs, n);
    return rv;
}

sysreturn readlink(const char *pathname, char *buf, u64 bufsiz)
{
    sstring pathname_ss;
    if (!fault_in_user_string(pathname, &pathname_ss))
        return -EFAULT;
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = readlink_internal(cwd_fs, cwd, pathname_ss, buf, bufsiz);
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn readlinkat(int dirfd, const char *pathname, char *buf, u64 bufsiz)
{
    sstring pathname_ss;
    filesystem fs;
    inode cwd = resolve_dir(fs, dirfd, pathname, pathname_ss);
    sysreturn rv = readlink_internal(fs, cwd, pathname_ss, buf, bufsiz);
    filesystem_release(fs);
    return rv;
}

sysreturn unlink(const char *pathname)
{
    sstring pathname_ss;
    if (!fault_in_user_string(pathname, &pathname_ss))
        return -EFAULT;
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = filesystem_delete(cwd_fs, cwd, pathname_ss, false);
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn unlinkat(int dirfd, const char *pathname, int flags)
{
    if (flags & ~AT_REMOVEDIR) {
        return set_syscall_error(current, EINVAL);
    }
    sstring path_ss;
    filesystem fs;
    inode cwd = resolve_dir(fs, dirfd, pathname, path_ss);
    sysreturn rv;
    rv = filesystem_delete(fs, cwd, path_ss, !!(flags & AT_REMOVEDIR));
    filesystem_release(fs);
    return rv;
}

sysreturn rmdir(const char *pathname)
{
    sstring pathname_ss;
    if (!fault_in_user_string(pathname, &pathname_ss))
        return -EFAULT;
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = filesystem_delete(cwd_fs, cwd, pathname_ss, true);
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn rename(const char *oldpath, const char *newpath)
{
    sstring oldpath_ss, newpath_ss;
    if (!fault_in_user_string(oldpath, &oldpath_ss) || !fault_in_user_string(newpath, &newpath_ss))
        return -EFAULT;
    filesystem cwd_fs;
    inode cwd;
    process_get_cwd(current->p, &cwd_fs, &cwd);
    sysreturn rv = filesystem_rename(cwd_fs, cwd, oldpath_ss, cwd_fs, cwd, newpath_ss, false);
    filesystem_release(cwd_fs);
    return rv;
}

sysreturn renameat(int olddirfd, const char *oldpath, int newdirfd,
        const char *newpath)
{
    sstring oldpath_ss, newpath_ss;
    filesystem oldfs, newfs;
    inode oldwd = resolve_dir(oldfs, olddirfd, oldpath, oldpath_ss);
    inode newwd = resolve_dir(newfs, newdirfd, newpath, newpath_ss);
    sysreturn rv = filesystem_rename(oldfs, oldwd, oldpath_ss, newfs, newwd, newpath_ss, false);
    filesystem_release(oldfs);
    filesystem_release(newfs);
    return rv;
}

sysreturn renameat2(int olddirfd, const char *oldpath, int newdirfd,
        const char *newpath, unsigned int flags)
{
    if ((flags & ~(RENAME_EXCHANGE | RENAME_NOREPLACE)) ||
            ((flags & RENAME_EXCHANGE) && (flags & RENAME_NOREPLACE))) {
        return set_syscall_error(current, EINVAL);
    }
    sstring oldpath_ss, newpath_ss;
    filesystem oldfs, newfs;
    inode oldwd = resolve_dir(oldfs, olddirfd, oldpath, oldpath_ss);
    inode newwd = resolve_dir(newfs, newdirfd, newpath, newpath_ss);
    int fss;
    if (flags & RENAME_EXCHANGE) {
        fss = filesystem_exchange(oldfs, oldwd, oldpath_ss, newfs, newwd, newpath_ss);
    }
    else {
        fss = filesystem_rename(oldfs, oldwd, oldpath_ss, newfs, newwd, newpath_ss,
            !!(flags & RENAME_NOREPLACE));
    }
    filesystem_release(oldfs);
    filesystem_release(newfs);
    return fss;
}

/* File paths are treated as absolute paths. */
sysreturn fs_rename(sstring oldpath, sstring newpath)
{
    filesystem fs = get_root_fs();
    inode root = fs->get_inode(fs, filesystem_getroot(fs));
    return filesystem_rename(fs, root, oldpath, fs, root, newpath, false);
}

sysreturn close(int fd)
{
    fdesc f = resolve_fd(current->p, fd);
    deallocate_fd(current->p, fd);

    if (fetch_and_add(&f->refcnt, -2) == 2) {
        if (f->close)
            return apply(f->close, get_current_context(current_cpu()), syscall_io_complete);
        msg_err("close: no handler for fd %d", fd);
    }

    return 0;
}

sysreturn fcntl(int fd, int cmd, s64 arg)
{
    fdesc f = resolve_fd(current->p, fd);
    sysreturn rv = 0;

    fdesc_lock(f);
    switch (cmd) {
    case F_GETFD:
        rv = fdtable_get_fd_flags(current->p->fdtable, fd);
        break;
    case F_SETFD:
        rv = fdtable_set_fd_flags(current->p->fdtable, fd, arg & FD_CLOEXEC);
        break;
    case F_GETFL:
        rv = f->flags & ~O_CLOEXEC;
        break;
    case F_SETFL:
        /* Ignore file access mode and file creation flags. */
        arg &= ~(O_ACCMODE | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);

        f->flags = (f->flags & O_ACCMODE) | (arg & ~O_CLOEXEC);
        break;
    case F_GETLK:
        if (arg) {
            s16 l_type = F_UNLCK;
            if (!set_user_value(&((struct flock *)arg)->l_type, l_type))
                rv = -EFAULT;
        }
        break;
    case F_SETLK:
    case F_SETLKW:
        break;
    case F_DUPFD:
    case F_DUPFD_CLOEXEC: {
        if (arg < 0) {
            rv = -EINVAL;
            break;
        }
        int newfd = allocate_fd_gte(current->p, arg, f,
                                    (cmd == F_DUPFD_CLOEXEC) ? FD_CLOEXEC : 0);
        if (newfd == INVALID_PHYSICAL) {
            rv = -EMFILE;
        } else {
            fdesc_unlock(f);
            return newfd;
        }
        break;
    }
    case F_SETPIPE_SZ:
        if (f->type == FDESC_TYPE_PIPE) {
            rv = pipe_set_capacity(f, (int)arg);
        } else {
            rv = -EINVAL;
        }
        break;
    case F_GETPIPE_SZ:
        if (f->type == FDESC_TYPE_PIPE) {
            rv = pipe_get_capacity(f);
        } else {
            rv = -EINVAL;
        }
        break;
    case F_ADD_SEALS:
        if (f->type == FDESC_TYPE_REGULAR)
            rv = file_add_seals((file)f, (unsigned int)arg);
        else
            rv = -EINVAL;
        break;
    case F_GET_SEALS:
        if (f->type == FDESC_TYPE_REGULAR) {
            u64 seals;
            rv = fsfile_get_seals(((file)f)->fsf, &seals);
            if (rv == 0)
                rv = seals;
        } else {
            rv = -EINVAL;
        }
        break;
    default:
        rv = -ENOSYS;
    }
    fdesc_unlock(f);
    fdesc_put(f);
    return rv;
}

sysreturn ioctl_generic(fdesc f, unsigned long request, vlist ap)
{
    switch (request) {
    case FIONBIO: {
        int opt;
        if (!get_user_value(varg(ap, int *), &opt))
            return -EFAULT;
        fdesc_lock(f);
        if (opt) {
            f->flags |= O_NONBLOCK;
        }
        else {
            f->flags &= ~O_NONBLOCK;
        }
        fdesc_unlock(f);
        return 0;
    }
    case FIONCLEX:
    case FIOCLEX:
        return 0;
    default:
        return -ENOSYS;
    }
}

sysreturn ioctl(int fd, unsigned long request, ...)
{
    // checks if fd is valid
    fdesc f = resolve_fd(current->p, fd);

    vlist args;
    sysreturn rv;
    vstart(args, request);
    if (f->ioctl)
        rv = apply(f->ioctl, request, args);
    else
        rv = ioctl_generic(f, request, args);
    vend(args);
    fdesc_put(f);
    return rv;
}

sysreturn syscall_ignore()
{
    return 0;
}

sysreturn getpid()
{
    return current->p->pid;
}

sysreturn getppid()
{
    return process_getppid(current->p);
}

#define CAP_FS_SET ((1ull << 0) | (1ull << 1) | (1ull << 2) | (1ull << 3) | (1ull << 4) | \
                    (1ull << 9) | (1ull << 27) | (1ull << 32))

boolean creds_init(struct creds *c, u32 uid, u32 gid)
{
    zero(c, sizeof(*c));
    c->uid = c->euid = c->suid = c->fsuid = uid;
    c->gid = c->egid = c->sgid = c->fsgid = gid;
    c->cap_bset = CAP_FULL_SET;
    if (uid == 0)
        c->cap_permitted = c->cap_effective = CAP_FULL_SET;
    return true;
}

boolean creds_copy(struct creds *dst, struct creds *src)
{
    *dst = *src;
    if (!src->ngroups)
        return true;
    u64 size = src->ngroups * sizeof(u32);
    dst->groups = allocate(heap_locked(get_kernel_heaps()), size);
    if (dst->groups == INVALID_ADDRESS) {
        dst->groups = 0;
        dst->ngroups = 0;
        return false;
    }
    runtime_memcpy(dst->groups, src->groups, size);
    return true;
}

void creds_free(struct creds *c)
{
    if (c->ngroups)
        deallocate(heap_locked(get_kernel_heaps()), c->groups, c->ngroups * sizeof(u32));
    c->groups = 0;
    c->ngroups = 0;
}

void creds_snapshot(process p, struct creds *c)
{
    process_lock(p);
    *c = p->creds;
    process_unlock(p);
    c->groups = 0;
}

boolean capable(process p, int cap)
{
    process_lock(p);
    boolean r = !!(p->creds.cap_effective & (1ull << cap));
    process_unlock(p);
    return r;
}

static void creds_fix_caps_locked(struct creds *c, u32 old_uid, u32 old_euid, u32 old_suid,
                                  u32 old_fsuid)
{
    if ((old_uid == 0 || old_euid == 0 || old_suid == 0) &&
        (c->uid != 0 && c->euid != 0 && c->suid != 0)) {
        c->cap_permitted = c->cap_effective = c->cap_ambient = 0;
    }
    if (old_euid == 0 && c->euid != 0)
        c->cap_effective = 0;
    if (old_euid != 0 && c->euid == 0)
        c->cap_effective = c->cap_permitted;
    if (old_fsuid == 0 && c->fsuid != 0)
        c->cap_effective &= ~CAP_FS_SET;
    if (old_fsuid != 0 && c->fsuid == 0)
        c->cap_effective |= c->cap_permitted & CAP_FS_SET;
}

void creds_exec(process p)
{
    process_lock(p);
    struct creds *c = &p->creds;
    u64 old_permitted = c->cap_permitted;
    u64 permitted, effective;
    if (c->uid == 0 || c->euid == 0) {
        permitted = c->cap_bset | (c->cap_inheritable & c->cap_bset);
        effective = (c->euid == 0) ? permitted : 0;
        c->cap_ambient = 0;
    } else {
        permitted = effective = c->cap_ambient;
    }
    if (p->no_new_privs && (permitted & ~old_permitted)) {
        permitted &= old_permitted;
        effective &= permitted;
    }
    c->cap_permitted = permitted;
    c->cap_effective = effective;
    c->suid = c->fsuid = c->euid;
    c->sgid = c->fsgid = c->egid;
    process_unlock(p);
}

static inline boolean id_in(u32 id, u32 a, u32 b, u32 c)
{
    return id == a || id == b || id == c;
}

sysreturn getuid()
{
    process p = current->p;
    process_lock(p);
    u32 id = p->creds.uid;
    process_unlock(p);
    return id;
}

sysreturn geteuid()
{
    process p = current->p;
    process_lock(p);
    u32 id = p->creds.euid;
    process_unlock(p);
    return id;
}

sysreturn getgid()
{
    process p = current->p;
    process_lock(p);
    u32 id = p->creds.gid;
    process_unlock(p);
    return id;
}

sysreturn getegid()
{
    process p = current->p;
    process_lock(p);
    u32 id = p->creds.egid;
    process_unlock(p);
    return id;
}

static sysreturn getres_ids(u32 *ruid, u32 *euid, u32 *suid, boolean group)
{
    struct creds c;
    creds_snapshot(current->p, &c);
    u32 r = group ? c.gid : c.uid, e = group ? c.egid : c.euid, s = group ? c.sgid : c.suid;
    if (!copy_to_user(ruid, &r, sizeof(r)) || !copy_to_user(euid, &e, sizeof(e)) ||
        !copy_to_user(suid, &s, sizeof(s)))
        return -EFAULT;
    return 0;
}

static sysreturn getresuid(u32 *ruid, u32 *euid, u32 *suid)
{
    return getres_ids(ruid, euid, suid, false);
}

static sysreturn getresgid(u32 *rgid, u32 *egid, u32 *sgid)
{
    return getres_ids(rgid, egid, sgid, true);
}

static sysreturn set_ids(u32 nr, u32 ne, u32 ns, boolean is_setre, boolean group)
{
    process p = current->p;
    boolean priv = capable(p, group ? CAP_SETGID : CAP_SETUID);
    process_lock(p);
    struct creds *c = &p->creds;
    u32 *r = group ? &c->gid : &c->uid, *e = group ? &c->egid : &c->euid;
    u32 *s = group ? &c->sgid : &c->suid, *fs = group ? &c->fsgid : &c->fsuid;
    if (!priv) {
        boolean ok;
        if (is_setre)
            ok = (nr == -1 || nr == *r || nr == *e) && (ne == -1 || id_in(ne, *r, *e, *s));
        else
            ok = (nr == -1 || id_in(nr, *r, *e, *s)) && (ne == -1 || id_in(ne, *r, *e, *s)) &&
                 (ns == -1 || id_in(ns, *r, *e, *s));
        if (!ok) {
            process_unlock(p);
            return -EPERM;
        }
    }
    u32 old_uid = c->uid, old_euid = c->euid, old_suid = c->suid, old_fsuid = c->fsuid;
    u32 old_r = *r;
    if (nr != -1)
        *r = nr;
    if (ne != -1)
        *e = ne;
    if (is_setre) {
        if (nr != -1 || (ne != -1 && ne != old_r))
            *s = *e;
    } else if (ns != -1) {
        *s = ns;
    }
    *fs = *e;
    if (!group)
        creds_fix_caps_locked(c, old_uid, old_euid, old_suid, old_fsuid);
    process_unlock(p);
    return 0;
}

static sysreturn set_id(u32 id, boolean group)
{
    if (id == -1)
        return -EINVAL;
    process p = current->p;
    if (capable(p, group ? CAP_SETGID : CAP_SETUID))
        return set_ids(id, id, id, false, group);
    struct creds c;
    creds_snapshot(p, &c);
    if (id != (group ? c.gid : c.uid) && id != (group ? c.sgid : c.suid))
        return -EPERM;
    return set_ids(-1, id, -1, false, group);
}

static sysreturn setuid(u32 uid)
{
    return set_id(uid, false);
}

static sysreturn setgid(u32 gid)
{
    return set_id(gid, true);
}

static sysreturn setreuid(u32 ruid, u32 euid)
{
    return set_ids(ruid, euid, -1, true, false);
}

static sysreturn setregid(u32 rgid, u32 egid)
{
    return set_ids(rgid, egid, -1, true, true);
}

static sysreturn setresuid(u32 ruid, u32 euid, u32 suid)
{
    return set_ids(ruid, euid, suid, false, false);
}

static sysreturn setresgid(u32 rgid, u32 egid, u32 sgid)
{
    return set_ids(rgid, egid, sgid, false, true);
}

static sysreturn set_fsid(u32 id, boolean group)
{
    process p = current->p;
    boolean priv = capable(p, group ? CAP_SETGID : CAP_SETUID);
    process_lock(p);
    struct creds *c = &p->creds;
    u32 *fs = group ? &c->fsgid : &c->fsuid;
    u32 old = *fs;
    if (id != -1 && (priv || id_in(id, group ? c->gid : c->uid, group ? c->egid : c->euid,
                                   group ? c->sgid : c->suid) || id == old)) {
        *fs = id;
        if (!group)
            creds_fix_caps_locked(c, c->uid, c->euid, c->suid, old);
    }
    process_unlock(p);
    return old;
}

static sysreturn setfsuid(u32 fsuid)
{
    return set_fsid(fsuid, false);
}

static sysreturn setfsgid(u32 fsgid)
{
    return set_fsid(fsgid, true);
}

static sysreturn getgroups(int size, u32 *list)
{
    if (size < 0)
        return -EINVAL;
    process p = current->p;
    heap h = heap_locked(get_kernel_heaps());
    process_lock(p);
    u32 n = p->creds.ngroups;
    if (size == 0 || n == 0) {
        process_unlock(p);
        return n;
    }
    if (size < n) {
        process_unlock(p);
        return -EINVAL;
    }
    u32 *copy = allocate(h, n * sizeof(u32));
    if (copy == INVALID_ADDRESS) {
        process_unlock(p);
        return -ENOMEM;
    }
    runtime_memcpy(copy, p->creds.groups, n * sizeof(u32));
    process_unlock(p);
    sysreturn rv = copy_to_user(list, copy, n * sizeof(u32)) ? n : -EFAULT;
    deallocate(h, copy, n * sizeof(u32));
    return rv;
}

static sysreturn setgroups(int size, const u32 *list)
{
    if (size < 0 || size > NGROUPS_MAX)
        return -EINVAL;
    process p = current->p;
    if (!capable(p, CAP_SETGID))
        return -EPERM;
    heap h = heap_locked(get_kernel_heaps());
    u32 *groups = 0;
    if (size) {
        groups = allocate(h, size * sizeof(u32));
        if (groups == INVALID_ADDRESS)
            return -ENOMEM;
        if (!copy_from_user(list, groups, size * sizeof(u32))) {
            deallocate(h, groups, size * sizeof(u32));
            return -EFAULT;
        }
        for (int i = 1; i < size; i++)
            for (int j = i; j > 0 && groups[j - 1] > groups[j]; j--) {
                u32 tmp = groups[j];
                groups[j] = groups[j - 1];
                groups[j - 1] = tmp;
            }
    }
    process_lock(p);
    u32 *old = p->creds.groups;
    u32 old_n = p->creds.ngroups;
    p->creds.groups = groups;
    p->creds.ngroups = size;
    process_unlock(p);
    if (old_n)
        deallocate(h, old, old_n * sizeof(u32));
    return 0;
}

sysreturn sched_yield()
{
    thread_yield();             /* noreturn */
}

static void __attribute__((noreturn)) exit_current_thread(int code)
{
    process p = current->p;
    if (exit_thread(current)) {
        if (process_is_init(p))
            kernel_shutdown(code);
        process_lock(p);
        if (!p->exiting) {
            p->exiting = true;
            p->wait_status = wait_status_exited(code);
        }
        process_unlock(p);
        process_teardown(p);
    }
    syscall_finish(true);
}

sysreturn exit_group(int status)
{
    process p = current->p;
    if (process_is_init(p))
        kernel_shutdown(status);
    process_kill(p, wait_status_exited(status));
    exit_current_thread(status);
}

void exit(int code)
{
    exit_current_thread(code);
}

sysreturn pipe2(int fds[2], int flags)
{
    if (!fault_in_user_memory(fds, 2 * sizeof(int), true))
        return set_syscall_error(current, EFAULT);
    if (flags & ~(O_CLOEXEC | O_NONBLOCK))
        return set_syscall_error(current, EINVAL);

    return do_pipe2(fds, flags);
}

sysreturn pipe(int fds[2])
{
    return pipe2(fds, 0);
}

sysreturn eventfd(unsigned int count)
{
    return do_eventfd2(count, 0);
}

sysreturn eventfd2(unsigned int count, int flags)
{
    return do_eventfd2(count, flags);
}

static thread lookup_thread(int pid)
{
    thread t;
    if (pid== 0) {
        t = current;
        thread_reserve(t);
    } else {
        if ((t = thread_from_tid(current->p, pid)) == INVALID_ADDRESS)
            return 0;
    }
    return t;
}

sysreturn sched_setaffinity(int pid, u64 cpusetsize, u64 *mask)
{
    context ctx = get_current_context(current_cpu());
    u64 first_cpu = -1ull;
    u64 i;
    if (!memory_is_user(mask, cpusetsize) || context_set_err(ctx))
        return -EFAULT;
    for (i = 0; (first_cpu == -1ull) && (i + sizeof(u64) <= cpusetsize); i += sizeof(u64))
        first_cpu = i * 8 + lsb(mask[i / sizeof(u64)]);
    for (; (first_cpu == -1ull) && (i < cpusetsize); i++)
        first_cpu = i * 8 + lsb(((u8 *)mask)[i]);
    context_clear_err(ctx);
    if (first_cpu >= total_processors)
        return -EINVAL;
    thread t;
    if (!(t = lookup_thread(pid)))
            return set_syscall_error(current, EINVAL);
    cpusetsize = MIN(cpusetsize, pad(total_processors, 8) / 8);
    bitmap affinity = t->task.affinity;
    sysreturn rv;
    thread_lock(t);
    if (context_set_err(ctx)) {
        rv = -EFAULT;
        goto out;
    }
    runtime_memcpy(bitmap_base(affinity), mask, cpusetsize);
    context_clear_err(ctx);
    u64 cpus = cpusetsize * 8;
    if (cpus < total_processors)
        bitmap_range_check_and_set(affinity, cpus, total_processors - cpus, false, false);

    /* If the thread has last run on a non-affine CPU, move it to the first CPU in the affinity
     * mask. Note: this does not guarantee that the thread is migrated immediately to the affine CPU
     * (e.g. if it's already enqueued in its current scheduling queue it will most likely do another
     * run on its current CPU), but the migration will happen the next time the thread is scheduled
     * to run. */
    cpuinfo ci = struct_from_field(t->scheduling_queue, cpuinfo, thread_queue);
    if (!bitmap_get(affinity, ci->id))
        t->scheduling_queue = &cpuinfo_from_id(first_cpu)->thread_queue;

    rv = 0;
  out:
    thread_unlock(t);
    thread_release(t);
    return rv;
}

sysreturn sched_getaffinity(int pid, u64 cpusetsize, u64 *mask)
{
    if (!fault_in_user_memory(mask, cpusetsize, true))
        return set_syscall_error(current, EFAULT);
    thread t;
    if (64 * (cpusetsize / sizeof(u64)) < total_processors)
        return set_syscall_error(current, EINVAL);
    if (!(t = lookup_thread(pid)))
        return set_syscall_error(current, EINVAL);
    cpusetsize = pad(total_processors, 64) / 8;
    thread_lock(t);
    runtime_memcpy(mask, bitmap_base(t->task.affinity), cpusetsize);
    thread_unlock(t);
    thread_release(t);
    return cpusetsize;
}

static sysreturn cap_header(cap_user_header_t hdrp, int *copies, int *pid)
{
    struct user_cap_header hdr;
    if (!copy_from_user(hdrp, &hdr, sizeof(hdr)))
        return -EFAULT;
    switch (hdr.version) {
    case _LINUX_CAPABILITY_VERSION_1:
        *copies = 1;
        break;
    case _LINUX_CAPABILITY_VERSION_2:
    case _LINUX_CAPABILITY_VERSION_3:
        *copies = 2;
        break;
    default:
        hdr.version = _LINUX_CAPABILITY_VERSION_3;
        if (!copy_to_user(&hdrp->version, &hdr.version, sizeof(hdr.version)))
            return -EFAULT;
        return -EINVAL;
    }
    *pid = hdr.pid;
    return 0;
}

static sysreturn capget(cap_user_header_t hdrp, cap_user_data_t datap)
{
    int copies, pid;
    sysreturn rv = cap_header(hdrp, &copies, &pid);
    if (!datap)
        return (rv == -EINVAL) ? 0 : rv;
    if (rv)
        return rv;
    if (pid < 0)
        return -EINVAL;
    process p = current->p;
    struct creds c;
    if (pid == 0 || pid == p->pid) {
        creds_snapshot(p, &c);
    } else {
        process target = process_get(pid);
        if (!target)
            return -ESRCH;
        creds_snapshot(target, &c);
        process_release(target);
    }
    struct user_cap_data data[2];
    for (int i = 0; i < 2; i++) {
        data[i].effective = c.cap_effective >> (32 * i);
        data[i].permitted = c.cap_permitted >> (32 * i);
        data[i].inheritable = c.cap_inheritable >> (32 * i);
    }
    if (!copy_to_user(datap, data, copies * sizeof(data[0])))
        return -EFAULT;
    return 0;
}

static sysreturn capset(cap_user_header_t hdrp, const cap_user_data_t datap)
{
    int copies, pid;
    sysreturn rv = cap_header(hdrp, &copies, &pid);
    if (rv)
        return rv;
    process p = current->p;
    if (pid != 0 && pid != p->pid)
        return -EPERM;
    struct user_cap_data data[2];
    zero(data, sizeof(data));
    if (!copy_from_user(datap, data, copies * sizeof(data[0])))
        return -EFAULT;
    u64 effective = (data[0].effective | ((u64)data[1].effective << 32)) & CAP_FULL_SET;
    u64 permitted = (data[0].permitted | ((u64)data[1].permitted << 32)) & CAP_FULL_SET;
    u64 inheritable = (data[0].inheritable | ((u64)data[1].inheritable << 32)) & CAP_FULL_SET;
    process_lock(p);
    struct creds *c = &p->creds;
    boolean setpcap = !!(c->cap_effective & (1ull << CAP_SETPCAP));
    if ((!setpcap && (inheritable & ~(c->cap_inheritable | c->cap_permitted))) ||
        (inheritable & ~(c->cap_inheritable | c->cap_bset)) ||
        (permitted & ~c->cap_permitted) || (effective & ~permitted)) {
        process_unlock(p);
        return -EPERM;
    }
    c->cap_effective = effective;
    c->cap_permitted = permitted;
    c->cap_inheritable = inheritable;
    c->cap_ambient &= permitted & inheritable;
    process_unlock(p);
    return 0;
}

static sysreturn wait4(int pid, int *wstatus, int options, struct rusage *rusage)
{
    if (options & ~(WNOHANG | WUNTRACED | WCONTINUED | __WNOTHREAD | __WCLONE | __WALL))
        return -EINVAL;
    if (pid == S32_MIN)
        return -ESRCH;
    if ((wstatus && !validate_process_memory(current->p, wstatus, sizeof(*wstatus), true)) ||
        (rusage && !validate_process_memory(current->p, rusage, sizeof(*rusage), true)))
        return -EFAULT;
    int idtype = P_ALL, id = 0;
    if (pid > 0) {
        idtype = P_PID;
        id = pid;
    } else if (pid == 0) {
        idtype = P_PGID;
        id = current->p->pgid;
    } else if (pid < -1) {
        idtype = P_PGID;
        id = -pid;
    }
    return process_wait(idtype, id, options | WEXITED, wstatus, 0, rusage, true);
}

static sysreturn waitid(int idtype, int id, struct siginfo *infop, int options,
                        struct rusage *rusage)
{
    if (options & ~(WNOHANG | WNOWAIT | WEXITED | WSTOPPED | WCONTINUED | __WNOTHREAD | __WCLONE | __WALL))
        return -EINVAL;
    if (!(options & (WEXITED | WSTOPPED | WCONTINUED)))
        return -EINVAL;
    switch (idtype) {
    case P_ALL:
        break;
    case P_PGID:
        if (id < 0)
            return -EINVAL;
        if (id == 0)
            id = current->p->pgid;
        break;
    case P_PID:
        if (id <= 0)
            return -EINVAL;
        break;
    case P_PIDFD:
        return -EBADF;
    default:
        return -EINVAL;
    }
    if ((infop && !validate_process_memory(current->p, infop, sizeof(*infop), true)) ||
        (rusage && !validate_process_memory(current->p, rusage, sizeof(*rusage), true)))
        return -EFAULT;
    return process_wait(idtype, id, options, 0, infop, rusage, false);
}

static sysreturn prctl_set_ptracer(u64 arg2)
{
    int ptracer;
    if (arg2 == 0 || arg2 == PR_SET_PTRACER_ANY) {
        ptracer = (int)arg2;
    } else {
        if (arg2 > S32_MAX)
            return -EINVAL;
        process tracer = process_get(arg2);
        if (!tracer)
            return -EINVAL;
        process_release(tracer);
        ptracer = arg2;
    }
    process p = current->p;
    process_lock(p);
    p->ptracer = ptracer;
    process_unlock(p);
    return 0;
}

static sysreturn prctl(int option, u64 arg2, u64 arg3, u64 arg4, u64 arg5)
{
    process p = current->p;
    switch (option) {
    case PR_SET_PDEATHSIG:
        if (arg2 > NSIG)
            return -EINVAL;
        process_lock(p);
        p->pdeathsig = arg2;
        process_unlock(p);
        return 0;
    case PR_GET_PDEATHSIG: {
        process_lock(p);
        int sig = p->pdeathsig;
        process_unlock(p);
        return copy_to_user((void *)arg2, &sig, sizeof(sig)) ? 0 : -EFAULT;
    }
    case PR_SET_NAME:
        if (!copy_from_user((void *)arg2, current->name, sizeof(current->name)))
            return -EFAULT;
        current->name[sizeof(current->name) - 1] = '\0';
        return 0;
    case PR_GET_NAME:
        if (!copy_to_user((void *)arg2, current->name, sizeof(current->name)))
            return -EFAULT;
        return 0;
    case PR_GET_DUMPABLE:
        return p->dumpable;
    case PR_SET_DUMPABLE:
        if (arg2 > 1)
            return -EINVAL;
        p->dumpable = arg2;
        return 0;
    case PR_SET_NO_NEW_PRIVS:
        if (arg2 != 1 || arg3 || arg4 || arg5)
            return -EINVAL;
        process_lock(p);
        p->no_new_privs = true;
        process_unlock(p);
        return 0;
    case PR_GET_NO_NEW_PRIVS:
        if (arg2 || arg3 || arg4 || arg5)
            return -EINVAL;
        return p->no_new_privs;
    case PR_CAPBSET_READ:
        if (arg2 > CAP_LAST_CAP)
            return -EINVAL;
        process_lock(p);
        sysreturn bit = !!(p->creds.cap_bset & (1ull << arg2));
        process_unlock(p);
        return bit;
    case PR_CAPBSET_DROP:
        if (arg2 > CAP_LAST_CAP)
            return -EINVAL;
        if (!capable(p, CAP_SETPCAP))
            return -EPERM;
        process_lock(p);
        p->creds.cap_bset &= ~(1ull << arg2);
        process_unlock(p);
        return 0;
    case PR_SET_PTRACER:
        return prctl_set_ptracer(arg2);
    case PR_SET_SECCOMP:
        return seccomp_prctl(arg2, (void *)arg3);
    case PR_GET_SECCOMP:
        return current->seccomp_mode;
    default:
        return -EINVAL;
    }
}

sysreturn sysinfo(struct sysinfo *info)
{
    context ctx = get_current_context(current_cpu());
    if (!memory_is_user(info, sizeof(struct sysinfo)) || context_set_err(ctx))
        return set_syscall_error(current, EFAULT);

    kernel_heaps kh = get_kernel_heaps();
    runtime_memset((u8 *) info, 0, sizeof(*info));
    info->uptime = sec_from_timestamp(uptime());
    info->totalram = heap_total((heap)kh->physical);
    u64 allocated = heap_allocated((heap)kh->physical);
    info->freeram = info->totalram < allocated ? 0 : info->totalram - allocated;
    info->procs = 1;
    info->mem_unit = 1;
    context_clear_err(ctx);
    return 0;
}

sysreturn umask(int mask)
{
    return mask;
}

sysreturn getcpu(unsigned int *cpu, unsigned int *node, void *tcache)
{
    cpuinfo ci = current_cpu();
    context ctx = get_current_context(ci);
    if ((cpu != 0 && !memory_is_user(cpu, sizeof(*cpu))) ||
        (node != 0 && !memory_is_user(node, sizeof(*node))) ||
        context_set_err(ctx))
        return -EFAULT;
    if (cpu)
        *cpu = ci->id;
    /* XXX to do */
    if (node)
        *node = 0;
    context_clear_err(ctx);
    return 0;
}

void register_file_syscalls(struct syscall *map)
{
    register_syscall(map, read, read);
    register_syscall(map, pread64, pread);
    register_syscall(map, write, write);
    register_syscall(map, pwrite64, pwrite);
#ifdef __x86_64__
    register_syscall(map, open, open);
    register_syscall(map, dup2, dup2);
    register_syscall(map, stat, stat);
    register_syscall(map, lstat, lstat);
    register_syscall(map, access, access);
    register_syscall(map, readlink, readlink);
    register_syscall(map, unlink, unlink);
    register_syscall(map, rmdir, rmdir);
    register_syscall(map, rename, rename);
    register_syscall(map, getdents, getdents);
    register_syscall(map, mkdir, mkdir);
    register_syscall(map, pipe, pipe);
    register_syscall(map, eventfd, eventfd);
    register_syscall(map, creat, creat);
    register_syscall(map, utime, utime);
    register_syscall(map, utimes, utimes);
    register_syscall(map, chown, syscall_ignore);
    register_syscall(map, link, link);
    register_syscall(map, symlink, symlink);
    register_syscall(map, inotify_init, inotify_init);
#endif
    register_syscall(map, inotify_init1, inotify_init1);
    register_syscall(map, inotify_add_watch, inotify_add_watch);
    register_syscall(map, inotify_rm_watch, inotify_rm_watch);
    register_syscall(map, openat, openat);
    register_syscall(map, dup, dup);
    register_syscall(map, dup3, dup3);
    register_syscall(map, fallocate, fallocate);
    register_syscall(map, faccessat, faccessat);
    register_syscall(map, fadvise64, fadvise64);
    register_syscall(map, fstat, fstat);
    register_syscall(map, newfstatat, newfstatat);
    register_syscall(map, statx, statx);
    register_syscall(map, readv, readv);
    register_syscall(map, writev, writev);
    register_syscall(map, preadv, preadv);
    register_syscall(map, pwritev, pwritev);
    register_syscall(map, sendfile, sendfile);
    register_syscall(map, truncate, truncate);
    register_syscall(map, ftruncate, ftruncate);
    register_syscall(map, fdatasync, fdatasync);
    register_syscall(map, fsync, fsync);
    register_syscall(map, sync, sync);
    register_syscall(map, syncfs, syncfs);
    register_syscall(map, io_setup, io_setup);
    register_syscall(map, io_submit, io_submit);
    register_syscall(map, io_getevents, io_getevents);
    register_syscall(map, io_destroy, io_destroy);
    register_syscall(map, lseek, lseek);
    register_syscall(map, fcntl, fcntl);
    register_syscall(map, ioctl, (sysreturn (*)())ioctl);
    register_syscall(map, getcwd, getcwd);
    register_syscall(map, linkat, linkat);
    register_syscall(map, symlinkat, symlinkat);
    register_syscall(map, readlinkat, readlinkat);
    register_syscall(map, unlinkat, unlinkat);
    register_syscall(map, renameat, renameat);
    register_syscall(map, renameat2, renameat2);
    register_syscall(map, utimensat, utimensat);
    register_syscall(map, close, close);
    register_syscall(map, sched_yield, sched_yield);
    register_syscall(map, brk, brk);
    register_syscall(map, uname, uname);
    register_syscall(map, getrlimit, getrlimit);
    register_syscall(map, setrlimit, setrlimit);
    register_syscall(map, prlimit64, prlimit64);
    register_syscall(map, getrusage, getrusage);
    register_syscall(map, getpid, getpid);
    register_syscall(map, getppid, getppid);
    register_syscall(map, exit_group, exit_group);
    register_syscall(map, exit, (sysreturn (*)())exit);
    register_syscall(map, getdents64, getdents64);
    register_syscall(map, mkdirat, mkdirat);
    register_syscall(map, getrandom, getrandom);
    register_syscall(map, membarrier, membarrier);
    register_syscall(map, copy_file_range, copy_file_range);
    register_syscall(map, pipe2, pipe2);
    register_syscall(map, socketpair, socketpair);
    register_syscall(map, eventfd2, eventfd2);
    register_syscall(map, chdir, chdir);
    register_syscall(map, fchdir, fchdir);
    register_syscall(map, setxattr, setxattr);
    register_syscall(map, lsetxattr, lsetxattr);
    register_syscall(map, fsetxattr, fsetxattr);
    register_syscall(map, getxattr, getxattr);
    register_syscall(map, lgetxattr, lgetxattr);
    register_syscall(map, fgetxattr, fgetxattr);
    register_syscall(map, sched_getaffinity, sched_getaffinity);
    register_syscall(map, sched_setaffinity, sched_setaffinity);
    register_syscall(map, sched_get_priority_min, syscall_ignore);
    register_syscall(map, sched_get_priority_max, syscall_ignore);
    register_syscall(map, sched_setscheduler, syscall_ignore);
    register_syscall(map, getuid, getuid);
    register_syscall(map, geteuid, geteuid);
    register_syscall(map, getresuid, getresuid);
    register_syscall(map, getresgid, getresgid);
    register_syscall(map, getgroups, getgroups);
    register_syscall(map, setgroups, setgroups);
    register_syscall(map, setuid, setuid);
    register_syscall(map, setgid, setgid);
    register_syscall(map, setreuid, setreuid);
    register_syscall(map, setregid, setregid);
    register_syscall(map, setresuid, setresuid);
    register_syscall(map, setresgid, setresgid);
    register_syscall(map, setfsuid, setfsuid);
    register_syscall(map, setfsgid, setfsgid);
    register_syscall(map, capget, capget);
    register_syscall(map, capset, capset);
    register_syscall(map, prctl, prctl);
    register_syscall(map, seccomp, seccomp);
    register_syscall(map, wait4, wait4);
    register_syscall(map, waitid, waitid);
    register_syscall(map, sysinfo, sysinfo);
    register_syscall(map, umask, umask);
    register_syscall(map, statfs, statfs);
    register_syscall(map, fstatfs, fstatfs);
    register_syscall(map, io_uring_setup, io_uring_setup);
    register_syscall(map, io_uring_enter, io_uring_enter);
    register_syscall(map, io_uring_register, io_uring_register);
    register_syscall(map, getcpu, getcpu);
}


struct syscall {
    void *handler;
};

static struct syscall _linux_syscalls[SYS_MAX];
struct syscall * const linux_syscalls = _linux_syscalls;

static void syscall_context_pause(context ctx)
{
    syscall_context sc = (syscall_context)ctx;
    syscall_accumulate_stime(sc);
    context_release_refcount(ctx);
}

static void syscall_context_resume(context ctx)
{
    syscall_context sc = (syscall_context)ctx;
    assert(sc->start_time == 0); // XXX tmp debug
    timestamp here = now(CLOCK_ID_MONOTONIC_RAW);
    sc->start_time = here == 0 ? 1 : here;
    context_reserve_refcount(ctx);
}

static void syscall_context_pre_suspend(context ctx)
{
    check_syscall_context_replace(current_cpu(), ctx);
}

syscall_context allocate_syscall_context(cpuinfo ci)
{
    build_assert((SYSCALL_CONTEXT_SIZE & (SYSCALL_CONTEXT_SIZE - 1)) == 0);
    heap h = heap_locked(get_kernel_heaps());
    u32 alloc_flags = MEM_NOWAIT;   /* this function can be called when suspending a context */
    syscall_context sc = mem_alloc(h, SYSCALL_CONTEXT_SIZE, alloc_flags);
    if (sc == INVALID_ADDRESS)
        return sc;
    context c = &sc->uc.kc.context;
    if (!init_unix_context(&sc->uc, CONTEXT_TYPE_SYSCALL, SYSCALL_CONTEXT_SIZE,
                           ci->free_syscall_contexts, alloc_flags)) {
        deallocate(h, sc, SYSCALL_CONTEXT_SIZE);
        return INVALID_ADDRESS;
    }
    c->pause = syscall_context_pause;
    c->resume = syscall_context_resume;
    c->pre_suspend = syscall_context_pre_suspend;
    return sc;
}

void syscall_dispatch(thread t, syscall_context sc, context_frame f)
{
    if (shutting_down & SHUTDOWN_ONGOING)
        return;
    context ctx = &sc->uc.kc.context;
    sysreturn rv = -ENOSYS;
    boolean skip = seccomp_check(t, f, &rv);
    if (!skip) {
        u64 call = (u64)(u32)f[FRAME_VECTOR];
        if (call < SYS_MAX) {
            struct syscall *s = t->p->syscalls + call;
            sysreturn (*h)(u64, u64, u64, u64, u64, u64) = s->handler;
            if (h) {
                t->syscall_complete = false;
                context_reserve_refcount(ctx);
                u64 arg0 = f[SYSCALL_FRAME_ARG0];
                rv = h(arg0, f[SYSCALL_FRAME_ARG1], f[SYSCALL_FRAME_ARG2],
                       f[SYSCALL_FRAME_ARG3], f[SYSCALL_FRAME_ARG4], f[SYSCALL_FRAME_ARG5]);
                assert(ctx->refcount.c > 1);
                context_release_refcount(ctx);
                set_syscall_return(t, rv);
                return;
            }
        }
    }
    set_syscall_return(t, rv);
}
void syscall_handler(thread t)
{
    /* The syscall_context stored in ci was set as current on syscall entry in
       order to get a usable stack. We still need to finish initializing it
       and complete the context switch. */
    cpuinfo ci = current_cpu();
    ci->state = cpu_kernel;
    assert(is_thread_context(&t->context));
    context_frame f = thread_frame(t);
    f[FRAME_FULL] = true;
    thread_reserve(t); /* frame save reference */
    u64 call = (u64)(u32)f[FRAME_VECTOR];
    syscall_restart_arch_setup(f);
    syscall_context sc = (syscall_context)get_current_context(ci);
    context ctx = &sc->uc.kc.context;
    assert(is_syscall_context(ctx));
    sc->t = t;
    ctx->fault_handler = t->context.fault_handler;
    ctx->as = t->context.as;
    sc->start_time = 0;
    sc->call = (int)call;
    assert(ctx->refcount.c == 1);
    t->syscall = sc;
    context_pause(&t->context);
    context_release(&t->context);
    context_resume(ctx);
    syscall_dispatch(t, sc, f);
    t->syscall = 0;
    schedule_thread(t);
    kern_yield();
}

// should hang off the thread context, but the assembly handler needs
// to find it.
BSS_RO_AFTER_INIT void (*syscall)(thread t);

closure_func_basic(io_completion, void, syscall_io_complete_cfn,
                   sysreturn rv)
{
    thread t = ((syscall_context)get_current_context(current_cpu()))->t;
    syscall_return(t, rv);
}

closure_func_basic(buffer_handler, status, hostname_done,
                   buffer b)
{
    hostname = b;

    /* Remove trailing CR and LF, if any. */
    while (buffer_length(hostname) > 0) {
        char last_char = *(char *)(buffer_end(hostname) - 1);
        if ((last_char == '\r') || (last_char == '\n'))
            hostname->end--;
        else
            break;
    }

    closure_finish();
    return STATUS_OK;
}

closure_func_basic(io_completion, void, io_complete_ignore,
                   sysreturn rv)
{
}

static const sstring missing_files_exclude[] = {
    ss_static_init("ld.so.cache"),
};

closure_func_basic(shutdown_handler, void, print_missing_files_cfn,
                   int status, merge m)
{
    buffer b;
    rprintf("missing_files_begin\n");
    vector_foreach(missing_files, b) {
        for (int i = 0; i < sizeof(missing_files_exclude)/sizeof(missing_files_exclude[0]); i++) {
            if (!buffer_compare_with_sstring(b, missing_files_exclude[i]))
                goto next;
        }
        rprintf("%v\n", b);
next:
        continue;
    }
    rprintf("missing_files_end\n");
}

void init_syscalls(process p)
{
    heap h = heap_locked(get_kernel_heaps());
    syscall = syscall_handler;
    syscall_io_complete = closure_func(h, io_completion, syscall_io_complete_cfn);
    io_completion_ignore = closure_func(h, io_completion, io_complete_ignore);
    filesystem fs = p->root_fs;
    vector hostname_v = split(h, alloca_wrap_cstring("etc/hostname"), '/');
    tuple hostname_t = resolve_path(filesystem_getroot(fs), hostname_v);
    split_dealloc(hostname_v);
    if (hostname_t)
        filesystem_read_entire(fs, hostname_t, h,
                               closure_func(h, buffer_handler, hostname_done), ignore_status);
    tuple root = p->process_root;
    do_missing_files = get(root, sym(missing_files)) != 0;
    if (do_missing_files) {
        missing_files = allocate_vector(h, 8);
        assert(missing_files != INVALID_ADDRESS);
        shutdown_handler print_missing_files = closure_func(h, shutdown_handler,
                                                            print_missing_files_cfn);
        add_shutdown_completion(print_missing_files);
    }
}

void _register_syscall(struct syscall *m, int n, sysreturn (*f)())
{
    assert(m[n].handler == 0);
    m[n].handler = f;
}

void *swap_syscall_handler(struct syscall *m, int n, sysreturn (*f)())
{
    sysreturn (*ret)() = m[n].handler;
    m[n].handler = f;
    return ret;
}
