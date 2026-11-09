#define _GNU_SOURCE
#pragma clang diagnostic ignored "-Wsign-compare"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int passed, failed;

static void record(const char *name, int ok, const char *fmt, ...)
{
	char detail[192], line[320];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(detail, sizeof detail, fmt, ap);
	va_end(ap);
	int n = snprintf(line, sizeof line, "MINI_CHROMIUM_TEST name=%s status=%s detail=%s\n", name, ok ? "PASS" : "FAIL",
		detail);
	write(1, line, (size_t)n);
	ok ? passed++ : failed++;
}

static int reap(pid_t pid)
{
	int status = -1;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	return status;
}

static int send_fds(int sock, const int *fds, int nfds, const char *data, size_t len)
{
	char *control = malloc(CMSG_SPACE(sizeof(int) * (size_t)(nfds > 0 ? nfds : 1)));
	if (!control)
		return -ENOMEM;
	memset(control, 0, CMSG_SPACE(sizeof(int) * (size_t)(nfds > 0 ? nfds : 1)));
	struct iovec iov = { (void *)data, len };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control,
		.msg_controllen = CMSG_SPACE(sizeof(int) * (size_t)(nfds > 0 ? nfds : 1)) };
	struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
	if (cm) {
		cm->cmsg_level = SOL_SOCKET;
		cm->cmsg_type = SCM_RIGHTS;
		cm->cmsg_len = CMSG_LEN(sizeof(int) * (size_t)nfds);
		if (nfds > 0)
			memcpy(CMSG_DATA(cm), fds, sizeof(int) * (size_t)nfds);
	}
	int r = sendmsg(sock, &msg, MSG_NOSIGNAL);
	int e = errno;
	free(control);
	if (r < 0)
		return -e;
	return 0;
}

static int recv_fds(int sock, int *fds, int max, int *nfds, int *mflags, char *data, size_t len, int flags)
{
	char *control = malloc(CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int) * 260));
	if (!control)
		return -ENOMEM;
	memset(control, 0, CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int) * 260));
	struct iovec iov = { data, len };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control,
		.msg_controllen = CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int) * 260) };
	ssize_t n = recvmsg(sock, &msg, flags);
	int e = errno;
	int cnt = 0;
	if (n > 0) {
		for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
			if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
				int count = (int)((cm->cmsg_len - CMSG_LEN(0)) / sizeof(int));
				for (int i = 0; i < count && cnt < max; i++)
					memcpy(&fds[cnt++], CMSG_DATA(cm) + sizeof(int) * (size_t)i, sizeof(int));
			}
		}
		if (mflags)
			*mflags = msg.msg_flags;
	}
	free(control);
	if (n < 0)
		return -e;
	if (nfds)
		*nfds = cnt;
	return (int)n;
}

static int close_chain(int *fds, int n)
{
	for (int i = 0; i < n; i++)
		close(fds[i]);
	return 0;
}

static void check_stream_small(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		record("rights_stream", 0, "socketpair errno=%d", errno);
		return;
	}
	int p[2];
	pipe2(p, O_CLOEXEC);
	int sent = send_fds(sv[0], p + 1, 1, "x", 1) == 0;
	int fds[4], nfds = 0, mflags = 0;
	char b = 0;
	ssize_t n = recv_fds(sv[1], fds, 4, &nfds, &mflags, &b, 1, MSG_CMSG_CLOEXEC);
	int ok = sent && n == 1 && b == 'x' && nfds == 1 && !(mflags & MSG_CTRUNC);
	if (ok) {
		int cloexec = fcntl(fds[0], F_GETFD) == FD_CLOEXEC;
		ok = ok && cloexec && write(fds[0], "hi", 2) == 2;
		char buf[4] = "";
		ok = ok && read(p[0], buf, 2) == 2 && !memcmp(buf, "hi", 2);
		close(fds[0]);
	}
	close(p[0]);
	close(p[1]);
	close(sv[0]);
	close(sv[1]);
	record("rights_stream", ok, "sent=%d nfds=%d", sent, nfds);
}

static void check_seqpacket_small(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv)) {
		record("rights_seqpacket", 0, "socketpair errno=%d", errno);
		return;
	}
	int p[2];
	pipe2(p, O_CLOEXEC);
	int sent = send_fds(sv[0], p + 1, 1, "y", 1) == 0;
	int fds[4], nfds = 0, mflags = 0;
	char b = 0;
	ssize_t n = recv_fds(sv[1], fds, 4, &nfds, &mflags, &b, 1, 0);
	int ok = sent && n == 1 && b == 'y' && nfds == 1;
	if (ok)
		close(fds[0]);
	close(p[0]);
	close(p[1]);
	close(sv[0]);
	close(sv[1]);
	record("rights_seqpacket", ok, "sent=%d nfds=%d", sent, nfds);
}

static void check_bulk(int count, const char *name)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv)) {
		record(name, 0, "socketpair errno=%d", errno);
		return;
	}
	int *fds = malloc(sizeof(int) * (size_t)count);
	int *got = malloc(sizeof(int) * (size_t)count);
	if (!fds || !got) {
		record(name, 0, "malloc");
		free(fds);
		free(got);
		close(sv[0]);
		close(sv[1]);
		return;
	}
	for (int i = 0; i < count; i++)
		fds[i] = eventfd((unsigned)i + 1, EFD_CLOEXEC | EFD_NONBLOCK);
	int sent = send_fds(sv[0], fds, count, "b", 1) == 0;
	int nfds = 0, mflags = 0;
	char b = 0;
	ssize_t n = recv_fds(sv[1], got, count, &nfds, &mflags, &b, 1, 0);
	int ok = sent && n == 1 && nfds == count && !(mflags & MSG_CTRUNC);
	for (int i = 0; ok && i < count; i++) {
		uint64_t v = 0;
		if (read(got[i], &v, sizeof v) != (ssize_t)sizeof v || v != (uint64_t)i + 1)
			ok = 0;
	}
	record(name, ok, "sent=%d nfds=%d", sent, nfds);
	if (ok)
		close_chain(got, nfds);
	else
		close_chain(got, nfds);
	close_chain(fds, count);
	free(fds);
	free(got);
	close(sv[0]);
	close(sv[1]);
}

static void check_toomany(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		record("rights_254_einval", 0, "socketpair errno=%d", errno);
		return;
	}
	int *fds = malloc(sizeof(int) * 254);
	if (!fds) {
		record("rights_254_einval", 0, "malloc");
		close(sv[0]);
		close(sv[1]);
		return;
	}
	for (int i = 0; i < 254; i++)
		fds[i] = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	errno = 0;
	int r = send_fds(sv[0], fds, 254, "z", 1);
	int ok = r == -EINVAL;
	record("rights_254_einval", ok, "r=%d errno=%d", r, errno);
	close_chain(fds, 254);
	free(fds);
	close(sv[0]);
	close(sv[1]);
}

static void check_ebadf(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		record("rights_ebadf", 0, "socketpair errno=%d", errno);
		return;
	}
	int bad = 987654;
	int r = send_fds(sv[0], &bad, 1, "x", 1);
	record("rights_ebadf", r == -EBADF, "r=%d errno=%d", r, errno);
	close(sv[0]);
	close(sv[1]);
}

static void check_bad_len(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		record("rights_bad_cmsg_len", 0, "socketpair errno=%d", errno);
		return;
	}
	int fd = dup(0);
	char control[CMSG_SPACE(sizeof(int))];
	memset(control, 0, sizeof control);
	struct iovec iov = { "x", 1 };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof control };
	struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = 1;
	errno = 0;
	int small = sendmsg(sv[0], &msg, MSG_NOSIGNAL) < 0 && errno == EINVAL;
	memset(&msg, 0, sizeof msg);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof control;
	cm = CMSG_FIRSTHDR(&msg);
	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = sizeof control + 64;
	errno = 0;
	int overrun = sendmsg(sv[0], &msg, MSG_NOSIGNAL) < 0 && errno == EINVAL;
	record("rights_bad_cmsg_len", small && overrun, "small=%d overrun=%d", small, overrun);
	close(fd);
	close(sv[0]);
	close(sv[1]);
}

static void check_ctrunc_partial(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		record("rights_ctrunc", 0, "socketpair errno=%d", errno);
		return;
	}
	int p1[2], p2[2], p3[2];
	pipe2(p1, O_CLOEXEC);
	pipe2(p2, O_CLOEXEC);
	pipe2(p3, O_CLOEXEC);
	int fds[3] = { p1[1], p2[1], p3[1] };
	int sent = send_fds(sv[0], fds, 3, "q", 1) == 0;
	close(p1[1]);
	close(p2[1]);
	close(p3[1]);
	char small[CMSG_SPACE(sizeof(int) * 2)];
	memset(small, 0, sizeof small);
	char b = 0;
	struct iovec iov = { &b, 1 };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = small, .msg_controllen = sizeof small };
	ssize_t n = recvmsg(sv[1], &msg, 0);
	int ctrunc = n == 1 && (msg.msg_flags & MSG_CTRUNC);
	int kept = 0;
	for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
		if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
			int count = (int)((cm->cmsg_len - CMSG_LEN(0)) / sizeof(int));
			for (int i = 0; i < count; i++) {
				int f;
				memcpy(&f, CMSG_DATA(cm) + sizeof(int) * (size_t)i, sizeof f);
				close(f);
				kept++;
			}
		}
	}
	close(sv[0]);
	close(sv[1]);
	char c;
	int eof = (read(p1[0], &c, 1) == 0) || (read(p2[0], &c, 1) == 0) || (read(p3[0], &c, 1) == 0);
	close(p1[0]);
	close(p2[0]);
	close(p3[0]);
	record("rights_ctrunc", sent && ctrunc && kept == 2 && eof, "sent=%d ctrunc=%d kept=%d eof=%d", sent, ctrunc, kept, eof);
}

static void check_ctrunc_nospace(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv)) {
		record("rights_ctrunc_nospace", 0, "socketpair errno=%d", errno);
		return;
	}
	int p[2];
	pipe2(p, O_CLOEXEC);
	int sent = send_fds(sv[0], p + 1, 1, "n", 1) == 0;
	close(p[1]);
	char b = 0;
	struct iovec iov = { &b, 1 };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = 0, .msg_controllen = 0 };
	ssize_t n = recvmsg(sv[1], &msg, 0);
	int ok = sent && n == 1 && (msg.msg_flags & MSG_CTRUNC) && msg.msg_controllen == 0;
	close(sv[0]);
	close(sv[1]);
	char c;
	int eof = read(p[0], &c, 1) == 0;
	close(p[0]);
	record("rights_ctrunc_nospace", ok && eof, "n=%zd eof=%d", n, eof);
}

static int child_nofile_with_fd(int fd);
static void check_nofile(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		record("rights_nofile_ctrunc", 0, "socketpair errno=%d", errno);
		return;
	}
	int child_end = fcntl(sv[1], F_DUPFD, 10);
	int p[2];
	pipe2(p, O_CLOEXEC);
	int fds[3];
	for (int i = 0; i < 3; i++) {
		fds[i] = eventfd((unsigned)i + 1, EFD_CLOEXEC | EFD_NONBLOCK);
	}
	pid_t pid = fork();
	if (pid == 0) {
		close(sv[0]);
		close(sv[1]);
		char buf[32];
		snprintf(buf, sizeof buf, "%d", child_end);
		(void)buf;
		int rc = child_nofile_with_fd(child_end);
		_exit(rc);
	}
	close(child_end);
	close(p[0]);
	close(p[1]);
	close(sv[1]);
	struct timespec ts = { 0, 200 * 1000 * 1000 };
	nanosleep(&ts, 0);
	int sent = send_fds(sv[0], fds, 3, "f", 1) == 0;
	int status = reap(pid);
	close_chain(fds, 3);
	close(sv[0]);
	extern int wifexited(int);
	extern int wexitstatus(int);
	int ok = sent && WIFEXITED(status) && WEXITSTATUS(status) == 0;
	record("rights_nofile_ctrunc", ok, "sent=%d status=0x%x", sent, status);
}

static int child_nofile_with_fd(int fd)
{
	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl))
		return 2;
	rl.rlim_cur = 20;
	rl.rlim_max = 20;
	if (setrlimit(RLIMIT_NOFILE, &rl))
		return 3;
	int dummy[64], nd = 0;
	for (int i = 0; i < 64; i++) {
		int d = open("/dev/null", O_RDONLY);
		if (d < 0)
			break;
		dummy[nd++] = d;
	}
	if (open("/dev/null", O_RDONLY) >= 0)
		return 4;
	char b = 0;
	struct iovec iov = { &b, 1 };
	char control[CMSG_SPACE(sizeof(int) * 4)];
	memset(control, 0, sizeof control);
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof control };
	ssize_t n = recvmsg(fd, &msg, 0);
	if (n != 1 || !(msg.msg_flags & MSG_CTRUNC))
		return 5;
	for (int i = 0; i < nd; i++)
		close(dummy[i]);
	return 0;
}

static void check_inflight_close(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		record("rights_inflight_close", 0, "socketpair errno=%d", errno);
		return;
	}
	int p[2];
	pipe2(p, O_CLOEXEC);
	int sent = send_fds(sv[0], p + 1, 1, "v", 1) == 0;
	close(p[1]);
	close(sv[0]);
	close(sv[1]);
	char c;
	int eof = read(p[0], &c, 1) == 0;
	close(p[0]);
	record("rights_inflight_close", sent && eof, "sent=%d eof=%d", sent, eof);
}

static void check_peercred_pair(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		record("peercred_socketpair", 0, "socketpair errno=%d", errno);
		return;
	}
	struct ucred c1, c2;
	socklen_t l = sizeof c1;
	int ok1 = getsockopt(sv[0], SOL_SOCKET, SO_PEERCRED, &c1, &l) == 0 && c1.pid == getpid() && c1.uid == getuid() &&
		c1.gid == getgid();
	l = sizeof c2;
	int ok2 = getsockopt(sv[1], SOL_SOCKET, SO_PEERCRED, &c2, &l) == 0 && c2.pid == getpid();
	close(sv[0]);
	close(sv[1]);
	record("peercred_socketpair", ok1 && ok2, "ok1=%d ok2=%d", ok1, ok2);
}

static void check_peercred_connect(void)
{
	char path[108];
	snprintf(path, sizeof path, "scm-%d.sock", (int)getpid());
	unlink(path);
	int server = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	strcpy(addr.sun_path, path);
	int setup = server >= 0 && bind(server, (struct sockaddr *)&addr, sizeof addr) == 0 && listen(server, 5) == 0;
	int client = setup ? socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0) : -1;
	int conn = setup && client >= 0 && connect(client, (struct sockaddr *)&addr, sizeof addr) == 0;
	int acc = conn ? accept(server, 0, 0) : -1;
	int ok = acc >= 0;
	int ok_client = 0, ok_acc = 0;
	if (ok) {
		struct ucred cc, ca;
		socklen_t l = sizeof cc;
		ok_client = getsockopt(client, SOL_SOCKET, SO_PEERCRED, &cc, &l) == 0 && cc.pid == getpid();
		l = sizeof ca;
		ok_acc = getsockopt(acc, SOL_SOCKET, SO_PEERCRED, &ca, &l) == 0 && ca.pid == getpid();
		ok = ok && ok_client && ok_acc;
	}
	if (acc >= 0)
		close(acc);
	if (client >= 0)
		close(client);
	if (server >= 0)
		close(server);
	unlink(path);
	record("peercred_connect_accept", ok, "setup=%d conn=%d ok_client=%d ok_acc=%d", setup, conn, ok_client, ok_acc);
}

static int recv_cred(int sock, struct ucred *cred, char *data, size_t len)
{
	char control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int) * 4)];
	memset(control, 0, sizeof control);
	struct iovec iov = { data, len };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof control };
	ssize_t n = recvmsg(sock, &msg, 0);
	if (n <= 0)
		return (int)n;
	cred->pid = 0;
	for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm)) {
		if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_CREDENTIALS)
			memcpy(cred, CMSG_DATA(cm), sizeof *cred);
	}
	return (int)n;
}

static void check_passcred_sender(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		record("passcred_sender", 0, "socketpair errno=%d", errno);
		return;
	}
	int one = 1;
	int s_ok = setsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &one, sizeof one) == 0;
	int got = 0;
	if (s_ok) {
		int v = 0;
		socklen_t l = sizeof v;
		got = getsockopt(sv[0], SOL_SOCKET, SO_PASSCRED, &v, &l) == 0 && v == 1;
	}
	ssize_t sent_n = send(sv[1], "h", 1, MSG_NOSIGNAL);
	struct ucred cred;
	char b = 0;
	ssize_t n = recv_cred(sv[0], &cred, &b, 1);
	int ok = s_ok && got && sent_n == 1 && n == 1 && cred.pid == getpid() && cred.uid == getuid() && b == 'h';
	close(sv[0]);
	close(sv[1]);
	record("passcred_sender", ok, "n=%zd pid=%d", n, cred.pid);
}

static void check_passcred_receiver(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		record("passcred_receiver", 0, "socketpair errno=%d", errno);
		return;
	}
	int one = 1;
	int s_ok = setsockopt(sv[1], SOL_SOCKET, SO_PASSCRED, &one, sizeof one) == 0;
	ssize_t sent_n = send(sv[0], "i", 1, MSG_NOSIGNAL);
	struct ucred cred;
	char b = 0;
	ssize_t n = recv_cred(sv[1], &cred, &b, 1);
	int ok = s_ok && sent_n == 1 && n == 1 && cred.pid == getpid() && b == 'i';
	close(sv[0]);
	close(sv[1]);
	record("passcred_receiver", ok, "n=%zd pid=%d", n, cred.pid);
}

static void check_explicit_eperm(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		record("explicit_creds_eperm", 0, "socketpair errno=%d", errno);
		return;
	}
	pid_t pid = fork();
	if (pid < 0) {
		record("explicit_creds_eperm", 0, "fork errno=%d", errno);
		close(sv[0]);
		close(sv[1]);
		return;
	}
	if (pid == 0) {
		close(sv[1]);
		if (geteuid() == 0 && (setgid(1000) || setuid(1000)))
			_exit(2);
		struct ucred sent;
		sent.pid = 999999;
		sent.uid = getuid();
		sent.gid = getgid();
		char control[CMSG_SPACE(sizeof(struct ucred))];
		memset(control, 0, sizeof control);
		struct iovec iov = { "x", 1 };
		struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control,
			.msg_controllen = sizeof control };
		struct cmsghdr *cm = CMSG_FIRSTHDR(&msg);
		cm->cmsg_level = SOL_SOCKET;
		cm->cmsg_type = SCM_CREDENTIALS;
		cm->cmsg_len = CMSG_LEN(sizeof sent);
		memcpy(CMSG_DATA(cm), &sent, sizeof sent);
		errno = 0;
		_exit(sendmsg(sv[0], &msg, MSG_NOSIGNAL) < 0 && errno == EPERM ? 0 : 3);
	}
	int status = reap(pid);
	int ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
	close(sv[0]);
	close(sv[1]);
	record("explicit_creds_eperm", ok, "status=0x%x", status);
}

static void check_dontwait(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		record("dontwait_eagain", 0, "socketpair errno=%d", errno);
		return;
	}
	char b = 0;
	errno = 0;
	ssize_t n = recv(sv[0], &b, 1, MSG_DONTWAIT);
	int ok = n < 0 && errno == EAGAIN;
	record("dontwait_eagain", ok, "n=%zd errno=%d", n, errno);
	close(sv[0]);
	close(sv[1]);
}

static void check_seqpacket_trunc(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv)) {
		record("seqpacket_trunc", 0, "socketpair errno=%d", errno);
		return;
	}
	int sent = send(sv[0], "first-message", 13, 0) == 13;
	char buf[8] = "";
	struct iovec iov = { buf, 5 };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
	ssize_t n1 = recvmsg(sv[1], &msg, MSG_DONTWAIT);
	int trunc = n1 == 5 && (msg.msg_flags & MSG_TRUNC) && !memcmp(buf, "first", 5);
	char buf2[16] = "";
	struct iovec iov2 = { buf2, sizeof buf2 };
	struct msghdr msg2 = { .msg_iov = &iov2, .msg_iovlen = 1 };
	ssize_t n2 = recvmsg(sv[1], &msg2, MSG_TRUNC | MSG_DONTWAIT);
	int sv2[2];
	socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv2);
	send(sv2[0], "hello-world", 11, 0);
	char small[3] = "";
	struct iovec iov3 = { small, sizeof small };
	struct msghdr msg3 = { .msg_iov = &iov3, .msg_iovlen = 1 };
	ssize_t n3 = recvmsg(sv2[1], &msg3, MSG_TRUNC | MSG_DONTWAIT);
	int trunc_ret = n3 == 11 && (msg3.msg_flags & MSG_TRUNC);
	(void)n2;
	int ok = sent && trunc && trunc_ret;
	close(sv[0]);
	close(sv[1]);
	close(sv2[0]);
	close(sv2[1]);
	record("seqpacket_trunc", ok, "trunc=%d ret=%zd", trunc, n3);
}

static void check_seqpacket_large(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv)) {
		record("seqpacket_large", 0, "socketpair errno=%d", errno);
		return;
	}
	char *payload = malloc(8000);
	memset(payload, 'a', 8000);
	ssize_t s = send(sv[0], payload, 8000, 0);
	char *buf = malloc(8000);
	ssize_t r = s == 8000 ? recv(sv[1], buf, 8000, MSG_DONTWAIT) : -1;
	int ok = s == 8000 && r == 8000 && !memcmp(payload, buf, 8000);
	free(payload);
	free(buf);
	close(sv[0]);
	close(sv[1]);
	record("seqpacket_large", ok, "send=%zd recv=%zd", s, r);
}

static void check_stream_stops(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		record("stream_stops_at_rights", 0, "socketpair errno=%d", errno);
		return;
	}
	int p[2];
	pipe2(p, O_CLOEXEC);
	int s1 = send_fds(sv[0], p + 1, 1, "first", 5) == 0;
	int s2 = send(sv[0], "second", 6, MSG_NOSIGNAL) == 6;
	char buf[64] = "";
	struct iovec iov = { buf, sizeof buf };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
	char control[CMSG_SPACE(sizeof(int))];
	msg.msg_control = control;
	msg.msg_controllen = sizeof control;
	ssize_t n1 = recvmsg(sv[1], &msg, 0);
	int nfds = 0;
	for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm))
		if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS)
			nfds += (int)((cm->cmsg_len - CMSG_LEN(0)) / sizeof(int));
	int ok1 = n1 == 5 && !memcmp(buf, "first", 5) && nfds == 1;
	if (nfds == 1) {
		for (struct cmsghdr *cm = CMSG_FIRSTHDR(&msg); cm; cm = CMSG_NXTHDR(&msg, cm))
			if (cm->cmsg_level == SOL_SOCKET && cm->cmsg_type == SCM_RIGHTS) {
				int f;
				memcpy(&f, CMSG_DATA(cm), sizeof f);
				close(f);
			}
	}
	char buf2[64] = "";
	ssize_t n2 = recv(sv[1], buf2, sizeof buf2, MSG_DONTWAIT);
	int ok2 = n2 == 6 && !memcmp(buf2, "second", 6);
	int ok = s1 && s2 && ok1 && ok2;
	close(p[0]);
	close(p[1]);
	close(sv[0]);
	close(sv[1]);
	record("stream_stops_at_rights", ok, "n1=%zd n2=%zd", n1, n2);
}

static void check_unknown_flags(void)
{
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv)) {
		record("unknown_send_flags", 0, "socketpair errno=%d", errno);
		return;
	}
	errno = 0;
	int ok = send(sv[0], "x", 1, MSG_OOB) < 0 && errno == EOPNOTSUPP;
	record("unknown_send_flags", ok, "errno=%d", errno);
	close(sv[0]);
	close(sv[1]);
}

int main(void)
{
	alarm(30);
	check_stream_small();
	check_seqpacket_small();
	check_bulk(128, "rights_128");
	check_bulk(253, "rights_253");
	check_bulk(1, "rights_1_single");
	check_toomany();
	check_ebadf();
	check_bad_len();
	check_ctrunc_partial();
	check_ctrunc_nospace();
	check_nofile();
	check_inflight_close();
	check_peercred_pair();
	check_peercred_connect();
	check_passcred_sender();
	check_passcred_receiver();
	check_explicit_eperm();
	check_dontwait();
	check_seqpacket_trunc();
	check_seqpacket_large();
	check_stream_stops();
	check_unknown_flags();
	char line[96];
	int len = snprintf(line, sizeof line, "MINI_CHROMIUM_RESULT status=%s passed=%d failed=%d\n", failed ? "FAIL" : "PASS",
		passed, failed);
	write(1, line, (size_t)len);
	return failed ? 1 : 0;
}
