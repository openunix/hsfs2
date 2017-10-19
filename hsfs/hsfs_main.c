/*
 * Copyright (C) 2012, 2013, 2017 Feng Shuo <steve.shuo.feng@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * The content started with "lo_" is directly copied from Miklos'
 * passthrough_ll.c of the libfuse project. See the file COPYING in
 * libfuse3 source for license.
 */

#define _GNU_SOURCE
#define FUSE_USE_VERSION 30

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <fuse_lowlevel.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <inttypes.h>

/* We are re-using pointers to our `struct lo_inode` and `struct
   lo_dirp` elements as inodes. This means that we must be able to
   store uintptr_t values in a fuse_ino_t variable. The following
   incantation checks this condition at compile time. */
#if defined(__GNUC__) && (__GNUC__ > 4 || __GNUC__ == 4 && __GNUC_MINOR__ >= 6) && !defined __cplusplus
_Static_assert(sizeof(fuse_ino_t) >= sizeof(uintptr_t),
	       "fuse_ino_t too small to hold uintptr_t values!");
#else
struct _uintptr_to_must_hold_fuse_ino_t_dummy_struct \
	{ unsigned _uintptr_to_must_hold_fuse_ino_t:
			((sizeof(fuse_ino_t) >= sizeof(uintptr_t)) ? 1 : -1); };
#endif

struct lo_inode {
	struct lo_inode *next;
	struct lo_inode *prev;
	int fd;
	ino_t ino;
	dev_t dev;
	uint64_t nlookup;
};

struct lo_data {
	int debug;
	int writeback;
	struct lo_inode root;
};

static struct lo_data *lo_data(fuse_req_t req)
{
	return (struct lo_data *) fuse_req_userdata(req);
}

static struct lo_inode *lo_inode(fuse_req_t req, fuse_ino_t ino)
{
	if (ino == FUSE_ROOT_ID)
		return &lo_data(req)->root;
	else
		return (struct lo_inode *) (uintptr_t) ino;
}

static int lo_fd(fuse_req_t req, fuse_ino_t ino)
{
	return lo_inode(req, ino)->fd;
}

static bool lo_debug(fuse_req_t req)
{
	return lo_data(req)->debug != 0;
}

static void lo_init(void *userdata,
		    struct fuse_conn_info *conn)
{
	struct lo_data *lo = (struct lo_data*) userdata;

	if(conn->capable & FUSE_CAP_EXPORT_SUPPORT)
		conn->want |= FUSE_CAP_EXPORT_SUPPORT;

	if (lo->writeback &&
	    conn->capable & FUSE_CAP_WRITEBACK_CACHE) {
		if (lo->debug)
			fprintf(stderr, "lo_init: activating writeback\n");
		conn->want |= FUSE_CAP_WRITEBACK_CACHE;
	}
}

static void lo_getattr(fuse_req_t req, fuse_ino_t ino,
			     struct fuse_file_info *fi)
{
	int res;
	struct stat buf;
	(void) fi;

	res = fstatat(lo_fd(req, ino), "", &buf, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		return (void) fuse_reply_err(req, errno);

	fuse_reply_attr(req, &buf, 1.0);
}

static struct lo_inode *lo_find(struct lo_data *lo, struct stat *st)
{
	struct lo_inode *p;

	for (p = lo->root.next; p != &lo->root; p = p->next) {
		if (p->ino == st->st_ino && p->dev == st->st_dev)
			return p;
	}
	return NULL;
}

static int lo_do_lookup(fuse_req_t req, fuse_ino_t parent, const char *name,
			 struct fuse_entry_param *e)
{
	int newfd;
	int res;
	int saverr;
	struct lo_inode *inode;

	memset(e, 0, sizeof(*e));
	e->attr_timeout = 1.0;
	e->entry_timeout = 1.0;

	newfd = openat(lo_fd(req, parent), name, O_PATH | O_NOFOLLOW);
	if (newfd == -1)
		goto out_err;

	res = fstatat(newfd, "", &e->attr, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		goto out_err;

	inode = lo_find(lo_data(req), &e->attr);
	if (inode) {
		close(newfd);
		newfd = -1;
	} else {
		struct lo_inode *prev = &lo_data(req)->root;
		struct lo_inode *next = prev->next;
		saverr = ENOMEM;
		inode = calloc(1, sizeof(struct lo_inode));
		if (!inode)
			goto out_err;

		inode->fd = newfd;
		inode->ino = e->attr.st_ino;
		inode->dev = e->attr.st_dev;

		next->prev = inode;
		inode->next = next;
		inode->prev = prev;
		prev->next = inode;
	}
	inode->nlookup++;
	e->ino = (uintptr_t) inode;

	if (lo_debug(req))
		fprintf(stderr, "  %lli/%s -> %lli\n",
			(unsigned long long) parent, name, (unsigned long long) e->ino);

	return 0;

out_err:
	saverr = errno;
	if (newfd != -1)
		close(newfd);
	return saverr;
}

static void lo_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fuse_entry_param e;
	int err;

	if (lo_debug(req))
		fprintf(stderr, "lo_lookup(parent=%" PRIu64 ", name=%s)\n",
			parent, name);
	
	err = lo_do_lookup(req, parent, name, &e);
	if (err)
		fuse_reply_err(req, err);
	else
		fuse_reply_entry(req, &e);
}

static void lo_free(struct lo_inode *inode)
{
	struct lo_inode *prev = inode->prev;
	struct lo_inode *next = inode->next;

	next->prev = prev;
	prev->next = next;
	close(inode->fd);
	free(inode);
}

static void lo_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	struct lo_inode *inode = lo_inode(req, ino);

	if (lo_debug(req)) {
		fprintf(stderr, "  forget %lli %lli -%lli\n",
			(unsigned long long) ino, (unsigned long long) inode->nlookup,
			(unsigned long long) nlookup);
	}

	assert(inode->nlookup >= nlookup);
	inode->nlookup -= nlookup;

	if (!inode->nlookup)
		lo_free(inode);

	fuse_reply_none(req);
}

static void lo_readlink(fuse_req_t req, fuse_ino_t ino)
{
	char buf[PATH_MAX + 1];
	int res;

	res = readlinkat(lo_fd(req, ino), "", buf, sizeof(buf));
	if (res == -1)
		return (void) fuse_reply_err(req, errno);

	if (res == sizeof(buf))
		return (void) fuse_reply_err(req, ENAMETOOLONG);

	buf[res] = '\0';

	fuse_reply_readlink(req, buf);
}

struct lo_dirp {
	int fd;
	DIR *dp;
	struct dirent *entry;
	off_t offset;
};

static struct lo_dirp *lo_dirp(struct fuse_file_info *fi)
{
	return (struct lo_dirp *) (uintptr_t) fi->fh;
}

static void lo_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	int error = ENOMEM;
	struct lo_dirp *d = calloc(1, sizeof(struct lo_dirp));
	if (d == NULL)
		goto out_err;

	d->fd = openat(lo_fd(req, ino), ".", O_RDONLY);
	if (d->fd == -1)
		goto out_errno;

	d->dp = fdopendir(d->fd);
	if (d->dp == NULL)
		goto out_errno;

	d->offset = 0;
	d->entry = NULL;

	fi->fh = (uintptr_t) d;
	fuse_reply_open(req, fi);
	return;

out_errno:
	error = errno;
out_err:
	if (d) {
		if (d->fd != -1)
			close(d->fd);
		free(d);
	}
	fuse_reply_err(req, error);
}

static void lo_do_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
			  off_t offset, struct fuse_file_info *fi, int plus)
{
	struct lo_dirp *d = lo_dirp(fi);
	char *buf;
	char *p;
	size_t rem;
	int err;

	(void) ino;

	buf = calloc(size, 1);
	if (!buf)
		return (void) fuse_reply_err(req, ENOMEM);

	if (offset != d->offset) {
		seekdir(d->dp, offset);
		d->entry = NULL;
		d->offset = offset;
	}
	p = buf;
	rem = size;
	while (1) {
		size_t entsize;
		off_t nextoff;

		if (!d->entry) {
			errno = 0;
			d->entry = readdir(d->dp);
			if (!d->entry) {
				if (errno && rem == size) {
					err = errno;
					goto error;
				}
				break;
			}
		}
		nextoff = telldir(d->dp);
		if (plus) {
			struct fuse_entry_param e;

			err = lo_do_lookup(req, ino, d->entry->d_name, &e);
			if (err)
				goto error;

			entsize = fuse_add_direntry_plus(req, p, rem,
							 d->entry->d_name,
							 &e, nextoff);
		} else {
			struct stat st = {
				.st_ino = d->entry->d_ino,
				.st_mode = d->entry->d_type << 12,
			};
			entsize = fuse_add_direntry(req, p, rem,
						    d->entry->d_name,
						    &st, nextoff);
		}
		if (entsize > rem)
			break;

		p += entsize;
		rem -= entsize;

		d->entry = NULL;
		d->offset = nextoff;
	}

	fuse_reply_buf(req, buf, size - rem);
	free(buf);
	return;

error:
	free(buf);
	fuse_reply_err(req, err);
}

static void lo_readdir(fuse_req_t req, fuse_ino_t ino, size_t size,
		       off_t offset, struct fuse_file_info *fi)
{
	lo_do_readdir(req, ino, size, offset, fi, 0);
}

static void lo_readdirplus(fuse_req_t req, fuse_ino_t ino, size_t size,
			   off_t offset, struct fuse_file_info *fi)
{
	lo_do_readdir(req, ino, size, offset, fi, 1);
}

static void lo_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct lo_dirp *d = lo_dirp(fi);
	(void) ino;
	closedir(d->dp);
	free(d);
	fuse_reply_err(req, 0);
}

static void lo_create(fuse_req_t req, fuse_ino_t parent, const char *name,
		      mode_t mode, struct fuse_file_info *fi)
{
	int fd;
	struct fuse_entry_param e;
	int err;

	if (lo_debug(req))
		fprintf(stderr, "lo_create(parent=%" PRIu64 ", name=%s)\n",
			parent, name);
			
	fd = openat(lo_fd(req, parent), name,
		    (fi->flags | O_CREAT) & ~O_NOFOLLOW, mode);
	if (fd == -1)
		return (void) fuse_reply_err(req, errno);

	fi->fh = fd;

	err = lo_do_lookup(req, parent, name, &e);
	if (err)
		fuse_reply_err(req, err);
	else
		fuse_reply_create(req, &e, fi);
}

static void lo_open(fuse_req_t req, fuse_ino_t ino,
		    struct fuse_file_info *fi)
{
	int fd;
	char buf[64];

	if (lo_debug(req))
		fprintf(stderr, "lo_open(ino=%" PRIu64 ", flags=%d)\n",
			ino, fi->flags);

	/* With writeback cache, kernel may send read requests even
	   when userspace opened write-only */
	if (lo_data(req)->writeback &&
	    (fi->flags & O_ACCMODE) == O_WRONLY) {
		fi->flags &= ~O_ACCMODE;
		fi->flags |= O_RDWR;
	}

	/* With writeback cache, O_APPEND is handled by the kernel.
	   This breaks atomicity (since the file may change in the
	   underlying filesystem, so that the kernel's idea of the
	   end of the file isn't accurate anymore). In this example,
	   we just accept that. A more rigorous filesystem may want
	   to return an error here */
	if (lo_data(req)->writeback && (fi->flags & O_APPEND))
		fi->flags &= ~O_APPEND;

	sprintf(buf, "/proc/self/fd/%i", lo_fd(req, ino));
	fd = open(buf, fi->flags & ~O_NOFOLLOW);
	if (fd == -1)
		return (void) fuse_reply_err(req, errno);

	fi->fh = fd;
	fuse_reply_open(req, fi);
}

static void lo_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	(void) ino;

	close(fi->fh);
	fuse_reply_err(req, 0);
}

static void lo_read(fuse_req_t req, fuse_ino_t ino, size_t size,
		    off_t offset, struct fuse_file_info *fi)
{
	struct fuse_bufvec buf = FUSE_BUFVEC_INIT(size);

	if (lo_debug(req))
		fprintf(stderr, "lo_read(ino=%" PRIu64 ", size=%zd, "
			"off=%lu)\n", ino, size, (unsigned long) offset);

	buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
	buf.buf[0].fd = fi->fh;
	buf.buf[0].pos = offset;

	fuse_reply_data(req, &buf, FUSE_BUF_SPLICE_MOVE);
}

static void lo_write_buf(fuse_req_t req, fuse_ino_t ino,
			 struct fuse_bufvec *in_buf, off_t off,
			 struct fuse_file_info *fi)
{
	(void) ino;
	ssize_t res;
	struct fuse_bufvec out_buf = FUSE_BUFVEC_INIT(fuse_buf_size(in_buf));

	out_buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
	out_buf.buf[0].fd = fi->fh;
	out_buf.buf[0].pos = off;

	if (lo_debug(req))
		fprintf(stderr, "lo_write(ino=%" PRIu64 ", size=%zd, off=%lu)\n",
			ino, out_buf.buf[0].size, (unsigned long) off);
	
	res = fuse_buf_copy(&out_buf, in_buf, 0);
	if(res < 0)
		fuse_reply_err(req, -res);
	else
		fuse_reply_write(req, (size_t) res);
}

/*
 * The end of the passthrough_ll.c content, with excluding the main()
 * of the file. Following codes will use "hsfs_" prefix, which is the
 * historic project name.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <uriparser/Uri.h>

#ifdef HAVE_LINUX_VM_SOCKETS_H
#include <linux/vm_sockets.h>
# ifndef AF_VSOCK
#  define AF_VSOCK 40
# endif
# define HAVE_VSOCK
#endif

#ifdef WITH_VMWARE_VMCI
# include <vmci/vmci_sockets.h>
# define HAVE_VSOCK
#endif

struct hsfs_cmdline_opts {
        int is_client;
        int is_server;
        int writeback;
        char *target_spec;
        /* below are reference only, never free */
        char *server_path;
        UriUriA target_uri;
};

struct hsfs_remote_info {
        uint32_t	major;
	uint32_t	minor;
	uint32_t	max_readahead;
	uint32_t	flags;
	uint16_t	max_background;
	uint16_t	congestion_threshold;
	uint32_t	max_write;
	uint32_t	time_gran;
};

/* The real super, lo_data must be the first one to make the "lo_"
 * codes work. */
struct hsfs_super {
        union {
                struct lo_data lo_data;
                struct hsfs_remote_info re_data;
        }u;
        int type;
        struct fuse_conn_info *conn;
        int sock;
        int fd;
#ifdef WITH_VMWARE_VMCI
        int vmci_fd;
#endif  /* WITH_VMWARE_VMCI */
};

/* For type */
#define HSFS_SB_NONE   0x000
#define HSFS_SB_CLIENT 0x001
#define HSFS_SB_SERVER 0x002

static bool is_client(struct hsfs_super *sb)
{
        return (sb->type & HSFS_SB_CLIENT);
}

/* Debug */
#ifndef unlikely
# define unlikely(x)	__builtin_expect((x),0)
#endif	/* unlikely */
int __INIT_DEBUG = 0;
#define DEBUG(fmt, args...) do {                                        \
                if (unlikely(__INIT_DEBUG))                             \
                        fprintf(stderr, fmt "\n", ##args);              \
        }while(0)
#define BUG_ON(exp) assert(!(exp))

char *progname = NULL;

static void exit_usage(int err)
{
        printf("usage:\n");
        printf("    %s --client URI [-d] [-f] [-s] [-o options] mount-point\n", progname);
	printf("    %s --server URI [-d] [-f] [-s] [-o options] local-dir\n", progname);
	printf("    %s [-h|--help] [-V|--version]\n", progname);
        if (!err) {
                printf("options:\n");
                fuse_cmdline_help();
                fuse_lowlevel_help();
                printf("Refer to mount.%s(8) or %s(5) for more -o options and the URI spec.\n", progname, progname);
        }
	exit(!!err);
}

static void print_version(void)
{
#ifdef PACKAGE_NAME
	printf("%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
#else
        printf("%s develop version\n", progname);
#endif
        fuse_lowlevel_version();
	exit(0);
}

static void hsfs_init(void *userdata, struct fuse_conn_info *conn)
{
	struct hsfs_super *sb = (struct hsfs_super *)userdata;

        BUG_ON(sb->conn);

        /* There is no way to return any errors during init. */
        if (is_client(sb))
                sb->conn = conn;
        else
                lo_init(userdata, conn);
}

static struct fuse_lowlevel_ops hsfs_oper = {
	.init		= hsfs_init,
	.lookup		= lo_lookup,
	.forget		= lo_forget,
	.getattr	= lo_getattr,
	.readlink	= lo_readlink,
	.opendir	= lo_opendir,
	.readdir	= lo_readdir,
	.readdirplus	= lo_readdirplus,
	.releasedir	= lo_releasedir,
	.create		= lo_create,
	.open		= lo_open,
	.release	= lo_release,
	.read		= lo_read,
	.write_buf      = lo_write_buf
#ifdef BUILD_VIRTFS
	.statfs = hsx_fuse_statfs,
	.mkdir = hsx_fuse_mkdir,
	.write = hsx_fuse_write,
	.setattr = hsx_fuse_setattr,
	.rmdir = hsx_fuse_rmdir,
	.unlink = hsx_fuse_unlink,
	.symlink = hsx_fuse_symlink,
	.rename = hsx_fuse_rename,
	.mknod = hsx_fuse_mknod,
	.link = hsx_fuse_link,
	.access = hsx_fuse_access,
	.getxattr = hsx_fuse_getxattr,
	.setxattr = hsx_fuse_setxattr,
#endif
};


static const struct fuse_opt hsfs_cmdline_spec[] = {
        { "--client",
          offsetof(struct hsfs_cmdline_opts, is_client), 1},
        { "--server",
          offsetof(struct hsfs_cmdline_opts, is_server), 1},
	{ "writeback",
	  offsetof(struct hsfs_cmdline_opts, writeback), 1 },
	{ "no_writeback",
	  offsetof(struct hsfs_cmdline_opts, writeback), 0 },
        FUSE_OPT_END
};

static int hsfs_cmdline_proc(void *data, const char *arg, int key,
                             struct fuse_args *outargs __attribute__((unused)))
{
        struct hsfs_cmdline_opts *opts = data;

        switch (key) {
        case FUSE_OPT_KEY_NONOPT:
                if (!opts->target_spec)
                        return fuse_opt_add_opt(&opts->target_spec, arg);
                else
                        return 1;
        default:
                return 1;
        }

        return 0;
}

static int hsfs_parse_cmdline(struct fuse_args *args,
                              struct fuse_cmdline_opts *fuse_opts,
                              struct hsfs_cmdline_opts *hsfs_opts)
{
        int ret;
        UriParserStateA state = {
                .uri = &(hsfs_opts->target_uri),
        };

	bzero(hsfs_opts, sizeof(*hsfs_opts));

        ret = fuse_opt_parse(args, hsfs_opts, hsfs_cmdline_spec, hsfs_cmdline_proc);
        if (ret != 0)
                goto out_usage;

        ret = fuse_parse_cmdline(args, fuse_opts);
        if (ret != 0)
                goto out_usage;

        __INIT_DEBUG = fuse_opts->debug;

        if (fuse_opts->show_help)
                goto out_usage;
        else if (fuse_opts->show_version) {
                print_version();
                goto out;
        }
        ret = 1;
        if (hsfs_opts->is_client && hsfs_opts->is_server) {
                fprintf(stderr, "Client and server target URI cannot be specified together.\n");
                goto out_usage;
        }
        else if (hsfs_opts->is_client) {
                if (!fuse_opts->mountpoint) {
                        fprintf(stderr, "The mount point must be specified for client mode.\n");
                        goto out_usage;
                }
        }
        else if (hsfs_opts->is_server) {
                if (!fuse_opts->mountpoint) {
                        fprintf(stderr, "The local serving dir must be specified for server mode.\n");
                        goto out_usage;
                }
                hsfs_opts->server_path = fuse_opts->mountpoint;
        }
        else{
                fprintf(stderr, "Either client or server target URI must be specified.\n");
                goto out_usage;
        }

        if (uriParseUriA(&state, hsfs_opts->target_spec) != URI_SUCCESS)
                ret = 1;
        else if (!hsfs_opts->target_uri.scheme.first) {
                state.errorPos = hsfs_opts->target_spec;
                ret = 1;
        }
        else if (strlen(hsfs_opts->target_uri.scheme.afterLast) <= 3) {
                state.errorPos = hsfs_opts->target_uri.scheme.afterLast +
                        strlen(hsfs_opts->target_uri.scheme.afterLast);
                ret = 1;
        }
        else
                ret = 0;
        if (ret) {
                fprintf(stderr, "%s: Incorrect URI format: %s\n", progname, hsfs_opts->target_spec);
                if (state.errorPos){
                        int i = state.errorPos - hsfs_opts->target_spec + strlen(progname) +
                                sizeof(": Incorrect URI format: ") - 1;
                        while (i > 0){
                                fprintf(stderr, " ");
                                i--;
                        }
                        fprintf(stderr, "^\n");
                }
                ret = 1;
                goto out_usage;
        }

        return 0;

out_usage:
        exit_usage(ret);
        /* Never reach here... */
out:
	return ret;
}

struct in_header {
	uint32_t	len;
	uint32_t	opcode;
	uint64_t	unique;
	uint64_t	nodeid;
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	pid;
	uint32_t	padding;
};

struct out_header {
	uint32_t	len;
	int32_t		error;
	uint64_t	unique;
};

struct init_out {
	uint32_t	major;
	uint32_t	minor;
	uint32_t	max_readahead;
	uint32_t	flags;
	uint16_t	max_background;
	uint16_t	congestion_threshold;
	uint32_t	max_write;
	uint32_t	time_gran;
	uint32_t	unused[9];
};

#define __FUSE_INIT 26
#define __FUSE_FORGET 2
#define __FUSE_BATCH_FORGET 42

static int hsfs_do_recv(struct fuse_session *se, struct hsfs_super *sb,
                        struct fuse_buf *recv_buf)
{
        struct fuse_bufvec src_vec, dst_vec = FUSE_BUFVEC_INIT(0);
        struct out_header out;
        int res, ret = 0;

        BUG_ON(recv_buf == NULL);
        BUG_ON(recv_buf->mem == NULL);

        if (fuse_session_exited(se))
                goto out;

	res = recv(sb->sock, &out, sizeof(out),  MSG_PEEK);
        if (res < 0){
                ret = -errno;
                goto out;
        }
        if (res != sizeof(out))
                goto out;

        DEBUG("   unique: %llu, error: %d, outsize: %d",
              out.unique, out.error, out.len);

        src_vec = FUSE_BUFVEC_INIT(out.len);
        src_vec.buf[0].fd = sb->sock;
        src_vec.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_RETRY;
        dst_vec.buf[0] = *recv_buf;
        dst_vec.buf[0].size = out.len;
        res = fuse_buf_copy(&dst_vec, &src_vec, FUSE_BUF_NO_SPLICE);
        if (res < 0){
                ret = res;
                goto out;
        }
        if (res != (int)out.len){
                ret = -errno;
                goto out;
        }
        recv_buf->size = res;
        return 0;
out:
        return ret;
}

#define COPY(xx) do {                                                   \
                sb->u.re_data.xx = init_reply.reply.xx;                    \
                DEBUG("Copy " #xx ":%d to super", (int)(sb->u.re_data.xx)); \
        } while(0)

static int hsfs_process_init(struct fuse_session *se, struct hsfs_super *sb,
                             struct fuse_buf *in_buf)
{
        struct init_reply {
                struct out_header header;
                struct init_out reply;
        } init_reply;

        struct fuse_buf outbuf = {
                .size = sizeof(init_reply),
                .mem = &init_reply,
                .flags = 0,
        };

        int ret;

        ret = hsfs_do_recv(se, sb, &outbuf);
        if (ret < 0)
                goto out;

        COPY(major); COPY(minor); COPY(max_readahead); COPY(flags);
        COPY(max_background); COPY(congestion_threshold); COPY(max_write);
        COPY(time_gran);

        fuse_session_process_buf(se, in_buf);
out:
        return ret;
}

/* Return value < 0 on error, 0 on exit*/
#define HSFS_LOOP_NEXT 1
#define HSFS_LOOP_RECV 2
static int hsfs_do_send(struct fuse_session *se, struct hsfs_super *sb,
                        struct fuse_buf *send_buf)
{
        struct fuse_bufvec dst_vec, src_vec = FUSE_BUFVEC_INIT(0);
        int res, ret = 0;

        if (send_buf == NULL)
                send_buf = src_vec.buf;

        if (fuse_session_exited(se))
                goto out;

        res = fuse_session_receive_buf(se, send_buf);
        if (res == -EINTR) {
                ret = HSFS_LOOP_NEXT;
                goto out;
        }
        if (res <= 0){
                ret = res;
                goto out;
        }

        dst_vec = FUSE_BUFVEC_INIT(res);
        dst_vec.buf[0].flags  = FUSE_BUF_IS_FD | FUSE_BUF_FD_RETRY;
        dst_vec.buf[0].fd = sb->sock;
        if (send_buf != src_vec.buf)
                src_vec.buf[0] = *send_buf;

        ret = fuse_buf_copy(&dst_vec, &src_vec, 0);
        if (ret <= 0)
                goto out;
        if (ret != res) {
                ret = errno;
                goto out;
        }

        ret = HSFS_LOOP_RECV;
        if (!send_buf->flags) {
                struct in_header *in = send_buf->mem;
                DEBUG("unique: %llu, opcode: %d, nodeid: %llu, insize: %d, pid: %d",
                      in->unique, in->opcode, in->nodeid, in->len, in->pid);

                if (in->opcode == __FUSE_INIT){
                        ret = hsfs_process_init(se, sb, send_buf);
                        if (ret == 0)
                                ret = HSFS_LOOP_NEXT;
                        else
                                goto out;
                }
                if ((in->opcode == __FUSE_BATCH_FORGET) ||
                    (in->opcode == __FUSE_FORGET))
                        ret = HSFS_LOOP_NEXT;
        }
        else {
                DEBUG("unknown request in pipe");
        }

out:
        if ((send_buf == src_vec.buf) && (src_vec.buf[0].mem != NULL))
                free(src_vec.buf[0].mem);

        return ret;
}


int hsfs_redirect_loop(struct fuse_session *se, struct hsfs_super *sb)
{
        int err = 0;
        int fuse_fd = fuse_session_fd(se);
        /* XXX Should poll it！ */
        struct fuse_buf fbuf = {
                .mem = NULL,
        };

        while (!fuse_session_exited(se)) {
                err = hsfs_do_send(se, sb, &fbuf);
                if (err <= 0)
                        break;
                if (err == HSFS_LOOP_NEXT)
                        continue;

                fbuf.flags = 0;
                err = hsfs_do_recv(se, sb, &fbuf);
                if (err < 0)
                        break;

                err = write(fuse_fd, fbuf.mem, fbuf.size);
                if (err < 0){
                        err = -errno;
                        break;
                }
        }

        if (fbuf.mem)
                free(fbuf.mem);

        fuse_session_reset(se);
        return err;
}

int hsfs_start_unix_client(struct hsfs_super *sb, struct hsfs_cmdline_opts *hsfs_opts)
{
        struct sockaddr_un addr_serv;
        int ret = 0;

        sb->sock = socket(PF_UNIX, SOCK_STREAM, 0);
        if (sb->sock < 0){
                ret = errno;
                perror(progname);
                goto out;
        }

        memset(&addr_serv, 0, sizeof(addr_serv));
        addr_serv.sun_family = AF_UNIX;
        strncpy(addr_serv.sun_path, hsfs_opts->target_spec + 7,
                sizeof(addr_serv.sun_path) - 1);

                ret = connect(sb->sock, (struct sockaddr *)&addr_serv, sizeof(addr_serv));
                if (ret){
                        ret = errno;
                        perror(progname);
                        goto out1;
                }
        return 0;
out1:
        close(sb->sock);
out:
        return ret;

}

int hsfs_start_unix_server(struct hsfs_super *sb, struct hsfs_cmdline_opts *hsfs_opts)
{
        struct sockaddr_un addr_serv;
        int ret = 0;

        sb->sock = socket(PF_UNIX, SOCK_STREAM, 0);
        if (sb->sock < 0){
                ret = errno;
                perror(progname);
                goto out;
        }

        memset(&addr_serv, 0, sizeof(addr_serv));
        addr_serv.sun_family = AF_UNIX;
        strncpy(addr_serv.sun_path, hsfs_opts->target_spec + 7,
                sizeof(addr_serv.sun_path) - 1);

                struct lo_data *lo = &(sb->u.lo_data);

                sb->type = HSFS_SB_SERVER;
                lo->root.next = lo->root.prev = &(lo->root);
                lo->debug = __INIT_DEBUG;
                lo->root.fd = open(hsfs_opts->server_path, O_PATH);
                lo->root.nlookup = 2;
                if (lo->root.fd == -1)
                        err(1, "open(\"%s\", O_PATH)", hsfs_opts->server_path);
                if (bind(sb->sock, (struct sockaddr *)&addr_serv, sizeof(addr_serv)) == -1) {
                        ret = errno;
                        perror("bind error");
                        goto out1;
                }
                if (listen(sb->sock, 1) == -1) {
                        ret = errno;
                        perror("listen error");
                        goto out1;
                }
                sb->fd = accept(sb->sock, NULL, NULL);
                if (sb->fd == -1){
                        ret = errno;
                        perror("listen error");
                        goto out1;
                }

        return 0;

out1:
        close(sb->sock);
out:
        return ret;
}

static int __vmware_start

int hsfs_start_vmci_client(struct hsfs_super *sb, struct hsfs_cmdline_opts *hsfs_opts)
{
        UriUriA *uri = &(hsfs_opts->target_uri);

        if (!uri->hostText.first || !uri->portText.first){
                fprintf(stderr, "%s: VMCI CID and port must be specified: %s",
                        progname, hsfs_opts->target_spec);
                goto err_out;
        }

        if (uri->userInfo.first || *uri->portText.afterLast != 0){
                fprintf(stderr, "%s: Unsupported URI schema: %s\n",
                        progname, hsfs_opts->target_spec);
                goto err_out;
        }

        DEBUG("URI->hostText: %s, %d", uri->hostText.first, uri->hostText.afterLast - uri->hostText.first);
        DEBUG("URI->portText: %s, %d", uri->portText.first, uri->portText.afterLast - uri->portText.first);

err_out:
        return 1;
}

int hsfs_start_vmci_server(struct hsfs_super *sb, struct hsfs_cmdline_opts *hsfs_opts)
{
        UriUriA *uri = &(hsfs_opts->target_uri);
        int sockfd, connfd;
        struct sockaddr_vm my_addr = {
#ifdef WITH_VMWARE_VMCI
                .svm_family = AF_UNSPEC,
#else
                .svm_family = AF_VSOCK,
#endif
        };

#ifdef WITH_VMWARE_VMCI
        unsigned int version;

        version = VMCISock_Version();
        if (version == VMCI_SOCKETS_INVALID_VERSION) {
                perror("VMCI");
                goto err_out;
        }
        DEBUG("VMCI: version=%d.%d.%d",
              VMCI_SOCKETS_VERSION_EPOCH(version),
              VMCI_SOCKETS_VERSION_MAJOR(version),
              VMCI_SOCKETS_VERSION_MINOR(version));
        my_addr.svm_family = VMCISock_GetAFValueFd(&(sb->vmci_fd));
        if (my_addr.svm_family == -1){
                perror("VSOCK");
                goto err_out;
        }
        DEBUG("VMCI: address family at %d", my_addr.svm_family);
#endif

        if (!uri->hostText.first || !uri->portText.first){
                fprintf(stderr, "%s: VMCI CID and port must be specified: %s\n",
                        progname, hsfs_opts->target_spec);
                goto err_out;
        }
        if (uri->userInfo.first || *uri->portText.afterLast != 0){
                fprintf(stderr, "%s: Unsupported URI schema: %s\n",
                        progname, hsfs_opts->target_spec);
                goto err_out;
        }
        if (uri->hostText.first[0] == '*')
                my_addr.svm_cid = VMADDR_CID_ANY;
        else {
                char *end = NULL;
                long int l = strtol(uri->hostText.first, &end, 0);
                if ((end != uri->hostText.afterLast) || l < 0
                    || l >= -1U || l == LONG_MAX){
                        fprintf(stderr, "%s: Invalid CID number: %s\n",
                                progname, hsfs_opts->target_spec);
                        goto err_out;
                }
                DEBUG("GET ICD %d\n", l);
        }


        sockfd = socket(AF_VSOCK, SOCK_DGRAM, 0);
        if (sockfd == -1){
                perror(progname);
                goto err_out;
        }


        DEBUG("URI->hostText: %s, %d\n", uri->hostText.first, uri->hostText.afterLast - uri->hostText.first);
        DEBUG("URI->portText: %s, %d\n", uri->portText.first, uri->portText.afterLast - uri->portText.first);
err_out:
        return 1;
}

struct hsfs_fs_type {
        const char *name;
        int (*fill_super)(struct hsfs_super *, struct hsfs_cmdline_opts *);
        void (*kill_super)(struct hsfs_super *);
} hsfs_fs_type_list [] = {
        {
                .name = "unix",
                .fill_super = hsfs_start_unix_client,
        },
        {
                .name = "vmci",
                .fill_super = hsfs_start_vmci_client,
        },
        {
                .name = "unix",
                .fill_super = hsfs_start_unix_server,
        },
        {
                .name = "vmci",
                .fill_super = hsfs_start_vmci_server,
        }
};

int hsfs_fill_super(struct hsfs_super *sb, struct hsfs_cmdline_opts *hsfs_opts)
{
        UriUriA *uri = &(hsfs_opts->target_uri);
        struct hsfs_fs_type *fs_list, *fs = NULL;
        int i, ret = 0;

        DEBUG("URI->scheme: %s, %d\n", uri->scheme.first, uri->scheme.afterLast - uri->scheme.first);

        if (hsfs_opts->is_client){
                sb->type = HSFS_SB_CLIENT;
                fs_list = hsfs_fs_type_list;
        }
        else {
                sb->type = HSFS_SB_CLIENT;
                fs_list = hsfs_fs_type_list + 2;
        }

        for (i = 0; i < 2; i++){
                if (!strncmp(uri->scheme.first, fs_list[i].name,
                             uri->scheme.afterLast - uri->scheme.first)){
                        fs = fs_list + i;
                        break;
                }
        }
        if (!fs){
                fprintf(stderr, "%s: Unsupported URI schema: %s\n",  progname, hsfs_opts->target_spec);
                ret = 1;
                goto out;
        }

        return fs->fill_super(sb, hsfs_opts);

out:
        return ret;
}

void hsfs_destroy_super(struct hsfs_super *sb)
{
        if (!is_client(sb)){
                struct lo_data *lo = &(sb->u.lo_data);

                while (lo->root.next != &(lo->root))
                        lo_free(lo->root.next);
                if (lo->root.fd >= 0)
                        close(lo->root.fd);
        }
}

int main(int argc, char **argv)
{
        struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
        struct fuse_cmdline_opts opts;
	struct fuse_session *se = NULL;
	struct hsfs_super super;
        struct hsfs_cmdline_opts hsfs_opts;
	int err = -1;

	bzero(&super, sizeof(struct hsfs_super));

	progname = basename(argv[0]);

        /* It actually never returns on errors. */
        err = hsfs_parse_cmdline(&args, &opts, &hsfs_opts);
	if (err != 0)
		goto out;

        err = hsfs_fill_super(&super, &hsfs_opts);
	if (err)
		goto out;

        se = fuse_session_new(&args, &hsfs_oper, sizeof(hsfs_oper), &super);
        if (se == NULL)
                goto err_out1;

        if (fuse_set_signal_handlers(se) != 0)
                goto err_out2;

        if (is_client(&super))
                err = fuse_session_mount(se, opts.mountpoint);
        else
                err = fuse_session_socket(se, super.fd);
        if (err)
                goto err_out3;

        fuse_daemonize(opts.foreground);

        if (is_client(&super))
                err = hsfs_redirect_loop(se, &super);
        else if (opts.singlethread)
			err = fuse_session_loop(se);
        else
                err = fuse_session_loop_mt(se, opts.clone_fd);

        if (is_client(&super))
                fuse_session_unmount(se);
err_out3:
        fuse_remove_signal_handlers(se);
err_out2:
        fuse_session_destroy(se);
err_out1:
        hsfs_destroy_super(&super);
out:
        if (opts.mountpoint != NULL)
                free(opts.mountpoint);
        if (hsfs_opts.target_spec)
                free(hsfs_opts.target_spec);
	fuse_opt_free_args(&args);

	return err ? 1 : 0;
}
