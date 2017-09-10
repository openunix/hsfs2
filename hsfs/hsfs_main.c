/*
 * Copyright (C) 2012, 2017 Feng Shuo <steve.shuo.feng@gmail.com>
 *
 * This file is part of VirtFS.
 *
 * VirtFS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * VirtFS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with VirtFS.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#define FUSE_USE_VERSION 30

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

/*
 * This file is the fuse filesystem implementation of VirtFS, by some
 * historic reasons, it was named as "HSFS". The "hsfs_" prefix is
 * kept as a shortcut for "virtfs_fuse_", to avoid conflicts with
 * VirtFS library naming ("virtfs_").
 */
struct hsfs_cmdline_opts {
        char *mountspec;
        char *netid;
};

/* VirtFS fuse super */
struct hsfs_super {
        struct hsfs_cmdline_opts opts;
        int flags;
        struct fuse_conn_info *conn;
        int bufsize;
        int sock;
};

/* For flags */
#define HSFS_SB_VIRTFS 0x0001

/* Debug */
#ifndef unlikely
# define unlikely(x)	__builtin_expect((x),0)
#endif	/* unlikely */
int __INIT_DEBUG = 0;
#define DEBUG(fmt, args...) do {                                        \
                if (unlikely(__INIT_DEBUG))                             \
                        fprintf(stderr, fmt "\n", ##args);              \
        }while(0)
#define DUMP_FUSE_CONN(c) do {                                          \
                DEBUG("Fuse conn(%p), Kernel_VER(%d.%d) FUSE_VER(%d, %d)", c, \
                      (c)->proto_major, (c)->proto_minor,               \
                      FUSE_MAJOR_VERSION, FUSE_MINOR_VERSION);          \
        }while(0)
#define DUMP_HSFS_OPTS(o) do {                                          \
                DEBUG("HSFS Opt mountspec: %s", (o)->mountspec);        \
                DEBUG("HSFS Opt netid: %s", (o)->netid);                \
        }while(0)
#define DUMP_HSFS_SUPER(s) do {                                         \
                DEBUG("HSFS Super(%p), flags(0x%x)", s, (s)->flags);    \
                DUMP_HSFS_OPTS(&(s->opts));                             \
        }while(0)
#define DUMP_FUSE_OPT(o) do {                                           \
                DEBUG("fuse_cmdline_opts: single thread(%d)", (o)->singlethread); \
        }while(0)
#define BUG_ON(exp) assert(!(exp))

char *progname = NULL;

#define FUSE_URI_SCHEME "fuse://"
#define FUSE_URI_SCHEME_LEN 7

#define KERNEL_BUF_PAGES 32
#define HEADER_SIZE 0x1000

static void exit_usage(int err)
{
	printf("usage: %s remotetarget dir [-rvVwfnh] [-t version] [-o hsfsoptions]\n", progname);
	printf("options:\n\t-r\t\tMount file system readonly\n");
	printf("\t-v\t\tVerbose\n");
	printf("\t-V\t\tPrint version\n");
	printf("\t-w\t\tMount file system read-write\n");
	printf("\t-f\t\tForeground, not a daemon\n");
	printf("\t-n\t\tDo not update /etc/mtab\n");
	printf("\t-h\t\tPrint this help\n");
	printf("\tversion\t\thsfs - currently, the only choice\n");
	printf("\thsfsoptions\tRefer mount.hsfs(8) or hsfs(5)\n\n");
        fuse_cmdline_help();
        fuse_lowlevel_help();
	exit(err);
}

static void print_version(void)
{
	printf("%s.\n", PACKAGE_STRING);
        printf("FUSE library version %s\n", fuse_pkgversion());
        fuse_lowlevel_version();
	exit(0);
}

static void hsfs_fuse_init(void *userdata, struct fuse_conn_info *conn)
{
	struct hsfs_super *sb = (struct hsfs_super *)userdata;

        BUG_ON(sb->conn);
        sb->conn = conn;

        DUMP_FUSE_CONN(conn);
        DUMP_HSFS_SUPER(sb);

        /* There is no way to return any errors during init. */
}

static struct fuse_lowlevel_ops hsfs_oper = {
        .init = hsfs_fuse_init,
#ifdef BUILD_VIRTFS
	.getattr = hsx_fuse_getattr,
	.statfs = hsx_fuse_statfs,
	.lookup = hsx_fuse_lookup,
	.mkdir = hsx_fuse_mkdir,
	.open = hsx_fuse_open,
	.release = hsx_fuse_release,
	.read = hsx_fuse_read,
	.write = hsx_fuse_write,
	.setattr = hsx_fuse_setattr,
	.forget = hsx_fuse_forget,
	.rmdir = hsx_fuse_rmdir,
	.unlink = hsx_fuse_unlink,
	.readlink = hsx_fuse_readlink,
	.symlink = hsx_fuse_symlink,
	.rename = hsx_fuse_rename,
	.readdir = hsx_fuse_readdir,
	.opendir = hsx_fuse_opendir,
	.mknod = hsx_fuse_mknod,
	.link = hsx_fuse_link,
	.create = hsx_fuse_create,
	.access = hsx_fuse_access,
	.getxattr = hsx_fuse_getxattr,
	.setxattr = hsx_fuse_setxattr,
	.readdirplus = hsx_fuse_readdir_plus,
#endif
};


static const struct fuse_opt hsfs_cmdline_spec[] = {
        {"proto=%s", offsetof(struct hsfs_cmdline_opts, netid), 0},
        FUSE_OPT_END
};


static int hsfs_cmdline_proc(void *data, const char *arg, int key,
                             struct fuse_args *outargs __attribute__((unused)))
{
        struct hsfs_cmdline_opts *opts = data;

        switch (key) {
        case FUSE_OPT_KEY_NONOPT:
                if (!opts->mountspec)
                        return fuse_opt_add_opt(&opts->mountspec, arg);
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

        ret = fuse_opt_parse(args, hsfs_opts, hsfs_cmdline_spec, hsfs_cmdline_proc);
        if (ret != 0)
                goto out_usage;

        ret = fuse_parse_cmdline(args, fuse_opts);

        if (ret != 0)
                goto out_usage;

        if (fuse_opts->show_help)
                goto out_usage;
        else if (fuse_opts->show_version) {
                print_version();
                goto out;
        }

        __INIT_DEBUG = fuse_opts->debug;

#ifndef BUILD_VIRTFS
        ret = strncmp(hsfs_opts->mountspec, FUSE_URI_SCHEME,
                      FUSE_URI_SCHEME_LEN);
        if (ret != 0){
                printf("Only " FUSE_URI_SCHEME " is supported.\n");
                goto out;
        }
#endif

        return 0;

out_usage:
        exit_usage(ret);
        /* Never reach here... */
out:
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
                int res = fuse_session_receive_buf(se, &fbuf);

                if (res == -EINTR)
                        continue;
                if (res <= 0)
                        break;

                if (fbuf.flags == FUSE_BUF_IS_FD)
                        err = splice(fbuf.fd, NULL, sb->sock, NULL, res, 0);
                else if (fbuf.flags == 0)
                        err = send(sb->sock, fbuf.mem, res, 0);
                else
                        BUG_ON(fbuf.flags);

                if (err != res){
                        err = errno;
                        break;
                }
        }

        if (fbuf.mem)
                free(fbuf.mem);

        /* XXX: No exported API to handle the error */
        /* if(se->error != 0) */
        /*         res = se->error; */
        fuse_session_reset(se);
        return err;
}

int hsfs_fill_super(struct hsfs_super *sb, struct fuse_cmdline_opts *fuse_opts)
{
        struct hsfs_cmdline_opts *hsfs_opts = &(sb->opts);
        struct sockaddr_un addr_serv;
        int err = 0;

        DUMP_HSFS_SUPER(sb);
        DUMP_FUSE_OPT(fuse_opts);

        sb->bufsize = KERNEL_BUF_PAGES * getpagesize() + HEADER_SIZE;

        sb->sock = socket(PF_UNIX, SOCK_STREAM, 0);
        if (sb->sock < 0){
                err = errno;
                perror(progname);
                goto out;
        }

        memset(&addr_serv, 0, sizeof(addr_serv));
        addr_serv.sun_family = AF_UNIX;
        strncpy(addr_serv.sun_path, hsfs_opts->mountspec + FUSE_URI_SCHEME_LEN, 108);

        err = connect(sb->sock, (struct sockaddr *)&addr_serv, sizeof(addr_serv));
        if (err){
                err = errno;
                perror(progname);
                goto out1;
        }

        return 0;

out1:
        close(sb->sock);
out:
        return err;
}

void hsfs_destroy_super(struct hsfs_super *sb)
{
        DUMP_HSFS_SUPER(sb);
}

int main(int argc, char **argv)
{
        struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
        struct fuse_cmdline_opts opts;
	struct fuse_session *se = NULL;
	struct hsfs_super super;
	int err = -1;

        /* struct hsfs_super contains struct hsfs_cmdline_opts, zero
         * it before parse cmdline option. */
	bzero(&super, sizeof(struct hsfs_super));

	progname = basename(argv[0]);

	if (argc < 3)
		exit_usage(1);

        /* It actually never returns on errors. */
        err = hsfs_parse_cmdline(&args, &opts, &super.opts);
	if (err != 0)
		goto out;

        err = hsfs_fill_super(&super, &opts);
	if (err)
		goto out;

        se = fuse_session_new(&args, &hsfs_oper, sizeof(hsfs_oper), &super);
        if (se == NULL)
                goto err_out1;

        if (fuse_set_signal_handlers(se) != 0)
                goto err_out2;

        if (fuse_session_mount(se, opts.mountpoint) != 0)
                goto err_out3;

        fuse_daemonize(opts.foreground);

        if (!(super.flags & HSFS_SB_VIRTFS))
                err = hsfs_redirect_loop(se, &super);
        else if (opts.singlethread)
			err = fuse_session_loop(se);
        else
                err = fuse_session_loop_mt(se, opts.clone_fd);

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
	fuse_opt_free_args(&args);

	return err ? 1 : 0;
}
