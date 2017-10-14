
AM_CFLAGS = -Wall -Wextra

if BUILD_FUSE
  FUSE_FLAGS = -I../fuse/include -D_FILE_OFFSET_BITS=64
  FUSE_LIB = $(top_builddir)/fuse/lib/libfuse3.la
else
  FUSE_FLAGS = `pkg-config fuse3 --cflags`
endif

AM_CPPFLAGS = $(FUSE_FLAGS)

bin_PROGRAMS = hsfs
hsfs_LDADD = $(FUSE_LIB) $(NFS3_LIB) $(NFSC_LIB) # $(top_builddir)/lib/libhsfs.a
hsfs_SOURCES = hsfs_main.c

if BUILD_NFS3
  NFS3_LIB = $(top_builddir)/nfs3/libhsi_nfs3.a
  NFSC_LIB = $(top_builddir)/nfs_common/libhsi_nfsc.a
  NFS3_FLAGS = -DBUILD_NFS3
noinst_LIBRARIES = libhsx_fuse.a
libhsx_fuse_a_CPPFLAGS = $(AM_CFLAGS) -g -Wall -I/usr/include/tirpc/ \
			`pkg-config fuse --cflags`
libhsx_fuse_a_SOURCES = hsx_fuse_getattr.c hsx_fuse_statfs.c hsx_fuse_init.c \
			hsx_fuse_lookup.c hsx_fuse_fill_reply.c hsx_fuse_mkdir.c \
			hsx_fuse_read.c hsx_fuse_write.c hsx_fuse_open.c hsx_fuse_release.c \
			hsx_fuse_rmdir.c hsx_fuse_forget.c hsx_fuse_setattr.c \
			hsx_fuse_readlink.c hsx_fuse_symlink.c \
			hsx_fuse_unlink.c hsx_fuse_rename.c hsx_fuse_readdir.c \
			hsx_fuse_opendir.c hsx_fuse_setxattr.c \
			hsx_fuse_mknod.c hsx_fuse_link.c hsx_fuse_create.c \
			hsx_fuse_access.c hsx_fuse_getxattr.c hsx_fuse_stat2iattr.c
endif
