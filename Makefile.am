
ACLOCAL_AMFLAGS = -I m4

if BUILD_FUSE
  FUSE_DIR = fuse
endif

if BUILD_NFS3
  NFS3_DIR = nfs3
  NFSC_DIR = nfs_common lib
endif

SUBDIRS = $(FUSE_DIR) $(NFS3_DIR) $(NFSC_DIR) hsfs man
