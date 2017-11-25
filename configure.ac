#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_INIT([hsfs], [0.4])
AC_PREREQ([2.60])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([hsfs/hsfs_main.c])
AC_CONFIG_HEADERS([include/config.h])

AM_INIT_AUTOMAKE([foreign])

# SLES 11SP2 (automake-1.10.1) doesn't have this
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Cygwin put tirpc into /usr/include/tirpc.
AC_SUBST([TIRPC_HEADERS])
AC_ARG_WITH([tirpc-headers],
	[AC_HELP_STRING([--with-tirpc-headers=<path>], [Alternative path to tirpc headers])],
	[TIRPC_HEADERS="-I $withval"
	case $BWLABELDIR in
     	     /*) ;;
     	     *) BWLABELDIR="`pwd`/$BWLABELDIR" ;;
	esac])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AM_PROG_CC_C_O

AC_GNU_SOURCE

AC_PROG_LIBTOOL

# Checks for libraries.
AC_ARG_WITH([system-fuse],
        [AS_HELP_STRING([--without-system-fuse],
                [build without system fuse (requires git access to github)])],
        [],
        [with_system_fuse=yes])
AS_IF([test "x$with_system_fuse" == xyes],
        [AC_CHECK_LIB([fuse3], [fuse_session_socket], [],
                [no_fuse_lib=yes])],
        [AS_IF([test -f "fuse/configure.ac"], [],
                [no_fuse_lib=yes])])
AS_IF([test "x$no_fuse_lib" == xyes],
        AC_MSG_ERROR([
FUSE (libfuse) version >= 3.0.0 with fuse_session_socket support not present.
Your options:
  (1) Preferred: Install the FUSE (libfuse 3.0.0 or higher) with support of
      "fuse_session_socket" devel package
  (2) Fetch the FUSE submodule by using below command and ./configure --without-system-fuse
      git submodule update --init fuse]))

if test "x$with_system_fuse" != "xyes"; then
        source_dir=$(pwd)
        cd fuse && ./makeconf.sh
        [[ $? != 0 ]] && no_fuse_lib=yes
        cd $source_dir
        # Broken FUSE tree
        AS_IF([test "x$no_fuse_lib" == xyes],
               AC_MSG_ERROR([
FUSE submodule broken ("git submodule update --init fuse" required?)]),
               AC_CONFIG_SUBDIRS([fuse]))
fi

AM_CONDITIONAL([BUILD_FUSE], [test x"$with_system_fuse" != xyes])
AM_CONDITIONAL([BUILD_NFS3], [test x"$with_nfs3" == xyes])

AC_CHECK_LIB([uriparser], [uriParseUriA], [], AC_MSG_ERROR([You need uriparser to run.]))

# Checks for header files.
AC_HEADER_ASSERT
AC_HEADER_DIRENT
AC_HEADER_MAJOR
AC_HEADER_RESOLV
AC_HEADER_STAT
AC_HEADER_STDBOOL

AC_CHECK_HEADERS([arpa/inet.h fcntl.h libintl.h limits.h memory.h mntent.h netdb.h netinet/in.h paths.h stdlib.h string.h sys/mount.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for types.
AC_TYPE_INT32_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T


# Checks for structures
AC_CHECK_MEMBERS([struct stat.st_atim])
AC_CHECK_MEMBERS([struct stat.st_atimespec])

# Check for compiler characteristics.
AC_C_INLINE

# Checks for library functions.

# Check for system service
AC_SYS_LARGEFILE

#
# If we're running GCC or clang define _U_ to be "__attribute__((unused))"
# so we can use _U_ to flag unused function parameters and not get warnings
# about them. Otherwise, define _U_ to be an empty string so that _U_ used
# to flag an unused function parameters will compile with other compilers.
#
# XXX - similar hints for other compilers?
#
if test "x$GCC" = "xyes" -o "x$CC" = "xclang" ; then
  AC_DEFINE(_U_, __attribute__((unused)), [Hint to the compiler that a function parameters is not used])
else
  AC_DEFINE(_U_, , [Hint to the compiler that a function parameters is not used])
fi



AC_SUBST([VMWARE_FLAGS])
AC_ARG_WITH([vmware-vmci],
        [AS_HELP_STRING([[--with-vmware-vmci[=path]]], [build with VMware VMCI/VSOCK headers (default at /usr/lib/vmware/include).])],
        [with_vmware_vmci=$withval],
        [with_vmware_vmci=no])
AS_IF([test "x$with_vmware_vmci" == xno],
        [AC_CHECK_HEADERS([linux/vm_sockets.h], [],
                [AC_MSG_ERROR([cannot find linux/vm_sockets.h, try use VMware VMCI/VSOCK headers with --with-vmware-vmci.])],
                [#include <sys/socket.h>])],
        [AS_IF([test "x$with_vmware_vmci" == xyes],
                [VMWARE_FLAGS="-I/usr/lib/vmware/include -DWITH_VMWARE_VMCI"],
                [VMWARE_FLAGS="-I$with_vmware_vmci -DWITH_VMWARE_VMCI"])])


AC_CONFIG_FILES([Makefile
                 hsfs/Makefile
                 nfs3/Makefile
                 man/Makefile
		 lib/Makefile
		 nfs_common/Makefile
		])
AC_OUTPUT
