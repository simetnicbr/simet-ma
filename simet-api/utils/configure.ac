dnl Process this file with autoconf 2.69+ to produce a configure script.
dnl
dnl Copyright (c) 2024 NIC.br <medicoes@simet.nic.br>
dnl
dnl This program is free software: you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation, either version 3 of the License, or
dnl (at your option) any later version.  In every case, additional
dnl restrictions and permissions apply, refer to the COPYING file in the
dnl program Source for details.
dnl
dnl This program is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl General Public License and the COPYING file in the program Source
dnl for details.

AC_PREREQ([2.69])
AC_INIT([simet-api-utils], m4_esyscmd_s([./version.sh]),
        [],
        [simet-api-utils],
        [])
AC_COPYRIGHT([Copyright (c) 2024 NIC.br <medicoes@simet.nic.br>])

AC_CONFIG_SRCDIR([src])
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([1.13 gnu tar-pax no-dist-gzip dist-xz -Wall])
AC_CONFIG_HEADERS([simet-api-utils_config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_SUBST([CONFIG_STATUS_DEPENDENCIES], ['$(top_srcdir)/version.sh $(top_srcdir)/version'])

if test ! -r version ; then
	echo "$PACKAGE_VERSION" > version
fi

dnl Work around the lack of a way to set preferred *FLAGS
AC_ARG_ENABLE([extend-flags],
    [AC_HELP_STRING([--enable-extend-flags],
        [force configure to extend already-defined C/CPP/LDFLAGS])],
    [
        AC_MSG_NOTICE([will extend C/CPP/LDFLAGS])
        enable_cflags_setting=yes
        enable_cppflags_setting=yes
        enable_ldflags_setting=yes
    ],
    [
        AC_MSG_CHECKING([whether configure.ac should try to override CFLAGS])
        if test "x${CFLAGS+set}" = xset; then
            enable_cflags_setting=no
        else
            enable_cflags_setting=yes
        fi
        AC_MSG_RESULT($enable_cflags_setting)

        dnl AC_MSG_CHECKING([whether configure.ac should try to override CPPFLAGS])
        dnl if test "x${CPPFLAGS+set}" = xset; then
        dnl     enable_cppflags_setting=no
        dnl else
        dnl     enable_cppflags_setting=yes
        dnl fi
        dnl AC_MSG_RESULT($enable_cppflags_setting)

        AC_MSG_CHECKING([whether configure.ac should try to override LDFLAGS])
        if test "x${LDFLAGS+set}" = xset; then
            enable_ldflags_setting=no
        else
            enable_ldflags_setting=yes
        fi
        AC_MSG_RESULT($enable_ldflags_setting)
    ])

dnl Before we get to the C compiler...
AC_USE_SYSTEM_EXTENSIONS

dnl Checks for programs
AC_PROG_CC

dnl Try to ask for C11, required on ancient OpenWRT
AX_CHECK_COMPILE_FLAG([-std=gnu11],
    [AX_APPEND_FLAG([-std=gnu11])],
    [AX_CHECK_COMPILE_FLAG([-std=c11],
	[AX_APPEND_FLAG([-std=c11])],
	[AC_MSG_WARN([Could not enforce a C11 or later compiler mode for C, compilation may fail])
	 AC_PROG_CC_STDC])
])

# Checks for library functions.
dnl AC_FUNC_REALLOC
dnl AC_FUNC_STAT
dnl AC_CHECK_FUNCS([memset strcasecmp strdup strerror strrchr strtoul timegm])

# Allow GNU Argp as a standalone lib, as an alternative to glibc
dnl AC_SEARCH_LIBS([argp_parse], [argp], [],
dnl    [AC_ERROR([An implementation of GNU Argp was not found, please install libargp])])

dnl important system extensions
dnl AC_SYS_LARGEFILE
dnl AC_CHECK_FUNCS([flockfile fgets_unlocked])

dnl -----------------
dnl Configure options
dnl -----------------

AC_ARG_ENABLE([valgrind-build],
    [AS_HELP_STRING([--enable-valgrind-build],
        [build for valgrind testing])],
    [AS_IF([test "x$enableval" != "xno"],
               [AC_DEFINE(VALGRIND_BUILD, [], [Valgrind-friendly build])])
    ])

dnl -------------------------------------------
dnl Override hardcoded *FLAGS for GCC and Clang
dnl If this breaks your platform, file a bug
dnl -------------------------------------------

dnl Do it after most of the autoconf crap, as they tend to screw
dnl up when you have anything more complex than -O2 -g for CFLAGS.

dnl We could do most of these overrides through AM_*FLAGS, but
dnl that's a pain for distros and users to override (as in it breaks
dnl 'make CFLAGS="-O0"') and only to be used for stuff that is
dnl absolutely essential to the build.

dnl if test "${GCC}${enable_cppflags_setting}" = "yesyes" ; then
dnl     CPPFLAGS="<whatever>"
dnl fi
if test "x${GCC}${enable_cflags_setting}" = "xyesyes" ; then
    dnl We need to detect -Wunknown-warning without the use of -Werror.
    dnl -Werror would be unsafe, as it might eventually trigger on the
    dnl test source code.
    dnl
    dnl clang needs "-Werror=unknown-warning-option".
    dnl gcc exits with an error when trying to enable unknown warnings.
    AX_CHECK_COMPILE_FLAG([-Werror=unknown-warning-option],
        [CFLAGSERRUW="-Werror=unknown-warning-option"],
        [],
        [],
        [AC_LANG_SOURCE([[
            int
            main(void)
            {

                ;
                return 0;
            }
        ]])])

    dnl gcc and clang warnings the code is not supposed to trigger...
    AX_APPEND_COMPILE_FLAGS(
        [-O3 -Wall -Wextra -Wformat=2 -Werror=format-security dnl
         -Wformat-signedness -Wformat-overflow=2 -Wformat-truncation=2 dnl
         -Wtrampolines -Wcast-align -Wsign-conversion -Wnull-dereference dnl
         -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations dnl
         -Wredundant-decls -Wstrict-overflow -Wconversion -Winit-self -Wshadow dnl
         -Wrestrict -Wpointer-arith -Wlogical-op -Wbad-function-cast dnl
         -Wwrite-strings -Wduplicated-branches -Wduplicated-cond dnl
         -Walloca -Wvla -Walloc-zero -Walloc-size-larger-than=10240000],
        [],
        [${CFLAGSERRUW}],
        [AC_LANG_SOURCE([[
            int
            main(void)
            {

                ;
                return 0;
            }
        ]])])

    dnl Do not move _FORTIFY_SOURCE to CPPFLAGS, otherwise bad things
    dnl happen when the user does 'make CFLAGS="-O0 -g"'.  Debian/Ubuntu
    dnl have fixes for this, but others don't.  We keep it in CFLAGS
    dnl where it will get overriden along with -O3/-O2.
    AC_MSG_CHECKING([whether _FORTIFY_SOURCE is already enabled])
    AC_LINK_IFELSE(
        [AC_LANG_SOURCE([[
            int
            main(void) {
            #ifndef _FORTIFY_SOURCE
                return 0;
            #else
            #error _FORTIFY_SOURCE already defined
            #endif
            }
        ]])],
        [
            AC_MSG_RESULT([no])
            dnl gcc manual says to avoid -Wp,-D like the plague and use
            dnl -D/-U directly.
            AX_APPEND_COMPILE_FLAGS([-D_FORTIFY_SOURCE=2], [], [],
                [AC_LANG_SOURCE([[
                    int
                    main(int argc, char *argv[])
                    {
                        char arr[64], *dst = arr, *src = argv[0];
                        if (argc && src) { while (*src) { *dst++ = *src++; } }
                            return 0;
                    }
                ]])])
        ],
        [
            AC_MSG_RESULT([yes])
        ])

    AX_APPEND_COMPILE_FLAGS([-fstack-protector-strong -Wstack-protector],
        [],
        [],
        [AC_LANG_SOURCE([[
            int
            main(int argc, char *argv[])
            {
                char arr[64], *dst = arr, *src = argv[0];
                if (argc && src) { while (*src) { *dst++ = *src++; } }
                    return 0;
            }
        ]])])
fi
if test "x${GCC}${enable_ldflags_setting}" = "xyesyes" ; then
    AX_APPEND_LINK_FLAGS([-Wl,-z,relro -Wl,-z,now], [], [],
        [AC_LANG_SOURCE([[
            int
            main(int argc, char *argv[])
            {
                char arr[64], *dst = arr, *src = argv[0];
                if (argc && src) { while (*src) { *dst++ = *src++; } }
                    return 0;
            }
        ]])])
fi
if test "x${GCC}${enable_ldflags_setting}${enable_cflags_setting}" = "xyesyesyes" ; then
    AC_MSG_NOTICE([checking for Position Independent Executables (PIE) support])
    OCFLAGS="${CFLAGS}"
    AX_CHECK_COMPILE_FLAG([-fPIE],
        [
            CFLAGS="${CFLAGS} -fPIE"
            AX_CHECK_LINK_FLAG([-fPIE -pie],
                [LDFLAGS="${LDFLAGS} -fPIE -pie"
                 AC_MSG_NOTICE([PIE generation enabled])],
                [CFLAGS="${OCFLAGS}"
                 AC_MSG_NOTICE([PIE generation not supported by linker])],
                [],
                [AC_LANG_SOURCE([[
                    int
                    main(void)
                    {

                        ;
                        return 0;
                    }
                ]])])
        ],
        [AC_MSG_NOTICE([PIE generation not supported by compiler])],
        [],
        [AC_LANG_SOURCE([[
            int
            main(void)
            {

                ;
                return 0;
            }
        ]])])
fi

AC_ARG_ENABLE([simetbox],
    [AC_HELP_STRING([--enable-simetbox],
        [build for SIMETBOX (OpenWRT)])],
    [case "${enableval}" in
        yes) simetbox=true ;;
        no)  simetbox=false ;;
        *) AC_MSG_ERROR([bad value ${enableval} for --enable-simetbox]) ;;
     esac],
    [simetbox=false])
AM_CONDITIONAL([SIMETBOX_BUILD], [test x$simetbox = xtrue])
AM_COND_IF([SIMETBOX_BUILD],
	   [
	      AC_MSG_NOTICE([building for SIMETBOX (OpenWRT)])
	      AC_DEFINE([IS_SIMETBOX_BUILD], [], [Is a SIMETBOX build])
	   ] )

dnl --------------------------
dnl autoconf output generation
dnl --------------------------

AC_MSG_NOTICE([project-wide base CPPFLAGS: $CPPFLAGS])
AC_MSG_NOTICE([project-wide base CFLAGS:   $CFLAGS])
AC_MSG_NOTICE([project-wide base LDFLAGS:  $LDFLAGS])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
