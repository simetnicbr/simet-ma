dnl Process this file with autoconf 2.69+ to produce a configure script.
dnl
dnl Copyright (c) 2018,2019 NIC.br <medicoes@simet.nic.br>
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
AC_INIT([simet-ma-runner], m4_esyscmd_s([./version.sh]),
        [medicoes@simet.nic.br],
        [simet-ma-runner],
        [http://simet.nic.br])
AC_COPYRIGHT([Copyright (c) 2018,2019 NIC.br <medicoes@simet.nic.br>])

AC_CONFIG_AUX_DIR([.])
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([1.13 foreign tar-pax no-dist-gzip dist-xz -Wall])
AC_CONFIG_FILES([Makefile])
AC_SUBST([CONFIG_STATUS_DEPENDENCIES], ['$(top_srcdir)/version.sh $(top_srcdir)/version'])

if test ! -r version ; then
	echo "$PACKAGE_VERSION" > version
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
	   [AC_MSG_NOTICE([building for SIMETBOX (OpenWRT)])])

AC_OUTPUT
