dnl Process this file with autoconf 2.69+ to produce a configure script.
dnl
dnl Copyright (c) 2018 NIC.br  <medicoes@simet.nic.br>
dnl
dnl This program is free software: you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation, either version 3 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program.  If not, see <http://www.gnu.org/licenses/>.

AC_PREREQ([2.69])
AC_INIT([simet-ma], m4_esyscmd_s([./version.sh]),
        [medicoes@simet.nic.br],
        [simet-ma],
        [http://simet.nic.br])
AC_COPYRIGHT([Copyright (c) 2018 NIC.br <medicoes@simet.nic.br>])

AC_CONFIG_AUX_DIR([.])
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([1.13 tar-pax gnu no-dist-gzip dist-xz -Wall])
AC_CONFIG_FILES([Makefile simet-api/Makefile cmake-projects/Makefile])
AC_CONFIG_SUBDIRS([twamp-client-c tcpbw-client-c inetup-client-c simet-runner])
AC_SUBST([CONFIG_STATUS_DEPENDENCIES], ['$(top_srcdir)/version.sh $(top_srcdir)/version'])

dnl MKDIR_P is used by our makefiles
AC_PROG_MKDIR_P

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
	   [AC_MSG_NOTICE([building for SIMETBOX (OpenWRT)])] )

AC_OUTPUT
