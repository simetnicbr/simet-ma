Fast-and-dirty build instructions
=================================

For OpenWRT, look at the simetbox-openwrt-feed package from simetnicbr,
instead.  The instructions in this file are for the native simet-ma
client, which targets standard desktop/server Linux distributions.

1. Install dependencies (refer to docker/Dockerfile, it has them all)
   or install and configure a recent enough docker-ce.

   Basically, the essential build packages, GNU autotools (automake,
   autoconf, libtool, gettext/autopoint, GNU config), and the development
   packages for json-c, libcurl, gcc.

   You will also need CMake for the embedded copy of libubox.  We can use
   the system libubox just fine (there are no local changes), but it is
   usually only available on OpenWRT.

2. Generate the build tooling:
   run ./autogen.sh from the top level source directory.  You need the GNU
   autotools suite (recent version) for this.

3. Generate the real Makefile:
   From the top level source directory, run ./configure to create the
   Makefile.  configure --help will give you hints.

   The Debian packaging uses, for example:

   ./configure --prefix=/opt/simet --localstatedir=/var \
               --libdir=/opt/simet/lib --sysconfdir=/opt/simet/etc

4a. Using docker to build (and run):

   WARNING: the top level source directory is used as the docker context,
   so you very very likely want the source directory to be *clean* before
   running the commands in the docker-build target.

   Refer to docker/README* for docker-specific details.

4b. Native build:
   make
   make install

   make install supports DESTDIR, e.g. make install DESTDIR=/tmp/simet-ma


Debian package
==============

There is a working Debian packaging in debian/, it is known to work on
Debian 8, Debian 9, Ubuntu LTS 16.04 and Ubuntu LTS 18.04.

To create the binary and source packages:
   install debhelper and other build dependencies (listed in debian/control)
   dpkg-buildpackage -uc -us


Tarball source package
======================

Do steps 1-3 above.

make dist-xz


Tarball binary package
======================

Do steps 1-3 above.
make bin-dist

Refer to the bin-dist target in the top level Makefile.am for details.


CAVEATS
=======

The automake + cmake integration in this package is currently incomplete,
and this breaks some automake features like "make dist-check", which have
no direct equivalent in CMake.

Eventually we will either switch entirely to CMake, or to automake.

