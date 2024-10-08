##
## Toplevel Makefile.am for simet-ma
## Copyright (c) 2018,2019 NIC.br <medicoes@simet.nic.br>
##
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.  In every case, additional
## restrictions and permissions apply, refer to the COPYING file in the
## program Source for details.
##
## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License and the COPYING file in the program Source
## for details.

SUBDIRS     = simet-api twamp-client-c tcpbw-client-c inetup-client-c simet-dnsaddr-c simet-runner cmake-projects
EXTRA_DIST  = autogen.sh version version.sh .dockerignore docker/ docs/

if ENABLE_SSPOOFER
SUBDIRS += sspoofer-client-c
endif

# we need to use an intermetiate variable, otherwise the shell dirties the
# repository creating the output file *before* running the version.sh script
version:
	VER=$$( $(top_srcdir)/version.sh ) && echo "$${VER}" > version

dist-local: version

# Creates a tarball of binaries, akin to how "make dist" creates a source distribution tarball
bin-dist: all
	test -d "$(abs_top_builddir)"
	-rm -rf "$(abs_top_builddir)/binary-dist"
	$(MKDIR_P) -- "$(abs_top_builddir)/binary-dist"
	$(MAKE) install-strip DESTDIR="$(abs_top_builddir)/binary-dist"
	tar zcf "${PACKAGE}-${VERSION}.binaries.tar.gz" --owner=root --group=root -C "$(abs_top_builddir)/binary-dist" .
	rm -rf "$(abs_top_builddir)/binary-dist"


# Docker examples
# run docker-build or docker-build-prod first, to get the image.
docker-build: clean
	@test -r docker/Dockerfile
	docker build --network host -t simet-ma:local -f docker/Dockerfile .
	@echo Unofficial image built and tagged as simet-ma:local.
	@echo To run the unofficial image you just built, do "make docker-simetma"

docker-build-prod: clean
	@test -r docker/Dockerfile.reference-container
	docker build --network host -t simet-ma:nicbr -f docker/Dockerfile.reference-container .
	@echo Image built from official simet-ma binaries and tagged as simet-ma:nicbr
	@echo To run the image, do "make docker-nicbr-simetma" or run it directly:
	@echo docker run --init -dt --network host --restart=unless-stopped --cap-add NET_ADMIN --cap-add NET_RAW --mount source=simet-ma-id,target=/opt/simet/etc/simet simet-ma:nicbr

docker-simetma:
	docker run --init -dt --rm --network host --cap-add NET_ADMIN --cap-add NET_RAW \
		--mount source=simet-ma-id,target=/opt/simet/etc/simet simet-ma:local

docker-nicbr-simetma:
	docker run --init -dt --network host --restart=unless-stopped \
		--cap-add NET_ADMIN --cap-add NET_RAW \
		--mount source=simet-ma-id,target=/opt/simet/etc/simet \
		simet-ma:nicbr

docker-twamp:
	docker run -t --rm --network host --mount source=simet-ma-id,target=/opt/simet/etc/simet \
		--cap-add NET_ADMIN --cap-add NET_RAW -e SIMET_RUN_TEST=TWAMP simet-ma:local

docker-tcpbw:
	docker run -t --rm --network host --mount source=simet-ma-id,target=/opt/simet/etc/simet \
		--cap-add NET_ADMIN --cap-add NET_RAW -e SIMET_RUN_TEST=TCPBW simet-ma:local

# SIMET internal: reminder of how to update the version file
.PHONY: bump-version
bump-version:
	-rm -f version
	$(top_srcdir)/version.sh > version
	-debchange -p --noquery -v "$(shell cat $(top_srcdir)/version | sed -e 's/^v//' -e 's/-/+/g' -e 's/+$$//')" -m "New release"
