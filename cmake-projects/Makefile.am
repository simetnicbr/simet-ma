# Automake <-> CMake impedence matching layer
#
#    all
#    clean
#    dist
#    distclean
#    install
#
#    distdir  (for dist/distcheck)
#
# CMake notes:
#    * must use out-of-source builds
#      and the CMake development team are holding back the world by refusing to
#      support -H, -B, so we have to do nasty hacks
#    * must manually adjust this file for each new projetc, to take advantage
#      of cmake -D

# something unlikely to be in a vendor source
cmake_build_subdir = simet-build-dir

EMPTY_AUTOMAKE_TARGETS = dvi pdf ps info html tags ctags
.PHONY: $(EMPTY_AUTOMAKE_TARGETS)
$(EMPTY_AUTOMAKE_TARGETS):

if SIMETBOX_BUILD
# we do not need these when doing an OpenWRT build
cmakeprojectsubdirs =
cmakeprojectdeps =
else
# we typically need these when not doing an OpenWRT build
cmakeprojectsubdirs = jsonpath
cmakeprojectdeps = jsonpath/$(cmake_build_subdir)/Makefile
endif

jsonpath/$(cmake_build_subdir)/Makefile: jsonpath/CMakeLists.txt
	(cd jsonpath && rm -fr "$(cmake_build_subdir)" && $(MKDIR_P) -- "$(cmake_build_subdir)" && \
	 cd "$(cmake_build_subdir)" && cmake -DCMAKE_INSTALL_PREFIX="$(prefix)" -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF ..) \
	|| exit $?

all-local: $(cmakeprojectdeps)
	for i in $(cmakeprojectsubdirs) ; do $(MAKE) -C "$$i/$(cmake_build_subdir)" all $(AM_MAKEFLAGS) ; done

check-local:
	for i in $(cmakeprojectsubdirs) ; do $(MAKE) -C "$$i/$(cmake_build_subdir)" test $(AM_MAKEFLAGS) ; done

clean-local:
	for i in $(cmakeprojectsubdirs) ; do $(MAKE) -C "$$i/$(cmake_build_subdir)" clean $(AM_MAKEFLAGS) ; rm -fr "$$i/$(cmake_build_subdir)" ; done

distclean-local: clean-local

install-cmake:
	for i in $(cmakeprojectsubdirs) ; do $(MAKE) -C "$$i/$(cmake_build_subdir)" install $(AM_MAKEFLAGS) ; done

install-data-local: install-cmake
install-exec-local: install-cmake

# Distribute files from here.
EXTRA_DIST = $(cmakeprojectsubdirs) jsonpath_changes.patch libubox_changes.patch
#dist-hook:
