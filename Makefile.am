
##
## Toplevel Makefile.am
##

ACLOCAL_AMFLAGS = -I m4

SUBDIRS		= m4 external doc include lib src test

EXTRA_DIST	= autogen.sh TODO

pkgconfigdir    = $(libdir)/pkgconfig
pkgconfig_DATA  = libbitc.pc

pkg-deb: dist
	- rm -rf $(distdir)
	mkdir -p $(distdir)
	mv $(distdir).tar.gz $(distdir)/$(PACKAGE)_$(VERSION).orig.tar.gz

	tar --directory $(distdir)/ \
         -xf $(distdir)/$(PACKAGE)_$(VERSION).orig.tar.gz

	cp -r $(top_srcdir)/contrib/debian $(distdir)/$(PACKAGE)-$(VERSION)/
	cd $(distdir)/$(PACKAGE)-$(VERSION)/; \
          ./configure; \
          dpkg-buildpackage -us -uc -rfakeroot; \
          mv $(abs_srcdir)/$(distdir)/*.deb $(abs_srcdir)

	$(am__post_remove_distdir)

pkg-rpm: dist
	- rm -rf $(distdir)
	mkdir -p $(distdir)/rpmbuild/{RPMS,SRPMS,BUILD,SOURCES,SPECS}

	cp -r $(top_srcdir)/contrib/rpmbuild $(distdir)
	mv $(distdir).tar.gz $(distdir)/rpmbuild/SOURCES/
	rpmbuild --define="_topdir $(abs_srcdir)/$(distdir)/rpmbuild" -ba $(distdir)/rpmbuild/SPECS/libbitc.spec
	mv $(abs_srcdir)/$(distdir)/rpmbuild/RPMS/*/*.rpm $(abs_srcdir)

	$(am__post_remove_distdir)
