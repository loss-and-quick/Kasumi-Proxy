.PHONY: srpm clean

ROOT_DIR := $(shell pwd)
SPEC ?= packaging/rpm/kasumi-proxy.spec
outdir ?= $(ROOT_DIR)

VERSION ?= $(shell ./scripts/app-version.sh)
ifeq ($(strip $(VERSION)),)
$(error Could not determine application version from scripts/app-version.sh)
endif

PKGNAME := kasumi-proxy
TARBALL := $(PKGNAME)-$(VERSION).tar.gz

srpm:
	@echo "==> Building SRPM for $(PKGNAME)-$(VERSION)..."
	mkdir -p $(outdir)
	mkdir -p rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	# Pack git repository archive without .git and build artifacts
	tar --exclude='.git' \
	    --exclude='target' \
	    --exclude='node_modules' \
	    --exclude='frontend/dist' \
	    --exclude='rpmbuild' \
	    --transform 's,^,$(PKGNAME)-$(VERSION)/,' \
	    -czf rpmbuild/SOURCES/$(TARBALL) .
	# Run rpmbuild to generate the SRPM with dynamically injected version
	rpmbuild -bs \
		--define "_topdir $(ROOT_DIR)/rpmbuild" \
		--define "version $(VERSION)" \
		$(SPEC)
	cp rpmbuild/SRPMS/*.src.rpm $(outdir)/
	@echo "==> SRPM created in $(outdir):"
	@ls -la $(outdir)/*.src.rpm

clean:
	rm -rf rpmbuild
