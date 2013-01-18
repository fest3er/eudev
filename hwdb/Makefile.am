ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

if ENABLE_HWDB_INSTALLATION

dist_udevhwdb_DATA = \
	20-pci-vendor-product.hwdb \
	20-pci-classes.hwdb \
	20-usb-vendor-product.hwdb \
	20-usb-classes.hwdb \
	20-acpi-vendor.hwdb \
	20-OUI.hwdb

if PERL_FOUND

all-local: $(dist_udevhwdb_DATA)

$(dist_udevhwdb_DATA): usb.ids pci.ids oui.txt
	$(PERL) ids-update.pl

if WGET_FOUND

define wget-hwdb-source
	$(WGET) -q -O $@ $$url
endef

usb.ids:
	url=http://www.linux-usb.org/usb.ids && $(wget-hwdb-source)

pci.ids:
	url=http://pci-ids.ucw.cz/v2.2/pci.ids && $(wget-hwdb-source)

oui.txt:
	url=http://standards.ieee.org/develop/regauth/oui/oui.txt && $(wget-hwdb-source)

endif
endif
endif

install-data-hook:
	-$(MKDIR_P) $(DESTDIR)$(sysconfdir)/udev/hwdb.d
