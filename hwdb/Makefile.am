ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

if ENABLE_HWDB_INSTALLATION

udevhwdb_DATA = \
	20-pci-vendor-product.hwdb \
	20-pci-classes.hwdb \
	20-usb-vendor-product.hwdb \
	20-usb-classes.hwdb \
	20-acpi-vendor.hwdb \
	20-OUI.hwdb

.NOTPARALLEL: $(udevhwdb_DATA)
$(udevhwdb_DATA):
	@echo "=================================================" && \
	echo "$@ not found" && \
	echo " " && \
	echo "Please download and extract to here a copy of the" && \
	echo "Combined hardware identification databases, from" && \
	echo "https://github.com/gentoo/hwids" && \
	echo "==================================================" && \
	exit 1

endif

install-data-hook:
	-$(MKDIR_P) $(DESTDIR)$(sysconfdir)/udev/hwdb.d

