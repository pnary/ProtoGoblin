##
## io-cache
##

ifeq ($(findstring io-cache,$(WITHOUT_VKLAYERS)),)

IO_CACHE_x86_64_MESON_ARGS = --libdir=$(DST_DIR)/share/protogoblin/lib64
IO_CACHE_i386_MESON_ARGS = --libdir=$(DST_DIR)/share/protogoblin/lib32

$(eval $(call rules-source,io-cache,$(SRCDIR)/vklayers/io-cache))
$(eval $(call rules-meson,io-cache,x86_64,unix))
$(eval $(call rules-meson,io-cache,i386,unix))

$(OBJ)/.io-cache-x86_64-post-build:
	mkdir -p $(DST_DIR)/share/protogoblin/lib64/
	cp -a $(IO_CACHE_x86_64_DST)/lib64/libprotogoblin_io_cache.so $(DST_DIR)/share/protogoblin/lib64/ 2>/dev/null || \
	cp -a $(IO_CACHE_x86_64_DST)/lib/libprotogoblin_io_cache.so $(DST_DIR)/share/protogoblin/lib64/ 2>/dev/null || true
	touch $@

$(OBJ)/.io-cache-i386-post-build:
	mkdir -p $(DST_DIR)/share/protogoblin/lib32/
	cp -a $(IO_CACHE_i386_DST)/lib32/libprotogoblin_io_cache.so $(DST_DIR)/share/protogoblin/lib32/ 2>/dev/null || \
	cp -a $(IO_CACHE_i386_DST)/lib/libprotogoblin_io_cache.so $(DST_DIR)/share/protogoblin/lib32/ 2>/dev/null || true
	touch $@

all-dist: io-cache

endif # WITHOUT_VKLAYERS
