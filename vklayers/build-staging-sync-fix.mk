##
## staging-sync-fix
##

ifeq ($(findstring staging-sync-fix,$(WITHOUT_VKLAYERS)),)

STAGING_SYNC_FIX_x86_64_MESON_ARGS = --bindir=$(DST_DIR)/share/protogoblin/lib64
STAGING_SYNC_FIX_i386_MESON_ARGS = --bindir=$(DST_DIR)/share/protogoblin/lib32

$(eval $(call rules-source,staging-sync-fix,$(SRCDIR)/vklayers/staging-sync-fix))
$(eval $(call rules-meson,staging-sync-fix,i386,windows))
$(eval $(call rules-meson,staging-sync-fix,x86_64,windows))

$(OBJ)/.staging-sync-fix-x86_64-post-build:
	mkdir -p $(DST_DIR)/share/protogoblin/lib64/
	cp -a $(STAGING_SYNC_FIX_x86_64_DST)/bin/d3d11.dll $(DST_DIR)/share/protogoblin/lib64/ 2>/dev/null || \
	cp -a $(STAGING_SYNC_FIX_x86_64_DST)/lib/d3d11.dll $(DST_DIR)/share/protogoblin/lib64/ 2>/dev/null || true
	touch $@

$(OBJ)/.staging-sync-fix-i386-post-build:
	mkdir -p $(DST_DIR)/share/protogoblin/lib32/
	cp -a $(STAGING_SYNC_FIX_i386_DST)/bin/d3d11.dll $(DST_DIR)/share/protogoblin/lib32/ 2>/dev/null || \
	cp -a $(STAGING_SYNC_FIX_i386_DST)/lib/d3d11.dll $(DST_DIR)/share/protogoblin/lib32/ 2>/dev/null || true
	touch $@

all-dist: staging-sync-fix

endif # WITHOUT_VKLAYERS
