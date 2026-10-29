##
## mangohud
##

ifeq ($(findstring mangohud,$(WITHOUT_VKLAYERS)),)

MANGOHUD_MESON_ARGS = \
  -Dwith_x11=enabled \
  -Dwith_wayland=enabled \
  -Dwith_dbus=disabled \
  -Dwith_nvml=disabled \
  -Dwith_xnvctrl=disabled \
  -Dinclude_doc=false \
  -Dmangoapp=false \
  -Dmangohudctl=false \
  -Dmangoplot=disabled \
  -Dtests=disabled \
  -Duse_system_spdlog=disabled \
  -Dappend_libdir_mangohud=false

MANGOHUD_DEPENDS = vulkan-headers glslang

$(eval $(call rules-source,mangohud,$(SRCDIR)/vklayers/MangoHud))
$(eval $(call rules-meson,mangohud,i386,unix))
$(eval $(call rules-meson,mangohud,x86_64,unix))

# ProtoGoblin MangoHud deadlock fixes (patches/mangohud/): blacklisted helper
# processes (wine's steam.exe shim, explorer.exe, launchers) must refuse the
# Vulkan layer interface in vkNegotiateLoaderLayerInterfaceVersion instead of
# wedging the loader's procaddr walk.  Applied after the source sync and
# before meson configure; patch(1) --forward keeps this idempotent if the
# source tree already carries an equivalent fix.  After editing a patch, run
# `make mangohud-clean` to re-sync and re-apply from scratch.
MANGOHUD_PATCHES = $(wildcard $(SRCDIR)/patches/mangohud/*.patch)

$(OBJ)/.mangohud-post-source: $(MANGOHUD_PATCHES)
	@set -e; for p in $(MANGOHUD_PATCHES); do \
		echo ">> Applying MangoHud patch: $$p"; \
		patch -d $(MANGOHUD_SRC) -p1 --forward --silent < "$$p"; \
	done; \
	touch $@

$(OBJ)/.mangohud-x86_64-post-build: $(SRCDIR)/tools/normalize_mangohud_manifest.py
	mkdir -p $(DST_DIR)/share/mangohud/implicit_layer.d/
	@set -e; for manifest in $(MANGOHUD_x86_64_DST)/share/vulkan/implicit_layer.d/*MangoHud*.json; do \
		python3 $(SRCDIR)/tools/normalize_mangohud_manifest.py "$$manifest" "$(DST_DIR)/share/mangohud/implicit_layer.d/$$(basename "$$manifest")" 64; \
	done
	touch $@

$(OBJ)/.mangohud-i386-post-build: $(SRCDIR)/tools/normalize_mangohud_manifest.py
	mkdir -p $(DST_DIR)/share/mangohud/implicit_layer.d/
	@set -e; for manifest in $(MANGOHUD_i386_DST)/share/vulkan/implicit_layer.d/*MangoHud*.json; do \
		python3 $(SRCDIR)/tools/normalize_mangohud_manifest.py "$$manifest" "$(DST_DIR)/share/mangohud/implicit_layer.d/$$(basename "$$manifest")" 32; \
	done
	touch $@

all-dist: mangohud

endif # WITHOUT_VKLAYERS
