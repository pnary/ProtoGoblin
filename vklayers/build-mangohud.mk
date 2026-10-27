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

$(OBJ)/.mangohud-x86_64-post-build:
	mkdir -p $(DST_DIR)/share/mangohud/implicit_layer.d/
	cp -a $(MANGOHUD_x86_64_DST)/share/vulkan/implicit_layer.d/*MangoHud*.json $(DST_DIR)/share/mangohud/implicit_layer.d/ 2>/dev/null || true
	touch $@

$(OBJ)/.mangohud-i386-post-build:
	mkdir -p $(DST_DIR)/share/mangohud/implicit_layer.d/
	cp -a $(MANGOHUD_i386_DST)/share/vulkan/implicit_layer.d/*MangoHud*.json $(DST_DIR)/share/mangohud/implicit_layer.d/ 2>/dev/null || true
	touch $@

all-dist: mangohud

endif # WITHOUT_VKLAYERS
