#!/usr/bin/env bash
#
# ProtoGoblin - Build and Install to Local Steam Compatibility Tools
#
# Automates building and installing ProtoGoblin as a selectable Steam
# compatibility tool in Steam's game Properties -> Compatibility menu.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_NAME="ProtoGoblin-local"
DISPLAY_NAME="ProtoGoblin (Local Build)"
CONTAINER_ENGINE=""
TARGET_ARCH="$(uname -m 2>/dev/null || echo 'x86_64')"
[[ "$TARGET_ARCH" == "amd64" ]] && TARGET_ARCH="x86_64"
FORCE_BUILD=false
DEV_OVERLAY=false
EXPLICIT_UPDATE=false
CHECK_ONLY=false
FORCE_UPDATE=false
BASE_PROTON=""
CUSTOM_DEST=""

# Colors
C_RED="\033[31;1m"
C_GREEN="\033[32;1m"
C_YELLOW="\033[33;1m"
C_CYAN="\033[36;1m"
C_RESET="\033[0m"

log_info()  { echo -e "${C_CYAN}::${C_RESET} $*"; }
log_ok()    { echo -e "${C_GREEN}✓${C_RESET} $*"; }
log_warn()  { echo -e "${C_YELLOW}!${C_RESET} $*"; }
log_err()   { echo -e "${C_RED}✗${C_RESET} $*" >&2; }

show_help() {
    cat <<EOF
ProtoGoblin Steam Installer

Usage: $(basename "$0") [OPTIONS]

Options:
  --build                 Perform a full containerized build from source before installing.
  --dev                   Developer overlay mode: graft ProtoGoblin scripts/presets onto
                          an existing Proton installation (fast, no 45-minute Wine recompile).
  --update                Check existing deployment and update outdated components in-place.
  --check                 Check if the existing deployment is up to date without modifying files.
  --force                 Force update/refresh even if components appear current.
  --base-proton PATH      Base Proton directory for --dev mode (auto-detected if omitted).
  --name NAME             Internal tool name (default: ProtoGoblin-local).
  --display-name NAME     Visible name in Steam drop-down (default: "ProtoGoblin (Local Build)").
  --engine ENGINE         Container engine for full build: 'docker' or 'podman'.
  --dest DIR              Explicit destination compatibilitytools.d directory.
  -h, --help              Show this help message and exit.

Examples:
  # Automatically check existing deployment and update if needed, or install:
  ./install_to_steam.sh

  # Check whether existing deployment matches latest repository files:
  ./install_to_steam.sh --check

  # Explicitly update existing deployment in-place:
  ./install_to_steam.sh --update

  # Force full container build and install:
  ./install_to_steam.sh --build --engine=docker
EOF
}

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --build)
            FORCE_BUILD=true
            shift
            ;;
        --dev)
            DEV_OVERLAY=true
            shift
            ;;
        --update)
            EXPLICIT_UPDATE=true
            shift
            ;;
        --check)
            CHECK_ONLY=true
            shift
            ;;
        --force)
            FORCE_UPDATE=true
            shift
            ;;
        --base-proton)
            BASE_PROTON="$2"
            shift 2
            ;;
        --name)
            BUILD_NAME="$2"
            shift 2
            ;;
        --display-name)
            DISPLAY_NAME="$2"
            shift 2
            ;;
        --arch)
            TARGET_ARCH="$2"
            shift 2
            ;;
        --engine)
            CONTAINER_ENGINE="$2"
            shift 2
            ;;
        --dest)
            CUSTOM_DEST="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            log_err "Unknown argument: $1"
            show_help
            exit 1
            ;;
    esac
done

# 1. Detect Steam compatibilitytools.d destination
find_steam_compat_dir() {
    if [[ -n "$CUSTOM_DEST" ]]; then
        echo "$CUSTOM_DEST"
        return
    fi

    local CANDIDATES=(
        "${HOME}/.local/share/Steam/compatibilitytools.d"
        "${HOME}/.steam/root/compatibilitytools.d"
        "${HOME}/.steam/steam/compatibilitytools.d"
        "${HOME}/.var/app/com.valvesoftware.Steam/data/Steam/compatibilitytools.d"
    )

    for dir in "${CANDIDATES[@]}"; do
        local parent="$(dirname "$dir")"
        if [[ -d "$parent" ]]; then
            echo "$dir"
            return
        fi
    done

    # Default fallback
    echo "${HOME}/.local/share/Steam/compatibilitytools.d"
}

COMPAT_DIR="$(find_steam_compat_dir)"
TOOL_DIR="${COMPAT_DIR}/${BUILD_NAME}"

log_info "Target Steam compatibility folder:"
echo "   ${TOOL_DIR}"

# 2. Check for container engine if full build requested
detect_engine() {
    if [[ -n "$CONTAINER_ENGINE" ]]; then
        echo "$CONTAINER_ENGINE"
        return
    fi
    # Check if docker daemon is accessible
    if command -v docker &>/dev/null && docker info &>/dev/null; then
        echo "docker"
        return
    fi
    # Check if podman is available and functional
    if command -v podman &>/dev/null && podman info &>/dev/null; then
        echo "podman"
        return
    fi
    if command -v podman &>/dev/null; then
        echo "podman"
        return
    fi
    if command -v docker &>/dev/null; then
        echo "docker"
        return
    fi
    echo ""
}

# 3. Locate existing Proton for Dev Overlay mode
find_base_proton() {
    if [[ -n "$BASE_PROTON" ]] && [[ -d "$BASE_PROTON" ]]; then
        echo "$BASE_PROTON"
        return
    fi

    local SEARCH_DIRS=(
        "${HOME}/.local/share/Steam/compatibilitytools.d"
        "${HOME}/.steam/root/compatibilitytools.d"
        "${HOME}/.steam/steam/compatibilitytools.d"
        "${HOME}/.var/app/com.valvesoftware.Steam/data/Steam/compatibilitytools.d"
        "${HOME}/.local/share/Steam/steamapps/common"
        "${HOME}/.steam/root/steamapps/common"
    )

    for base in "${SEARCH_DIRS[@]}"; do
        if [[ -d "$base" ]]; then
            # Look for GE-Proton or Proton Experimental (excluding current tool destination if present)
            local match
            match="$(find "$base" -maxdepth 2 -type f -name "proton" 2>/dev/null | grep -v "/${BUILD_NAME}/" | head -n 1 || true)"
            if [[ -n "$match" ]]; then
                dirname "$match"
                return
            fi
        fi
    done

    # Fallback to current tool directory if already populated
    if [[ -f "${TOOL_DIR}/proton" ]]; then
        echo "${TOOL_DIR}"
        return
    fi

    echo ""
}

# 4. Deployment Detection & Component Verification
check_existing_deployment() {
    [[ -d "$TOOL_DIR" ]] && ([[ -f "${TOOL_DIR}/compatibilitytool.vdf" ]] || [[ -f "${TOOL_DIR}/proton" ]])
}

get_outdated_components() {
    local outdated=()
    local CORE_FILES=(
        "proton"
        "protogoblin.py"
        "protogoblin_command.py"
        "protogoblin"
        "utilities.py"
        "vulkan.py"
        "filelock.py"
        "default_pfx.py"
        "VERSION"
    )
    for f in "${CORE_FILES[@]}"; do
        if [[ -f "${SCRIPT_DIR}/${f}" ]]; then
            if [[ ! -f "${TOOL_DIR}/${f}" ]] || ! cmp -s "${SCRIPT_DIR}/${f}" "${TOOL_DIR}/${f}"; then
                outdated+=("${f}")
            fi
        fi
    done

    local preset="share/protogoblin/protogoblin_presets.json"
    if [[ -f "${SCRIPT_DIR}/${preset}" ]]; then
        if [[ ! -f "${TOOL_DIR}/${preset}" ]] || ! cmp -s "${SCRIPT_DIR}/${preset}" "${TOOL_DIR}/${preset}"; then
            outdated+=("${preset}")
        fi
    fi

    if [[ -d "${SCRIPT_DIR}/tools" ]]; then
        for f in "${SCRIPT_DIR}/tools"/*; do
            if [[ -f "$f" ]]; then
                local bname="$(basename "$f")"
                if [[ ! -f "${TOOL_DIR}/tools/${bname}" ]] || ! cmp -s "$f" "${TOOL_DIR}/tools/${bname}"; then
                    outdated+=("tools/${bname}")
                fi
            fi
        done
    fi

    if [[ -d "${SCRIPT_DIR}/vklayers/staging-sync-fix" ]]; then
        for f in "${SCRIPT_DIR}/vklayers/staging-sync-fix"/*; do
            if [[ -f "$f" ]]; then
                local bname="$(basename "$f")"
                if [[ ! -f "${TOOL_DIR}/vklayers/staging-sync-fix/${bname}" ]] || ! cmp -s "$f" "${TOOL_DIR}/vklayers/staging-sync-fix/${bname}"; then
                    outdated+=("vklayers/staging-sync-fix/${bname}")
                fi
            fi
        done
    fi

    if [[ -d "${SCRIPT_DIR}/vklayers/io-cache" ]]; then
        for f in "${SCRIPT_DIR}/vklayers/io-cache"/*; do
            if [[ -f "$f" ]]; then
                local bname="$(basename "$f")"
                if [[ ! -f "${TOOL_DIR}/vklayers/io-cache/${bname}" ]] || ! cmp -s "$f" "${TOOL_DIR}/vklayers/io-cache/${bname}"; then
                    outdated+=("vklayers/io-cache/${bname}")
                fi
            fi
        done
        local so_path="${TOOL_DIR}/share/protogoblin/lib64/libprotogoblin_io_cache.so"
        if command -v g++ &>/dev/null; then
            if [[ ! -f "$so_path" ]] || [[ "${SCRIPT_DIR}/vklayers/io-cache/io_cache.cpp" -nt "$so_path" ]]; then
                outdated+=("share/protogoblin/lib64/libprotogoblin_io_cache.so")
            fi
        fi
    fi

    if [[ -d "${SCRIPT_DIR}/share/protogoblin/mangohud" ]]; then
        local source deployed rel arch
        for arch in lib64 lib32 implicit_layer.d; do
            for source in "${SCRIPT_DIR}/share/protogoblin/mangohud/${arch}/"*; do
                [[ -f "$source" ]] || continue
                case "$arch" in
                    lib64) rel="files/lib/x86_64-linux-gnu/$(basename "$source")" ;;
                    lib32) rel="files/lib/i386-linux-gnu/$(basename "$source")" ;;
                    implicit_layer.d) rel="files/share/mangohud/implicit_layer.d/$(basename "$source")" ;;
                esac
                deployed="${TOOL_DIR}/${rel}"
                if [[ ! -f "$deployed" ]] || ! cmp -s "$source" "$deployed"; then
                    outdated+=("$rel")
                fi
            done
        done
    fi

    local vdf="${TOOL_DIR}/compatibilitytool.vdf"
    if [[ ! -f "$vdf" ]] || ! grep -q "\"${BUILD_NAME}\"" "$vdf" 2>/dev/null; then
        outdated+=("compatibilitytool.vdf")
    fi

    echo "${outdated[@]}"
}

write_manifest() {
    local VDF_PATH="${TOOL_DIR}/compatibilitytool.vdf"
    log_info "Writing Steam registration manifest: ${VDF_PATH}"

    cat > "$VDF_PATH" <<EOF
"compatibilitytools"
{
  "compat_tools"
  {
    "${BUILD_NAME}"
    {
      "install_path" "."
      "display_name" "${DISPLAY_NAME}"
      "from_oslist"  "windows"
      "to_oslist"    "linux"
    }
  }
}
EOF

    chmod +x "${TOOL_DIR}/proton" 2>/dev/null || true
    if [[ -f "${TOOL_DIR}/protogoblin.py" ]]; then
        chmod +x "${TOOL_DIR}/protogoblin.py"
    fi
    if [[ -f "${TOOL_DIR}/protogoblin_command.py" ]]; then
        chmod +x "${TOOL_DIR}/protogoblin_command.py"
    fi
    if [[ -f "${TOOL_DIR}/protogoblin" ]]; then
        chmod +x "${TOOL_DIR}/protogoblin"
    fi
}

install_protogoblin_components() {
    log_info "Synchronizing ProtoGoblin runtime, introspective hooks, and presets..."
    cp -f "${SCRIPT_DIR}/proton" "${TOOL_DIR}/proton"
    cp -f "${SCRIPT_DIR}/protogoblin.py" "${TOOL_DIR}/protogoblin.py"
    cp -f "${SCRIPT_DIR}/protogoblin_command.py" "${TOOL_DIR}/protogoblin_command.py"
    cp -f "${SCRIPT_DIR}/protogoblin" "${TOOL_DIR}/protogoblin"
    cp -f "${SCRIPT_DIR}/utilities.py" "${TOOL_DIR}/utilities.py"
    cp -f "${SCRIPT_DIR}/vulkan.py" "${TOOL_DIR}/vulkan.py"
    if [[ -f "${SCRIPT_DIR}/filelock.py" ]]; then
        cp -f "${SCRIPT_DIR}/filelock.py" "${TOOL_DIR}/filelock.py"
    fi
    if [[ -f "${SCRIPT_DIR}/default_pfx.py" ]]; then
        cp -f "${SCRIPT_DIR}/default_pfx.py" "${TOOL_DIR}/default_pfx.py"
    fi
    if [[ -f "${SCRIPT_DIR}/VERSION" ]]; then
        cp -f "${SCRIPT_DIR}/VERSION" "${TOOL_DIR}/VERSION"
    fi
    chmod +x "${TOOL_DIR}/proton" "${TOOL_DIR}/protogoblin.py" "${TOOL_DIR}/protogoblin_command.py" "${TOOL_DIR}/protogoblin"

    # Install presets database
    mkdir -p "${TOOL_DIR}/share/protogoblin"
    if [[ -f "${SCRIPT_DIR}/share/protogoblin/protogoblin_presets.json" ]]; then
        cp -f "${SCRIPT_DIR}/share/protogoblin/protogoblin_presets.json" "${TOOL_DIR}/share/protogoblin/"
    fi

    # Install tools
    if [[ -d "${SCRIPT_DIR}/tools" ]]; then
        mkdir -p "${TOOL_DIR}/tools"
        cp -rf "${SCRIPT_DIR}/tools/"* "${TOOL_DIR}/tools/"
        chmod +x "${TOOL_DIR}/tools/"* 2>/dev/null || true
    fi

    # Install vendored libraries (such as D3D11 staging buffer sync fix and I/O cache)
    if [[ -d "${SCRIPT_DIR}/share/protogoblin/lib64" ]]; then
        mkdir -p "${TOOL_DIR}/share/protogoblin/lib64"
        cp -rf "${SCRIPT_DIR}/share/protogoblin/lib64/"* "${TOOL_DIR}/share/protogoblin/lib64/" 2>/dev/null || true
    fi
    if [[ -d "${SCRIPT_DIR}/share/protogoblin/lib32" ]]; then
        mkdir -p "${TOOL_DIR}/share/protogoblin/lib32"
        cp -rf "${SCRIPT_DIR}/share/protogoblin/lib32/"* "${TOOL_DIR}/share/protogoblin/lib32/" 2>/dev/null || true
    fi
    if [[ -d "${SCRIPT_DIR}/vklayers/staging-sync-fix" ]]; then
        mkdir -p "${TOOL_DIR}/share/protogoblin/staging-sync-fix"
        cp -rf "${SCRIPT_DIR}/vklayers/staging-sync-fix/"* "${TOOL_DIR}/share/protogoblin/staging-sync-fix/" 2>/dev/null || true
        mkdir -p "${TOOL_DIR}/vklayers/staging-sync-fix"
        cp -rf "${SCRIPT_DIR}/vklayers/staging-sync-fix/"* "${TOOL_DIR}/vklayers/staging-sync-fix/" 2>/dev/null || true
    fi
    if [[ -d "${SCRIPT_DIR}/vklayers/io-cache" ]]; then
        mkdir -p "${TOOL_DIR}/vklayers/io-cache"
        cp -rf "${SCRIPT_DIR}/vklayers/io-cache/"* "${TOOL_DIR}/vklayers/io-cache/" 2>/dev/null || true
        if command -v g++ &>/dev/null; then
            mkdir -p "${TOOL_DIR}/share/protogoblin/lib64"
            local so_path="${TOOL_DIR}/share/protogoblin/lib64/libprotogoblin_io_cache.so"
            if [[ ! -f "$so_path" ]] || [[ "${SCRIPT_DIR}/vklayers/io-cache/io_cache.cpp" -nt "$so_path" ]] || [[ "$FORCE_UPDATE" == true ]]; then
                log_info "Building libprotogoblin_io_cache.so..."
                g++ -O2 -fPIC -shared -std=c++17 "${SCRIPT_DIR}/vklayers/io-cache/io_cache.cpp" -o "$so_path" -ldl -lpthread 2>/dev/null || true
            fi
        fi
    fi

    # Install MangoHud overlay libraries and layer manifests
    if [[ -d "${SCRIPT_DIR}/share/protogoblin/mangohud" ]]; then
        log_info "Synchronizing bundled MangoHud overlay libraries and layer manifests..."
        mkdir -p "${TOOL_DIR}/share/protogoblin/mangohud"
        cp -rf "${SCRIPT_DIR}/share/protogoblin/mangohud/"* "${TOOL_DIR}/share/protogoblin/mangohud/" 2>/dev/null || true

        # Install into files/ for Proton runtime
        mkdir -p "${TOOL_DIR}/files/share/mangohud/implicit_layer.d"
        mkdir -p "${TOOL_DIR}/share/vulkan/implicit_layer.d"
        if [[ -d "${SCRIPT_DIR}/share/protogoblin/mangohud/implicit_layer.d" ]]; then
            cp -f "${SCRIPT_DIR}/share/protogoblin/mangohud/implicit_layer.d/"* "${TOOL_DIR}/files/share/mangohud/implicit_layer.d/" 2>/dev/null || true
            cp -f "${SCRIPT_DIR}/share/protogoblin/mangohud/implicit_layer.d/"* "${TOOL_DIR}/share/vulkan/implicit_layer.d/" 2>/dev/null || true
        fi

        # Install 64-bit MangoHud library and dependencies
        if [[ -d "${SCRIPT_DIR}/share/protogoblin/mangohud/lib64" ]]; then
            mkdir -p "${TOOL_DIR}/files/lib/x86_64-linux-gnu" "${TOOL_DIR}/files/lib64"
            cp -af "${SCRIPT_DIR}/share/protogoblin/mangohud/lib64/"* "${TOOL_DIR}/files/lib/x86_64-linux-gnu/" 2>/dev/null || true
            cp -af "${SCRIPT_DIR}/share/protogoblin/mangohud/lib64/"* "${TOOL_DIR}/files/lib64/" 2>/dev/null || true
        fi

        # Install 32-bit MangoHud library and dependencies (e.g. 32-bit libxkbcommon)
        if [[ -d "${SCRIPT_DIR}/share/protogoblin/mangohud/lib32" ]]; then
            mkdir -p "${TOOL_DIR}/files/lib/i386-linux-gnu" "${TOOL_DIR}/files/lib"
            cp -af "${SCRIPT_DIR}/share/protogoblin/mangohud/lib32/"* "${TOOL_DIR}/files/lib/i386-linux-gnu/" 2>/dev/null || true
            cp -af "${SCRIPT_DIR}/share/protogoblin/mangohud/lib32/"* "${TOOL_DIR}/files/lib/" 2>/dev/null || true
        fi

        # Install mangohud CLI wrapper if present
        if [[ -f "${SCRIPT_DIR}/share/protogoblin/mangohud/bin/mangohud" ]]; then
            mkdir -p "${TOOL_DIR}/tools"
            cp -f "${SCRIPT_DIR}/share/protogoblin/mangohud/bin/mangohud" "${TOOL_DIR}/tools/"
            chmod +x "${TOOL_DIR}/tools/mangohud" 2>/dev/null || true
        fi
    fi

    write_manifest
}

update_existing_deployment() {
    log_info "Checking existing deployment at: ${TOOL_DIR}"
    local outdated=($(get_outdated_components))
    if [[ ${#outdated[@]} -eq 0 ]] && [[ "$FORCE_UPDATE" != true ]]; then
        log_ok "Existing deployment is already up to date with repository changes."
        return 0
    fi

    if [[ "$FORCE_UPDATE" == true ]]; then
        log_info "Force update requested. Refreshing all ProtoGoblin components..."
    else
        log_warn "Detected ${#outdated[@]} outdated component(s):"
        for item in "${outdated[@]}"; do
            echo "   • ${item}"
        done
        log_info "Updating deployment with latest changes..."
    fi

    install_protogoblin_components
    log_ok "Existing ProtoGoblin deployment successfully updated!"
}

check_deployment_status() {
    if ! check_existing_deployment; then
        log_warn "No existing ProtoGoblin deployment found at: ${TOOL_DIR}"
        return 1
    fi

    log_info "Checking deployment status at: ${TOOL_DIR}"
    local outdated=($(get_outdated_components))
    if [[ ${#outdated[@]} -eq 0 ]]; then
        log_ok "ProtoGoblin deployment is fully up to date."
        return 0
    else
        log_warn "ProtoGoblin deployment has ${#outdated[@]} outdated component(s):"
        for item in "${outdated[@]}"; do
            echo "   • ${item}"
        done
        return 1
    fi
}

install_dev_overlay() {
    if check_existing_deployment && [[ -d "${TOOL_DIR}/files" ]] && [[ "$FORCE_UPDATE" != true ]]; then
        log_info "Base Proton runtime already established in ${TOOL_DIR}."
        update_existing_deployment
        return
    fi

    DETECTED_BASE="$(find_base_proton)"
    if [[ -z "$DETECTED_BASE" ]]; then
        log_err "No existing Proton installation found to overlay onto."
        log_err "Please provide --base-proton /path/to/Proton or use --build."
        exit 1
    fi
    log_info "Using base Proton runtime from: ${DETECTED_BASE}"
    log_info "Copying base runtime to ${TOOL_DIR}..."
    mkdir -p "$TOOL_DIR"
    rsync -arx --exclude "compatibilitytool.vdf" "${DETECTED_BASE}/" "${TOOL_DIR}/"

    install_protogoblin_components
}

build_from_source() {
    local ENGINE
    ENGINE="$(detect_engine)"
    if [[ -z "$ENGINE" ]]; then
        log_err "Neither docker nor podman found. Install one or run with --dev overlay mode."
        exit 1
    fi
    log_info "Configuring and running full build via $ENGINE..."
    local BUILD_DIR="${SCRIPT_DIR}/build"
    mkdir -p "$BUILD_DIR"
    pushd "$BUILD_DIR" >/dev/null
    chmod +x "${SCRIPT_DIR}/configure.sh" 2>/dev/null || true
    "${SCRIPT_DIR}/configure.sh" --build-name="$BUILD_NAME" --target-arch="$TARGET_ARCH" --container-engine="$ENGINE"
    make -j"$(nproc)"
    popd >/dev/null

    log_info "Installing built binaries to Steam..."
    mkdir -p "$TOOL_DIR"
    rsync --delete -arx "${BUILD_DIR}/dist/" "${TOOL_DIR}/"
    write_manifest
}

# 5. Execution Dispatch
mkdir -p "$COMPAT_DIR"

if [[ "$CHECK_ONLY" == true ]]; then
    check_deployment_status
    exit $?

elif [[ "$FORCE_BUILD" == true ]]; then
    build_from_source

elif [[ "$EXPLICIT_UPDATE" == true ]]; then
    if check_existing_deployment; then
        update_existing_deployment
    else
        log_warn "No existing ProtoGoblin deployment found at: ${TOOL_DIR}"
        log_info "Proceeding with initial installation..."
        install_dev_overlay
    fi

elif [[ -d "${SCRIPT_DIR}/build/dist" ]]; then
    log_info "Installing from existing build/dist..."
    mkdir -p "$TOOL_DIR"
    rsync --delete -arx "${SCRIPT_DIR}/build/dist/" "${TOOL_DIR}/"
    write_manifest

elif [[ -d "${SCRIPT_DIR}/dist" ]]; then
    log_info "Installing from existing dist/..."
    mkdir -p "$TOOL_DIR"
    rsync --delete -arx "${SCRIPT_DIR}/dist/" "${TOOL_DIR}/"
    write_manifest

elif check_existing_deployment; then
    log_info "Detected existing ProtoGoblin deployment."
    update_existing_deployment

elif [[ "$DEV_OVERLAY" == true ]]; then
    install_dev_overlay

else
    DETECTED_BASE="$(find_base_proton)"
    if [[ -n "$DETECTED_BASE" ]]; then
        log_warn "No pre-built dist/ folder found."
        log_info "Defaulting to --dev overlay mode using existing Proton base (${DETECTED_BASE})..."
        install_dev_overlay
    else
        log_warn "No build folder found and no existing Proton base detected."
        log_info "Building from source..."
        build_from_source
    fi
fi

echo ""
log_ok "ProtoGoblin ready in Steam!"
echo -e "${C_CYAN}================================================================${C_RESET}"
echo -e "Tool Location: ${TOOL_DIR}"
echo -e "Tool Name:     ${C_GREEN}${DISPLAY_NAME}${C_RESET}"
echo -e "${C_CYAN}================================================================${C_RESET}"
echo ""
echo "Next steps to use ProtoGoblin in Steam:"
echo "  1. Completely restart Steam (Steam menu -> Exit)."
echo "  2. Right-click any Windows game in your library -> Properties."
echo "  3. Go to the 'Compatibility' tab."
echo "  4. Check 'Force the use of a specific Steam Play compatibility tool'."
echo -e "  5. Select '${C_GREEN}${DISPLAY_NAME}${C_RESET}' from the drop-down menu."
echo ""
echo "To launch in active profiling mode with HUD telemetry:"
echo "  Launch Options: PROTOGOBLIN_MODE=profile %command%"
echo ""
echo "To manage profiles and inspect telemetry visually:"
echo "  Run: python ${TOOL_DIR}/protogoblin_command.py"
echo ""
