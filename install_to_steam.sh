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
  --base-proton PATH      Base Proton directory for --dev mode (auto-detected if omitted).
  --name NAME             Internal tool name (default: ProtoGoblin-local).
  --display-name NAME     Visible name in Steam drop-down (default: "ProtoGoblin (Local Build)").
  --engine ENGINE         Container engine for full build: 'docker' or 'podman'.
  --dest DIR              Explicit destination compatibilitytools.d directory.
  -h, --help              Show this help message and exit.

Examples:
  # Install from existing build folder or build by default if not found:
  ./install_to_steam.sh

  # Quick developer install onto existing Proton:
  ./install_to_steam.sh --dev

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
            # Look for GE-Proton or Proton Experimental
            local match
            match="$(find "$base" -maxdepth 2 -type f -name "proton" 2>/dev/null | head -n 1 || true)"
            if [[ -n "$match" ]]; then
                dirname "$match"
                return
            fi
        fi
    done
    echo ""
}

# 4. Perform Build / Sync Logic
mkdir -p "$COMPAT_DIR"

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
}

if [[ "$FORCE_BUILD" == true ]]; then
    build_from_source

elif [[ "$DEV_OVERLAY" == true ]]; then
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

    log_info "Injecting ProtoGoblin runtime, introspective hooks, and presets..."
    cp -f "${SCRIPT_DIR}/proton" "${TOOL_DIR}/proton"
    cp -f "${SCRIPT_DIR}/protogoblin.py" "${TOOL_DIR}/protogoblin.py"
    cp -f "${SCRIPT_DIR}/protogoblin_command.py" "${TOOL_DIR}/protogoblin_command.py"
    chmod +x "${TOOL_DIR}/proton" "${TOOL_DIR}/protogoblin.py" "${TOOL_DIR}/protogoblin_command.py"

    # Install presets database
    mkdir -p "${TOOL_DIR}/share/protogoblin"
    if [[ -f "${SCRIPT_DIR}/share/protogoblin/protogoblin_presets.json" ]]; then
        cp -f "${SCRIPT_DIR}/share/protogoblin/protogoblin_presets.json" "${TOOL_DIR}/share/protogoblin/"
    fi

    # Install tools
    if [[ -d "${SCRIPT_DIR}/tools" ]]; then
        mkdir -p "${TOOL_DIR}/tools"
        cp -rf "${SCRIPT_DIR}/tools/"* "${TOOL_DIR}/tools/"
    fi

else
    # Check if a dist directory already exists
    if [[ -d "${SCRIPT_DIR}/build/dist" ]]; then
        log_info "Installing from existing build/dist..."
        mkdir -p "$TOOL_DIR"
        rsync --delete -arx "${SCRIPT_DIR}/build/dist/" "${TOOL_DIR}/"
    elif [[ -d "${SCRIPT_DIR}/dist" ]]; then
        log_info "Installing from existing dist/..."
        mkdir -p "$TOOL_DIR"
        rsync --delete -arx "${SCRIPT_DIR}/dist/" "${TOOL_DIR}/"
    else
        DETECTED_BASE="$(find_base_proton)"
        if [[ -n "$DETECTED_BASE" ]]; then
            log_warn "No pre-built dist/ folder found."
            log_info "Defaulting to --dev overlay mode using existing Proton base (${DETECTED_BASE})..."
            exec "$0" --dev --name "$BUILD_NAME" --display-name "$DISPLAY_NAME"
        else
            log_warn "No build folder found and no existing Proton base detected."
            log_info "Building from source..."
            build_from_source
        fi
    fi
fi

# 5. Write compatibilitytool.vdf
VDF_PATH="${TOOL_DIR}/compatibilitytool.vdf"
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

# Ensure launcher scripts have executable bits
chmod +x "${TOOL_DIR}/proton" 2>/dev/null || true
if [[ -f "${TOOL_DIR}/protogoblin.py" ]]; then
    chmod +x "${TOOL_DIR}/protogoblin.py"
fi
if [[ -f "${TOOL_DIR}/protogoblin_command.py" ]]; then
    chmod +x "${TOOL_DIR}/protogoblin_command.py"
fi

echo ""
log_ok "ProtoGoblin successfully installed into Steam!"
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
