# Repository Guidelines

## Development Scope & Compatibility Philosophy

Until stated otherwise by the project owner, ProtoGoblin is a **forward-only project**. We do **NOT** care about backward compatibility. Do not retain legacy shims, obsolete Proton/Wine workarounds, or deprecated interfaces unless explicitly required for the target forward implementation.

## Project Structure & Module Organization

GE-Proton combines Wine, graphics translation layers, and game compatibility fixes. The root `proton` Python launcher and supporting `.py` files manage runtime behavior. Native integration code lives in `steam_helper/`, `lsteamclient/`, `umu_helper/`, and `wineopenxr/`. Dependencies such as `wine/`, `dxvk/`, `vkd3d-proton/`, and `protonfixes/` are Git submodules. Keep dependency changes scoped and intentional.

Build orchestration lives in `Makefile`, `Makefile.in`, `make/`, and `docker/`. GE patches and their application script live in `patches/`. Documentation is in `README.md` and `docs/`; bundled assets include `media/`, `fonts/`, and `locale/`.

## Build, Test, and Development Commands

Use a Linux host with Docker or Podman and the Proton SDK container; these are Bash commands.

- `git submodule update --init --recursive`: populate dependencies.
- `./patches/protonprep-valve-staging.sh &> patchlog.txt`: apply GE patches from the repository root. Inspect the log for failures and errors before building.
- `mkdir -p build && cd build`: create and enter an out-of-source build directory.
- `../configure.sh --build-name=GE-local --container-engine=docker`: configure the build; substitute `podman` if needed.
- `make -j$(nproc) redist`: build distributable archives, matching the CI build target.
- `make install`: install the configured build into the local Steam installation.

## Coding Style & Naming Conventions

Match the surrounding component's style. Python uses four-space indentation, `snake_case` functions, and `PascalCase` classes. Preserve local C/C++ conventions and tab-indented Make recipes. No repository-wide formatter or linter configuration is present. Register new Wine patches under `#WINE CUSTOM PATCHES` in `patches/protonprep-valve-staging.sh`.

## Testing Guidelines

There is no unified top-level test framework or coverage threshold. Run relevant component tests using that component's instructions and naming conventions. Validate builds and reproduce affected games through Steam or umu. Record AppID, GPU/driver, launch options, and comparisons with upstream Proton and previous GE versions. Use a clean prefix where possible and `PROTON_LOG=1 %command%` for logs. Consult `proton_video_playback_checklist` for media changes.

## Commit & Pull Request Guidelines

Commit messages must be one line. Agents must not identify or credit themselves in commits, including authorship claims, signatures, attribution text, or co-author trailers. Available history contains only `Initial commit`; use concise, imperative descriptions such as `Fix launcher prefix initialization`.

PRs should explain the problem, affected components, linked issues, and build/game validation results. Include logs or screenshots when they clarify the behavior.
