#!/bin/bash
# Nexus C2 Client Launcher
# This script sets up the environment for GNOME/Linux taskbar icon support
# and installs the .desktop file on first run

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Auto-install desktop integration on first run (Linux only)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    ICON_SRC="$SCRIPT_DIR/src/gui/resources/n.png"
    ICON_DEST="$HOME/.local/share/icons/hicolor/256x256/apps/nexus.png"
    DESKTOP_DEST="$HOME/.local/share/applications/nexus.desktop"

    # Install icon if not present or outdated
    if [[ -f "$ICON_SRC" ]] && [[ ! -f "$ICON_DEST" || "$ICON_SRC" -nt "$ICON_DEST" ]]; then
        mkdir -p "$(dirname "$ICON_DEST")"
        cp "$ICON_SRC" "$ICON_DEST"
        gtk-update-icon-cache "$HOME/.local/share/icons/hicolor/" 2>/dev/null || true
        echo "Nexus: Installed taskbar icon"
    fi

    # Install/update .desktop file if not present or script location changed
    if [[ ! -f "$DESKTOP_DEST" ]] || ! grep -q "$SCRIPT_DIR" "$DESKTOP_DEST" 2>/dev/null; then
        mkdir -p "$(dirname "$DESKTOP_DEST")"
        cat > "$DESKTOP_DEST" << EOF
[Desktop Entry]
Name=Nexus
Comment=Nexus C2 Client
Exec=$SCRIPT_DIR/run_nexus.sh
Icon=$ICON_DEST
Terminal=false
Type=Application
Categories=Development;Security;
StartupWMClass=nexus
EOF
        chmod +x "$DESKTOP_DEST"
        update-desktop-database "$HOME/.local/share/applications/" 2>/dev/null || true
        echo "Nexus: Installed desktop entry (you can find 'Nexus' in your app menu)"
    fi
fi

# Run the application
python3 src/main.py "$@"
