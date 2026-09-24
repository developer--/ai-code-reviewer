#!/bin/sh
# Builds "Repo Activity.app" into ~/Applications (double-click / Spotlight / Dock launcher).
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
APP="$HOME/Applications/Repo Activity.app"
# Stop a running copy so the new server code is actually used.
curl -s -m 3 -X POST -H 'X-Repo-Activity: 1' http://127.0.0.1:8765/api/quit >/dev/null 2>&1 && sleep 1 || true
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$SRC/server.py" "$SRC/index.html" "$APP/Contents/Resources/"
cat > "$APP/Contents/MacOS/repo-activity" <<'SH'
#!/bin/sh
DIR="$(cd "$(dirname "$0")/../Resources" && pwd)"
mkdir -p "$HOME/Library/Logs"
exec /usr/bin/python3 "$DIR/server.py" >>"$HOME/Library/Logs/repo-activity.log" 2>&1
SH
chmod +x "$APP/Contents/MacOS/repo-activity"
cat > "$APP/Contents/Info.plist" <<'PL'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Repo Activity</string>
  <key>CFBundleIdentifier</key><string>local.repo-activity</string>
  <key>CFBundleExecutable</key><string>repo-activity</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>LSUIElement</key><true/>
</dict></plist>
PL
echo "Built: $APP"
