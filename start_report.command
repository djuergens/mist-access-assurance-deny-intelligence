#!/bin/bash
# ─────────────────────────────────────────────────────────────
# Mist Deny Log Intelligence — Mac Launcher
# Double-click this file to start the report tool.
# ─────────────────────────────────────────────────────────────

# Move to the folder this script lives in
cd "$(dirname "$0")"

# Pick an available port
PORT=8765

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
  osascript -e 'display alert "Python 3 not found" message "Python 3 is required to run this tool. Please install it from python.org and try again." as critical'
  exit 1
fi

# Kill any previous server on this port
lsof -ti tcp:$PORT | xargs kill -9 2>/dev/null

# Start the local web server in the background
python3 -c "
import os, http.server, socketserver, threading, time
os.chdir('$(pwd)')
class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args): pass  # suppress console noise
with socketserver.TCPServer(('', $PORT), Handler) as httpd:
    httpd.serve_forever()
" &

SERVER_PID=$!
echo "Server started (PID $SERVER_PID) on port $PORT"

# Wait briefly for the server to start
sleep 1

# Open the browser
open "http://localhost:$PORT/deny_dashboard.html"

echo ""
echo "✅ Deny Log Intelligence is running at http://localhost:$PORT/deny_dashboard.html"
echo ""
echo "Leave this window open while you use the tool."
echo "Press Ctrl+C or close this window to stop the server."
echo ""

# Keep the script running so the server stays alive
wait $SERVER_PID
