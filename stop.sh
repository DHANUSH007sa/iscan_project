#!/bin/bash

clear
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    🛑 Stopping PiScan...                      ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Kill the server
echo "🔍 Looking for running server..."
pkill -f "python.*app.py"

if [ $? -eq 0 ]; then
    echo "✅ Server stopped successfully!"
else
    echo "ℹ️  No running server found"
fi

echo ""
