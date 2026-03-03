#!/bin/bash

clear
echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    🚀 Starting PiScan...                      ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check if we're in the right directory
if [ ! -d "backend" ]; then
    echo "❌ Error: Please run this script from the iscan_project directory"
    echo ""
    echo "   cd iscan_project"
    echo "   ./start.sh"
    echo ""
    exit 1
fi

# Kill any existing instances
echo "🔍 Checking for existing instances..."
pkill -f "python.*app.py" 2>/dev/null
sleep 1

# Start the backend
echo "🔧 Starting backend server..."
cd backend
source venv/bin/activate 2>/dev/null

if [ $? -ne 0 ]; then
    echo "❌ Error: Virtual environment not found"
    echo ""
    echo "   Please run setup first:"
    echo "   cd backend"
    echo "   python3 -m venv venv"
    echo "   source venv/bin/activate"
    echo "   pip install -r requirements.txt"
    echo ""
    exit 1
fi

# Start the server in background
nohup python3 app.py > ../server.log 2>&1 &
SERVER_PID=$!

# Wait for server to start
echo "⏳ Waiting for server to start..."
sleep 3

# Check if server is running
if ps -p $SERVER_PID > /dev/null; then
    echo "✅ Server started successfully!"
    echo ""
    
    # Show access information
    echo "🌐 Access URLs:"
    echo "   User Portal: http://localhost:5001"
    echo "   Admin Portal: http://localhost:5001/admin"
    echo ""
    
    echo "📋 Server is running in the background (PID: $SERVER_PID)"
    echo ""
    echo "To stop the server, run: ./stop.sh"
    echo ""
else
    echo "❌ Failed to start server. Check server.log for details:"
    echo ""
    tail -20 ../server.log
    exit 1
fi
