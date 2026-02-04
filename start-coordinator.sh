#!/bin/bash
#
# Simple script to start MPC Coordinator Service in background
#

cd "mpc-coordinator"

echo "Starting MPC Coordinator Service..."
echo ""

# Kill any existing instances
pkill -f node || true
sleep 1

# Start coordinator service in background
npm run dev > coordinator.log 2>&1 &
sleep 0.5

# Wait a bit for services to start
sleep 8

# Test coordinator service
echo "Testing coordinator service..."
if curl -s http://localhost:3000/health > /dev/null 2>&1; then
    echo "✅ Coordinator service is running"
else
    echo "❌ Coordinator service failed to start (check coordinator.log)"
fi

echo ""
echo "Coordinator service started in background."
echo "To stop: pkill node"
echo "To view logs: tail -f mpc-coordinator/coordinator.log"