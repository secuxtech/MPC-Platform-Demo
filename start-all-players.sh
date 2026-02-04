#!/bin/bash
#
# Simple script to start all 3 MPC REST service players in background
#

cd "mpc-rest-service/build"

echo "Starting MPC REST Services..."
echo ""

# Kill any existing instances
pkill -f mpc_rest_service || true
sleep 1

# Start players in background
./mpc_rest_service 8001 1 > ../player1.log 2>&1 &
PID1=$!
sleep 0.5

./mpc_rest_service 8002 2 > ../player2.log 2>&1 &
PID2=$!
sleep 0.5

./mpc_rest_service 8003 3 > ../player3.log 2>&1 &
PID3=$!
sleep 1

echo "Player 1 (PID $PID1): port 8001"
echo "Player 2 (PID $PID2): port 8002"
echo "Player 3 (PID $PID3): port 8003"
echo ""

# Wait a bit for services to start
sleep 2

# Test services
echo "Testing services..."
if curl -s http://localhost:8001/health > /dev/null 2>&1; then
    echo "✅ Player 1 is running"
else
    echo "❌ Player 1 failed to start (check mpc-rest-service/player1.log)"
fi

if curl -s http://localhost:8002/health > /dev/null 2>&1; then
    echo "✅ Player 2 is running"
else
    echo "❌ Player 2 failed to start (check mpc-rest-service/player2.log)"
fi

if curl -s http://localhost:8003/health > /dev/null 2>&1; then
    echo "✅ Player 3 is running"
else
    echo "❌ Player 3 failed to start (check mpc-rest-service/player3.log)"
fi

echo ""
echo "All services started in background."
echo "To stop: pkill mpc_rest_service"
echo "To view logs: tail -f mpc-rest-service/player1.log"
