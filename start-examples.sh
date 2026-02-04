#!/bin/bash
#
# Simple script to start MPC Coordinator Service in background
#

cd "mpc-coordinator/examples"

echo "Starting MPC Coordinator Testing & Examples..."
echo ""

# Start Testing & examples in background
npm run test:rest > ../logs/rest_service_integration_test.log 2>&1 &
sleep 0.5

npm run example:bitcoin > ../logs/example_bitcoin.log 2>&1 &
sleep 0.5

npm run example:ethereum > ../logs/example_ethereum.log 2>&1 &
sleep 0.5

echo ""
echo "MPC Coordinator Testing & Examples started in background."
echo "To view logs: tail -f mpc-coordinator/logs/rest_service_integration_test.log"
echo "To view logs: tail -f mpc-coordinator/logs/example_bitcoin.log"
echo "To view logs: tail -f mpc-coordinator/logs/example_ethereum.log"