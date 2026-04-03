#!/bin/bash

echo "Building AXIS 2.0 P2P Relay Server..."

cd relay

go mod init relay 2>/dev/null
go get .

go build -o ../relay_server . || { echo "Build failed"; exit 1; }

cd ..

echo "Build complete!"
echo ""
echo "To run:"
echo "  ./relay_server"
echo ""
echo "Users can then telnet to your VPS IP:6969"
echo "Default credentials: admin / admin123"
