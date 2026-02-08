#!/bin/bash
mkdir -p bin
echo "Building Bug Bounty Suite..."

# C++ build (Windows lws2_32 library ekka)
echo "Building C++ port scanner..."
g++ -std=c++11 -o bin/port_scanner.exe scanner/port_scanner.cpp -lws2_32 -pthread

# Rust build (fuzzer folder ekata gihin)
echo "Building Rust fuzzer..."
cd fuzzer
cargo build --release
cp target/release/http_fuzzer.exe ../bin/
cd ..

# Go build (recon folder ekata gihin)
echo "Building Go recon tool..."
cd recon
go build -o ../bin/web_recon.exe web_recon.go
cd ..

echo "Build complete! Executables are in bin/ directory."