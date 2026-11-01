#!/usr/bin/env bash
# Prints the README's example: each command as it would be typed, then what it prints.
set -u
cd "$(dirname "$0")/.."
bin=${NETPOLWARDEN:-./bin/netpolwarden}
echo '$ netpolwarden testdata/shop.yaml'
"$bin" testdata/shop.yaml | tr -d '\r'
echo
echo '$ netpolwarden testdata/shop.yaml --can "monitoring/prometheus shop/api 9100"'
"$bin" testdata/shop.yaml --can "monitoring/prometheus shop/api 9100" | tr -d '\r'
echo
echo '$ netpolwarden testdata/shop.yaml --matrix'
"$bin" testdata/shop.yaml --matrix | tr -d '\r'
