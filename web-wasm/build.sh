#!/bin/bash
set -e

echo "Building WebAssembly Client..."

if ! command -v wasm-pack &> /dev/null; then
    echo "[Error] 'wasm-pack' could not be found."
    echo "Please install it using: cargo install wasm-pack"
    echo "Or visit https://rustwasm.github.io/wasm-pack/installer/"
    exit 1
fi

wasm-pack build --target web --out-dir pkg

echo ""
echo "[Success] Build complete!"
echo "To run the demo, serve the 'web-wasm' directory with a web server."
echo "Example: npx serve ."
