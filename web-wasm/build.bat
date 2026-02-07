@echo off
echo Building WebAssembly Client...
wasm-pack build --target web --out-dir pkg

if %errorlevel% neq 0 (
    echo [Error] Build failed. Make sure 'wasm-pack' is installed.
    echo Install command: cargo install wasm-pack
    exit /b %errorlevel%
)

echo.
echo [Success] Build complete!
echo To run the demo, serve the 'web-wasm' directory with a web server.
echo Example: npx serve .
