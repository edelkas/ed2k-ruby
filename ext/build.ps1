# Generate the Makefile
ruby extconf.rb
$LIB_DIR = "../lib"
$GEM_NAME = "ed2k"

# Build the C extension
if (!(Test-Path $LIB_DIR)) {
    New-Item -ItemType Directory -Path $LIB_DIR | Out-Null
}
make
Copy-Item "c$GEM_NAME.so" "$LIB_DIR/c$GEM_NAME.so" -Force
make clean