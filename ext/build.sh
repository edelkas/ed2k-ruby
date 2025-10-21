# Generate the Makefile
ruby extconf.rb
LIB_DIR=../lib
GEM_NAME=ed2k

# Build the C extension
mkdir -p $LIB_DIR
make
cp c$GEM_NAME.so $LIB_DIR/c$GEM_NAME.so
make clean