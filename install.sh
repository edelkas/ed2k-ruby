# DESC     Script to rebuild and reinstall the gem locally
# USAGE    ./install.sh VERSION
# EXAMPLE  ./install.sh 0.2.1
cd ext
./build.sh
cd ..
gem build
gem install ed2k-$1.gem