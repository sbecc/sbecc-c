cd libsodium
sh ./autogen.sh
./configure
make
make check
cd ..
sh build.sh