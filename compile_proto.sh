SRC_DIR="./proto"
DST_DIR="./"
./protoc/bin/protoc -I=$SRC_DIR --python_out=$DST_DIR $SRC_DIR/pairing.proto