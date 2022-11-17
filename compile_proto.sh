SRC_FILE="./atvremote/pair/proto/pairing.proto"
DST_DIR="./"
./protoc/bin/protoc $SRC_FILE --python_out=$DST_DIR --mypy_out=$DST_DIR
SRC_FILE="./atvremote/remote/proto/commands.proto"
./protoc/bin/protoc $SRC_FILE --python_out=$DST_DIR --mypy_out=$DST_DIR