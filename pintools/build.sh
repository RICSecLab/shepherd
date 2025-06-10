CURDIR=`pwd`
cp $CURDIR/pintools/pintool_for_shepherd.cpp $PINTOOLS_DIR
cd $PINTOOLS_DIR
mkdir obj-intel64
make obj-intel64/pintool_for_shepherd.so 
cp $PINTOOLS_DIR/obj-intel64/pintool_for_shepherd.so $CURDIR/pintools
cd $CURDIR
