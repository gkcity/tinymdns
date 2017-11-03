#!/bin/sh

make

cp ../../../../tiny/target/libtiny_static.a build/tiny/libtiny.a
cp ../../../target/libtinymdns_static.a build/tinymdns/libtinymdns.a

make
