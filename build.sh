#!/bin/bash

:<<!
protoc -I pb pb/tf.proto \
       --go_out=paths=source_relative:pb
!
export GO111MODULE=on

mkdir build
go build -buildmode=plugin -o=./build/libmesateesdk.so.0.0.1 ./mesatee/xchain_plugin/
go build -buildmode=plugin -o=./build/libpaillier.so.0.0.1 ./paillier/xchain_plugin/
