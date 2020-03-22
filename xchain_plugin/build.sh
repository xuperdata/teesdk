#!/bin/bash

:<<!
protoc -I pb pb/tf.proto \
       --go_out=paths=source_relative:pb
!
go build -buildmode=plugin -o=libmesateesdk.so.0.0.1

