## teesdk 
A MesaTEE SDK by Golang as a wrapper of the C SDK

## Usage 
1. compile [mesatee-core-standalone](https://github.com/xuperdata/mesatee-core-standalone), and update the dylib [lib/libmesatee_sdk_c.so](./lib/libmesatee_sdk_c.so)

2. start the MesaTEE service;

3. run the unit test  
```
go test -v ./... -mod=vendor
```
or your program.
