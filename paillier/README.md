## paillier 
A Paillier SDK by Golang 

## Usage 

1. run the unit test  
```
go test
```
or your program.


2. run benchmark test
```
go test -bench=.
```

## Performance 

goos: darwin

goarch: amd64

|        | 1024 secret(op/s) | 2048 secbit(op/s) | 4096 secbit(op/s) |
| ------ | ----------------- | ----------------- | ----------------- |
| KeyGen | 49                | 5                 | 1                 |
| Enc    | 450               | 68                | 9                 |
| Dec    | 421               | 64                | 9                 |
| Add    | 231857            | 81327             | 27924             |
| Scalar | 62181             | 20756             | 7525              |

## Reference
1. http://hms.isi.jhu.edu/acsc/libpaillier/
