# The Go Language with SM2/SM3/SM4

This project add Chinese SM2/SM3/SM4 crypto standards into Go language.

run `src/all.bash` to build Go binaries.


## SM3

SM3 is a hash function with 256-bit digest size.

```
package main

import (
	"crypto/sm3"
	"fmt"
)

func main() {
	sum := sm3.Sum([]byte("hello world\n"))
	fmt.Printf("%x", sum)
}
```

## SM4

SM4 is a block cipher with 128-bit key length and 128-bit block size.

```
import "crypto/sm4"
```

## SM2

SM2 is an ellptic curve crypto standards with the 256-bit recommanded curve.

