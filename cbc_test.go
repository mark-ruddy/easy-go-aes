package aes

import (
	"fmt"
	"testing"
)

func TestAesEncryptCBC(t *testing.T) {
	orig := "hello world"
	key := "0123456789012345"
	fmt.Println("origin：", orig)
	encryptCode, err := AesEncryptCBC(orig, key)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("encrypt：", encryptCode)
	decryptCode, err := AesDecryptCBC(encryptCode, key)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("decrypt：", decryptCode)
}
