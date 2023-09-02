package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

func AesEncryptCBC(orig string, key string) (string, error) {
	origData := []byte(orig)
	k := []byte(key)

	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()

	origData = PKCS7Padding(origData, blockSize)

	blockMode := cipher.NewCBCEncrypter(block, k[:blockSize])

	cryted := make([]byte, len(origData))

	blockMode.CryptBlocks(cryted, origData)
	return base64.StdEncoding.EncodeToString(cryted), nil
}

func AesDecryptCBC(cryted string, key string) (string, error) {
	crytedByte, _ := base64.StdEncoding.DecodeString(cryted)
	k := []byte(key)

	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()

	blockMode := cipher.NewCBCDecrypter(block, k[:blockSize])

	orig := make([]byte, len(crytedByte))

	blockMode.CryptBlocks(orig, crytedByte)

	unpaddedOrig := PKCS7UnPadding(orig)
	if unpaddedOrig != nil {
		orig = unpaddedOrig
	}
	return string(orig), nil
}
