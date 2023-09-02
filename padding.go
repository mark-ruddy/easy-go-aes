package aes

import "bytes"

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	if length == 0 {
		return nil // Return an error or handle the case appropriately
	}
	unpadding := int(origData[length-1])
	if unpadding > length || unpadding == 0 {
		// Invalid padding, return an error or handle the case appropriately
		return nil
	}
	return origData[:(length - unpadding)]
}
