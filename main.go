package aes_256_ecb

import (
	"crypto/aes"
	"errors"
)

func Decrypt(data, key []byte) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := b.BlockSize()

	if len(data)%bs != 0 {
		return nil, errors.New("block size cannot match data size")
	}

	info := make([]byte, 0)
	dst := make([]byte, 16)
	for len(data) > 0 {
		b.Decrypt(dst, data)
		data = data[bs:]
		info = append(info, dst...)
	}
	info = PKCS7UnPadding(info)
	return info, nil
}

func PKCS7UnPadding(data []byte) []byte {
	l := len(data)
	un := int(data[l-1])
	return data[:(l - un)]
}
