/*
Copyright 2024 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Inspired by https://raw.githubusercontent.com/AdaLogics/go-fuzz-headers/main/bytesource/bytesource.go

package fuzz

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand/v2"
)

type ByteSource struct {
	rand.Rand

	randReader io.Reader

	maxLength uint64
}

type randReader struct {
	rand.Source

	// readVal contains remainder of 64-bit integer used for bytes
	// generation during most recent Read call.
	// It is saved so next Read call can start where the previous
	// one finished.
	readVal uint64
	// readPos indicates the number of low-order bytes of readVal
	// that are still valid.
	readPos int8
}

func (r *randReader) Read(p []byte) (n int, err error) {
	pos := r.readPos
	val := r.readVal
	for n = 0; n < len(p); n++ {
		if pos == 0 {
			val = r.Source.Uint64()
			pos = 8
		}
		p[n] = byte(val)
		val >>= 8
		pos--
	}
	r.readPos = pos
	r.readVal = val
	return
}

// NewByteSource returns a new ByteSource from a given slice of bytes.
func NewByteSource(input []byte) *ByteSource {
	// Expand the input using a random number generator.
	var rndReader io.Reader
	{
		var randNummerBytes [16]byte
		n := copy(randNummerBytes[:], input)
		input = input[n:]

		randNummer1 := binary.BigEndian.Uint64(randNummerBytes[:8])
		randNummer2 := binary.BigEndian.Uint64(randNummerBytes[8:])

		rndReader = &randReader{
			Source: rand.NewPCG(randNummer1, randNummer2),
		}
	}

	bs := &ByteSource{
		randReader: io.MultiReader(bytes.NewReader(input), rndReader),
		maxLength:  15,
	}
	bs.Rand = *rand.New(bs)
	return bs
}

func (s *ByteSource) Uint64() uint64 {
	var bytes [8]byte
	_, _ = s.randReader.Read(bytes[:])
	return binary.BigEndian.Uint64(bytes[:])
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func (s *ByteSource) String() string {
	slen := s.Uint64() % s.maxLength

	b := make([]rune, slen)
	for i := range b {
		b[i] = letterRunes[s.IntN(len(letterRunes))]
	}

	return string(b)
}

func (s *ByteSource) Bytes() []byte {
	len := s.Uint64() % s.maxLength

	bytes := make([]byte, len)
	_, _ = s.randReader.Read(bytes)

	return bytes
}

func (s *ByteSource) Bool() bool {
	return s.Uint64()%2 == 0
}

func (s *ByteSource) Read(p []byte) (n int, err error) {
	n, err = s.randReader.Read(p)
	if err != nil {
		panic("failed reading source") // Should not happen.
	}
	return n, nil
}
