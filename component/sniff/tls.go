package sniff

import (
	"errors"
)

type TlsSniffer struct{}

func (s TlsSniffer) Type() SnifferType {
	return Tls
}

func peekRead(bc BufConn) func(int) ([]byte, error) {
	lastByte := 0
	return func(n int) ([]byte, error) {
		lastByte += n
		all, err := bc.Peek(lastByte)
		if err != nil {
			return nil, err
		}
		return all[lastByte-n:], nil
	}
}

func memorizedBufferPeek(buf []byte) func(int) ([]byte, error) {
	pointer := 0
	return func(n int) ([]byte, error) {
		pointer += n
		if pointer > len(buf) {
			return nil, errors.New("tls message too short")
		}
		return buf[pointer-n : pointer], nil
	}
}

func lengthLead(peek func(int) ([]byte, error), n int) ([]byte, error) {
	lengthBytes, err := peek(n)
	if err != nil {
		return nil, err
	}
	length := 0
	for _, b := range lengthBytes {
		length = length<<8 + int(b)
	}
	if length == 0 {
		return nil, nil
	}
	return peek(length)
}

func (s TlsSniffer) Sniff(bc BufConn) (string, error) {
	peek := peekRead(bc)
	// record header (5B)
	handshake, err := peek(1)
	if err != nil || handshake[0] != 0x16 {
		return "", errors.New("not a tls handshake record")
	}
	version, err := peek(2)
	if err != nil || version[0] != 0x03 {
		return "", errors.New("invalid tls version")
	}
	message, err := lengthLead(peek, 2)
	if err != nil {
		return "", err
	}
	peek = memorizedBufferPeek(message)
	// handshake header (4B) || client version (2B) || clietn random (32B)
	if _, err = peek(38); err != nil {
		return "", err
	}
	// session id (1B + nB)
	if _, err = lengthLead(peek, 1); err != nil {
		return "", err
	}
	// cipher suites (2B + nB)
	if _, err = lengthLead(peek, 2); err != nil {
		return "", err
	}
	// compression methods (1B + nB)
	if _, err = lengthLead(peek, 1); err != nil {
		return "", err
	}
	// extensions (2B + nB)
	extensions, err := lengthLead(peek, 2)
	if err != nil {
		return "", err
	}
	peek = memorizedBufferPeek(extensions)
	for {
		// extension type (2B)
		extName, err := peek(2)
		if err != nil {
			return "", err
		}
		// extension data (2B + nB)
		extData, err := lengthLead(peek, 2)
		if err != nil {
			return "", err
		}
		if extName[0] != 0x00 || extName[1] != 0x00 {
			continue
		}
		peek := memorizedBufferPeek(extData)
		list, err := lengthLead(peek, 2)
		if err != nil {
			return "", err
		}
		peek = memorizedBufferPeek(list)
		for {
			// entry type (1B)
			entryType, err := peek(1)
			if err != nil {
				return "", err
			}
			// entry data (1B + nB)
			hostBytes, err := lengthLead(peek, 2)
			if err != nil {
				return "", err
			}
			if entryType[0] != 0x00 {
				continue
			}
			return string(hostBytes), nil
		}
	}
}
