package sniff

import (
	"errors"
	"net"
)

var (
	enable   = false
	sniffers = []Sniffer{
		TlsSniffer{},
		HttpSniffer{},
	}
)

func Enable() bool {
	return enable
}

func SetEnable(b bool) {
	enable = b
}

const (
	Http SnifferType = iota
	Tls
)

type SnifferType int

func (st SnifferType) String() string {
	switch st {
	case Http:
		return "HTTP"
	case Tls:
		return "TLS"
	default:
		return "unknown"
	}
}

type SniffResult struct {
	Host string
	Type SnifferType
}

type Sniffer interface {
	Type() SnifferType
	Sniff(bc BufConn) (string, error)
}

func Sniff(conn net.Conn) (SniffResult, error) {
	bc, ok := conn.(BufConn)
	if !ok {
		return SniffResult{}, errors.New("conn is unbuffered")
	}
	for _, sniffer := range sniffers {
		if host, err := sniffer.Sniff(bc); err == nil {
			return SniffResult{host, sniffer.Type()}, nil
		}
	}
	return SniffResult{}, errors.New("sniffer has no clue")
}
