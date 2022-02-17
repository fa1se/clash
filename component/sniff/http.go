package sniff

import (
	"errors"
	"strings"
)

type HttpSniffer struct{}

func (s HttpSniffer) Type() SnifferType {
	return Http
}

func peekNextLine(bc BufConn) func() (string, error) {
	lastByte := 0
	return func() (string, error) {
		line := make([]byte, 0)
		for {
			lastByte += 1
			all, err := bc.Peek(lastByte)
			if err != nil || len(all) == 0 {
				return "", errors.New("http message too shot")
			}
			if back := all[len(all)-1]; back == '\n' {
				return strings.TrimSpace(string(line)), nil
			} else {
				line = append(line, back)
			}
		}
	}
}

func (s HttpSniffer) Sniff(bc BufConn) (string, error) {
	isHttp := false
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "CONNECT", "OPTIONS", "TRACE"} {
		front, _ := bc.Peek(len(method))
		if strings.EqualFold(method, string(front)) {
			isHttp = true
			break
		}
	}
	if !isHttp {
		return "", errors.New("http method not present")
	}
	peek := peekNextLine(bc)
	for {
		line, err := peek()
		if err != nil {
			return "", err
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Host") {
			continue
		}
		if host := strings.TrimSpace(strings.Split(parts[1], ":")[0]); len(host) != 0 {
			return host, nil
		} else {
			return "", errors.New("invalid hostname")
		}
	}
}
