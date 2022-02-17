package mmdb

import (
	"net"
	"strings"
	"sync"

	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"

	"github.com/oschwald/geoip2-golang"
)

var (
	mmdb *geoip2.Reader
	once sync.Once
)

func Match(ip net.IP, country string) bool {
	once.Do(func() {
		var err error
		mmdb, err = geoip2.Open(C.Path.MMDB())
		if err != nil {
			log.Warnln("[mmdb] Cannot load GeoIP: %s", err.Error())
		}
	})
	if mmdb == nil {
		log.Warnln("[mmdb] GeoIP data not loaded, matching always evaluates to false")
		return false
	}
	record, _ := mmdb.Country(ip)
	return strings.EqualFold(record.Country.IsoCode, country)
}
