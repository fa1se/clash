package geosite

import (
	"io/ioutil"
	"net"
	"sync"

	"github.com/Dreamacro/clash/component/trie"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	dlc "github.com/fa1se/dlc-parser"
)

var (
	tree = make(map[string]*trie.DomainTrie)
	once sync.Once
	list dlc.Collection
)

func LoadMatcher(expr string) {
	once.Do(func() {
		raw, err := ioutil.ReadFile(C.Path.DLC())
		if err != nil {
			log.Warnln("[GeoSite] %s", err.Error())
			return
		}
		list = dlc.ParseCollection(raw)
		if list == nil {
			log.Warnln("[GeoSite] malformed geosite database")
		}
	})
	if list == nil {
		return
	}
	domains := list.Select(expr)
	if len(domains) == 0 {
		log.Warnln("[GeoSite] no matching entry to '%s'", expr)
		return
	}
	tree[expr] = trie.New()
	for _, domain := range domains {
		switch domain.Type {
		case dlc.RECORD_FULL:
			tree[expr].Insert(domain.Value, net.IP{0, 0, 0, 0})
		case dlc.RECORD_DOMAIN:
			tree[expr].Insert("+."+domain.Value, net.IP{0, 0, 0, 0})
		case dlc.RECORD_REGEXP:
			log.Debugln("[GeoSite] regexp: %s ignored", domain.Value)
		case dlc.RECORD_KEYWORD:
			log.Debugln("[GeoSite] keyword: %s ignored", domain.Value)
		}
	}
}

func Match(host, tag string) bool {
	tree := tree[tag]
	return tree != nil && tree.Search(host) != nil
}
