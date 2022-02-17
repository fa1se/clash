package rules

import (
	"github.com/Dreamacro/clash/component/geosite"
	C "github.com/Dreamacro/clash/constant"
)

type GEOSITE struct {
	tag     string
	adapter string
}

func (g *GEOSITE) RuleType() C.RuleType {
	return C.GEOSITE
}

func (g *GEOSITE) Match(metadata *C.Metadata) bool {
	if metadata.Host == "" {
		return false
	}
	return geosite.Match(metadata.Host, g.tag)
}

func (g *GEOSITE) Adapter() string {
	return g.adapter
}

func (g *GEOSITE) Payload() string {
	return g.tag
}

func (g *GEOSITE) ShouldResolveIP() bool {
	return false
}

func (i *GEOSITE) ShouldFindProcess() bool {
	return false
}

func NewGEOSITE(tag string, adapter string) *GEOSITE {
	geosite.LoadMatcher(tag)
	return &GEOSITE{
		tag:     tag,
		adapter: adapter,
	}
}
