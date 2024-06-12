package builder

import (
	"fmt"
	"regexp/syntax"
	"strings"

	"github.com/vizv/geosite-index/pkg/common"
)

func NormalizeRule(domainType common.DomainType, raw string) common.Chains {
	switch domainType {
	case common.DomainTypeFull:
		return common.Chains{append(common.SplitLiteralSegment(raw, ".", false), common.Segment{Type: common.SegmentTypeMatch, Value: "EXACT"})}
	case common.DomainTypeDomain:
		return common.Chains{append(common.SplitLiteralSegment(raw, ".", false), common.Segment{Type: common.SegmentTypeMatch, Value: "SUFFIX"})}
	case common.DomainTypeRegex:
		if !strings.HasSuffix(raw, "$") {
			panic(`only support regexp ends with a "$"`)
		}

		r, err := syntax.Parse(raw, syntax.Perl)
		if err != nil {
			panic(fmt.Sprintf(`error parse regexp "%s": %s`, raw, err))
		}

		chains := common.Chains{}
		rawChains := normalizeRegexpRule(r)

		for _, rawChain := range rawChains {
			chain := common.Chain{}
			literal := ""
			for i, segment := range rawChain {
				if segment.Type == common.SegmentTypeRegex {
					if segment.Value == "^" {
						if i != len(rawChain)-1 {
							panic(`"^" must at the begin of the regexp`)
						}
					}

					if segment.Value == "$" {
						if i != 0 {
							panic(`"$" must at the end of the regexp`)
						}
						continue
					}

					if len(literal) != 0 {
						chain = append(chain, common.SplitLiteralSegment(literal, `\.`, true)...)
						literal = ""
					}

					chain = append(chain, common.Segment{Type: common.SegmentTypeRegex, Value: segment.Value})
				} else {
					literal = segment.Value + literal
				}
			}
			if len(literal) != 0 {
				chain = append(chain, common.SplitLiteralSegment(literal, `\.`, true)...)
			}

			chains = append(chains, chain)
		}

		for i, chain := range chains {
			lastSegment := chain[len(chain)-1]
			if lastSegment.Type == common.SegmentTypeRegex && lastSegment.Value == "^" {
				chain[len(chain)-1] = common.Segment{Type: common.SegmentTypeMatch, Value: "EXACT"}
			}
			if lastSegment.Type == common.SegmentTypeRegex && lastSegment.Value == ".+" {
				chain[len(chain)-1] = common.Segment{Type: common.SegmentTypeMatch, Value: "SUFFIX"}
			}
			if lastSegment.Type == common.SegmentTypePlain && lastSegment.Value == `\.` {
				chain = append(chain, common.Segment{Type: common.SegmentTypeMatch, Value: "SUFFIX"})
			}

			lastSegment = chain[len(chain)-1]
			if lastSegment.Type != common.SegmentTypeMatch {
				panic("last segment is not a match segment")
			}

			chains[i] = chain
		}

		for i, chain := range chains {
			merged := common.Chain{}
			segments := []common.Segment{}
			for _, token := range chain {
				if token.Type == common.SegmentTypePlain && token.Value == `\.` || token.Type == common.SegmentTypeMatch {
					t := common.SegmentTypePlain
					p := ""

					for _, segment := range segments {
						switch segment.Type {
						case common.SegmentTypePlain:
							p = segment.Value + p
						case common.SegmentTypeRegex:
							t = common.SegmentTypeRegex
							p = segment.Value + p
						}
					}

					if p != "" {
						merged = append(merged, common.Segment{Type: t, Value: p})
					}

					if token.Type == common.SegmentTypeMatch {
						merged = append(merged, token)
					}

					segments = []common.Segment{}
				} else {
					segments = append(segments, token)
				}
			}

			chains[i] = merged
		}

		return chains
	default:
		panic(fmt.Sprintf(`type not supported: %d`, domainType))
	}
}
