package builder

import (
	"fmt"
	"regexp/syntax"

	"github.com/vizv/geosite-index/pkg/common"
)

// EmptyMatch                   // matches empty string

func normalizeRegexpRule(r *syntax.Regexp) common.Chains {
	switch r.Op {
	case syntax.OpEndText:
		return common.Chains{common.Chain{common.Segment{Type: common.SegmentTypeRegex, Value: "$"}}}
	case syntax.OpLiteral:
		return common.Chains{common.Chain{common.Segment{Type: common.SegmentTypePlain, Value: r.String()}}}
	case syntax.OpCapture:
		return normalizeRegexpRule(r.Sub[0])
	case syntax.OpQuest:
		return append(common.Chains{common.Chain{}}, normalizeRegexpRule(r.Sub[0])...)
	case syntax.OpConcat:
		chains := common.Chains{}
		for i := len(r.Sub) - 1; i >= 0; i-- {
			segmentChains := normalizeRegexpRule(r.Sub[i])

			if len(chains) == 0 {
				chains = segmentChains
				continue
			}

			newChains := common.Chains{}
			for _, chain := range chains {
				for _, segmentChain := range segmentChains {
					newChain := append(append(common.Chain{}, chain...), segmentChain...)
					newChains = append(newChains, newChain)
				}
			}
			chains = newChains
		}
		return chains
	case syntax.OpAlternate:
		chains := common.Chains{}
		for _, sub := range r.Sub {
			chains = append(chains, normalizeRegexpRule(sub)...)
		}
		return chains
	case syntax.OpPlus:
		if r.String() == "(?-s:.+)" {
			return common.Chains{common.Chain{common.Segment{Type: common.SegmentTypeRegex, Value: ".+"}}}
		}

		return common.Chains{common.Chain{common.Segment{Type: common.SegmentTypeRegex, Value: r.String()}}}
	case syntax.OpStar:
		return common.Chains{common.Chain{common.Segment{Type: common.SegmentTypeRegex, Value: r.String()}}}
	case syntax.OpRepeat:
		return common.Chains{common.Chain{common.Segment{Type: common.SegmentTypeRegex, Value: r.String()}}}
	case syntax.OpBeginText:
		return common.Chains{common.Chain{common.Segment{Type: common.SegmentTypeRegex, Value: "^"}}}
	case syntax.OpAnyCharNotNL:
		// FIXME: warn about "."
		return common.Chains{common.Chain{common.Segment{Type: common.SegmentTypeRegex, Value: "."}}}
	case syntax.OpCharClass:
		return common.Chains{common.Chain{common.Segment{Type: common.SegmentTypeRegex, Value: r.String()}}}
	case syntax.OpAnyChar, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		panic(fmt.Sprintf(`Regexp operator "%+v" not supported`, r.Op))
	default:
		panic(fmt.Sprintf(`Regexp operator "%+v" not implemented`, r.Op))
	}
}
