package common

import "strings"

func SplitLiteralSegment(literal, sep string, keep bool) []Segment {
	segments := []Segment{}

	tokens := strings.Split(literal, sep)
	for i, token := range tokens {
		if i > 0 {
			if keep {
				segments = append([]Segment{{Type: SegmentTypePlain, Value: `\.`}}, segments...)
			}
		}
		if len(token) != 0 {
			segments = append([]Segment{{Type: SegmentTypePlain, Value: token}}, segments...)
		}
	}

	return segments
}
