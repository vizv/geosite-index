package common

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

type DomainType int

const (
	DomainTypePlain  DomainType = 0
	DomainTypeRegex  DomainType = 1
	DomainTypeDomain DomainType = 2
	DomainTypeFull   DomainType = 3
)

type SegmentType int

const (
	SegmentTypePlain SegmentType = 0
	SegmentTypeRegex SegmentType = 1
	SegmentTypeMatch SegmentType = 2
)

func (i SegmentType) String() string {
	switch i {
	case SegmentTypePlain:
		return "PLAIN"
	case SegmentTypeRegex:
		return "REGEX"
	case SegmentTypeMatch:
		return "MATCH"
	}

	return "XXXXX"
}

type Chains []Chain
type Chain []Segment
type Segment struct {
	Type  SegmentType
	Value string
}

type PolicySet map[uint32]bool
type RuleMap map[string]*RuleNode
type RuleNode struct {
	ExactPolicies  PolicySet
	SuffixPolicies PolicySet
	PlainRules     RuleMap
	RegexpRules    RuleMap
}

func NewRuleNode() *RuleNode {
	return &RuleNode{
		ExactPolicies:  make(PolicySet),
		SuffixPolicies: make(PolicySet),
		PlainRules:     make(RuleMap),
		RegexpRules:    make(RuleMap),
	}
}

type PolicyMap map[uint32]string
type PolicyIndex struct {
	Version  uint32
	Policies PolicyMap
	Rules    *RuleNode
}

func NewPolicyIndex() *PolicyIndex {
	return &PolicyIndex{Version: 1, Policies: make(PolicyMap), Rules: NewRuleNode()}
}

func (p *PolicyIndex) AppendChain(chain Chain, policyIndex uint32) {
	r := p.Rules
	for _, segment := range chain {
		switch segment.Type {
		case SegmentTypePlain:
			nr := r.PlainRules[segment.Value]
			if nr == nil {
				nr = NewRuleNode()
				r.PlainRules[segment.Value] = nr
			}

			r = nr
		case SegmentTypeRegex:
			nr := r.RegexpRules[segment.Value]
			if nr == nil {
				nr = NewRuleNode()
				r.RegexpRules[segment.Value] = nr
			}

			r = nr
		case SegmentTypeMatch:
			switch segment.Value {
			case "EXACT":
				r.ExactPolicies[policyIndex] = true
			case "SUFFIX":
				r.SuffixPolicies[policyIndex] = true
			default:
				panic("invalid match")
			}
		default:
			panic("invalid segment")
		}
	}
}

func (p *PolicyIndex) dumpRuleMap(m RuleMap, t SegmentType, level int) {
	indent := strings.Repeat("  ", level)

	segments := make([]string, 0, len(m))
	for segment := range m {
		segments = append(segments, segment)
	}
	sort.Strings(segments)

	for _, segment := range segments {
		r := m[segment]
		fmt.Printf("%s:%s%s\n", t.String(), indent, segment)
		p.dumpNode(r, level+1)
	}
}

type PolicyNameSet map[string]bool

func (p *PolicyIndex) GetPolicyNameSet(set PolicySet) PolicyNameSet {
	names := make(PolicyNameSet)

	for id := range set {
		name, ok := p.Policies[id]
		if !ok {
			panic(fmt.Sprintf("invalid policy id: %d", id))
		}
		names[name] = true
	}

	return names
}

func (p *PolicyIndex) GetSetValues(set PolicySet) []string {
	names := []string{}
	policyNames := p.GetPolicyNameSet(set)
	for name := range policyNames {
		names = append(names, name)
	}

	sort.Strings(names)
	return names
}

func (p *PolicyIndex) dumpNode(n *RuleNode, level int) {
	indent := strings.Repeat("  ", level)

	if len(n.ExactPolicies) != 0 {
		fmt.Printf("%s:%s%s:%s\n", "EXACT", indent, "MATCH", strings.Join(p.GetSetValues(n.ExactPolicies), ","))

	}

	if len(n.SuffixPolicies) != 0 {
		fmt.Printf("%s:%s%s:%s\n", "SUFIX", indent, "MATCH", strings.Join(p.GetSetValues(n.SuffixPolicies), ","))
	}

	p.dumpRuleMap(n.PlainRules, SegmentTypePlain, level)
	p.dumpRuleMap(n.RegexpRules, SegmentTypeRegex, level)
}

func (p *PolicyIndex) Dump() {
	p.dumpNode(p.Rules, 0)
}

func (p *PolicyIndex) serializeUint32(w io.Writer, i uint32) error {
	err := binary.Write(w, binary.LittleEndian, i)

	return err
}

func (p *PolicyIndex) deserializeUint32(r io.Reader, i *uint32) error {
	err := binary.Read(r, binary.LittleEndian, i)

	return err
}

func (p *PolicyIndex) serializeString(w *bytes.Buffer, s string) error {
	n, err := w.WriteString(s)
	if n != len(s) {
		return io.ErrShortWrite
	}

	return err
}

func (p *PolicyIndex) deserializeString(r io.Reader, s *string, slen uint32) error {
	buf := make([]byte, slen)
	n, err := r.Read(buf)
	if uint32(n) != slen {
		return io.ErrShortWrite
	}
	*s = string(buf)

	return err
}

func (p *PolicyIndex) serializeStringN(w *bytes.Buffer, s string) error {
	slen := uint32(len(s))
	if err := p.serializeUint32(w, slen); err != nil {
		return err
	}
	return p.serializeString(w, s)
}

func (p *PolicyIndex) deserializeStringN(r io.Reader, s *string) error {
	var slen uint32
	if err := p.deserializeUint32(r, &slen); err != nil {
		return err
	}

	return p.deserializeString(r, s, slen)
}

func (p *PolicyIndex) serializePolicySet(w *bytes.Buffer, s PolicySet) error {
	slen := uint32(len(s))
	if err := p.serializeUint32(w, slen); err != nil {
		return err
	}
	for i := range s {
		if err := p.serializeUint32(w, i); err != nil {
			return err
		}
	}

	return nil
}

func (p *PolicyIndex) deserializePolicySet(r io.Reader, s PolicySet) error {
	var slen uint32
	if err := p.deserializeUint32(r, &slen); err != nil {
		return err
	}
	for i := uint32(0); i < slen; i++ {
		var n uint32
		if err := p.deserializeUint32(r, &n); err != nil {
			return err
		}
		s[n] = true
	}

	return nil
}

func (p *PolicyIndex) serializeRuleMap(w *bytes.Buffer, m RuleMap) error {
	mlen := uint32(len(m))
	if err := p.serializeUint32(w, mlen); err != nil {
		return err
	}
	for segment, n := range m {
		if err := p.serializeStringN(w, segment); err != nil {
			return err
		}
		if err := p.serializeRuleNode(w, n); err != nil {
			return err
		}
	}

	return nil
}

func (p *PolicyIndex) deserializeRuleMap(r io.Reader, m RuleMap) error {
	var mlen uint32
	if err := p.deserializeUint32(r, &mlen); err != nil {
		return err
	}
	for i := uint32(0); i < mlen; i++ {
		var s string
		if err := p.deserializeStringN(r, &s); err != nil {
			return err
		}
		n := NewRuleNode()
		if err := p.deserializeRuleNode(r, n); err != nil {
			return err
		}
		m[s] = n
	}

	return nil
}

func (p *PolicyIndex) serializeRuleNode(w *bytes.Buffer, n *RuleNode) error {
	if err := p.serializePolicySet(w, n.ExactPolicies); err != nil {
		return err
	}

	if err := p.serializePolicySet(w, n.SuffixPolicies); err != nil {
		return err
	}

	if err := p.serializeRuleMap(w, n.PlainRules); err != nil {
		return err
	}

	if err := p.serializeRuleMap(w, n.RegexpRules); err != nil {
		return err
	}

	return nil
}

func (p *PolicyIndex) deserializeRuleNode(r io.Reader, n *RuleNode) error {
	if err := p.deserializePolicySet(r, n.ExactPolicies); err != nil {
		return err
	}

	if err := p.deserializePolicySet(r, n.SuffixPolicies); err != nil {
		return err
	}

	if err := p.deserializeRuleMap(r, n.PlainRules); err != nil {
		return err
	}

	if err := p.deserializeRuleMap(r, n.RegexpRules); err != nil {
		return err
	}

	return nil
}

func (p *PolicyIndex) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	w := &buf
	if err := p.serializeString(w, "GEOI"); err != nil {
		return nil, err
	}
	if err := p.serializeUint32(w, p.Version); err != nil {
		return nil, err
	}

	plen := uint32(len(p.Policies))
	if err := p.serializeUint32(w, plen); err != nil {
		return nil, err
	}

	for i := uint32(0); i < plen; i++ {
		name := p.Policies[i]
		if err := p.serializeStringN(w, name); err != nil {
			return nil, err
		}
	}
	if err := p.serializeRuleNode(w, p.Rules); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (p *PolicyIndex) Deserialize(buf []byte) error {
	r := bytes.NewReader(buf)
	var magic string
	if err := p.deserializeString(r, &magic, 4); err != nil {
		return fmt.Errorf("invalid file magic")
	}

	if err := p.deserializeUint32(r, &p.Version); err != nil {
		return err
	}
	if p.Version != 1 {
		return fmt.Errorf("unsupported version %d", p.Version)
	}

	var plen uint32
	if err := p.deserializeUint32(r, &plen); err != nil {
		return err
	}
	for i := uint32(0); i < plen; i++ {
		var name string
		if err := p.deserializeStringN(r, &name); err != nil {
			return err
		}
		p.Policies[i] = name
	}

	if err := p.deserializeRuleNode(r, p.Rules); err != nil {
		return err
	}

	return nil
}

func reverseSlice(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func (n *RuleNode) Match(s PolicySet, tokens []string) {
	if len(tokens) == 0 {
		for p := range n.ExactPolicies {
			s[p] = true
		}

		return
	}

	if len(n.SuffixPolicies) > 0 {
		for p := range n.SuffixPolicies {
			s[p] = true
		}
	}

	token := tokens[0]
	rest := tokens[1:]
	pr := n.PlainRules[token]
	if pr != nil {
		pr.Match(s, rest)
	}

	for r, rr := range n.RegexpRules {
		re := regexp.MustCompile(fmt.Sprintf("^%s$", r))
		if re.MatchString(token) {
			rr.Match(s, rest)
		}
	}
}

func (p *PolicyIndex) Match(domain string) []string {
	ps := make(PolicySet)
	tokens := strings.Split(domain, ".")
	reverseSlice(tokens)
	p.Rules.Match(ps, tokens)

	names := []string{}
	ns := p.GetPolicyNameSet(ps)
	for name := range ns {
		names = append(names, name)
	}

	return names
}
