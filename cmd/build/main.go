package main

import (
	"bufio"
	"os"
	"strings"

	"github.com/vizv/geosite-index/pkg/builder"
	"github.com/vizv/geosite-index/pkg/common"
)

func main() {
	file, err := os.Open("./domain-list-community.txt")
	if err != nil {
		panic(err)
	}

	policyNameIndexes := map[string]uint32{}
	index := common.NewPolicyIndex()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		rule := scanner.Text()
		if rule == "" {
			continue
		}

		r := strings.SplitN(rule, ":", 3)
		policyName := r[0]
		rawMode := r[1]
		raw := r[2]
		var mode common.DomainType
		switch rawMode {
		case "Regex":
			mode = common.DomainTypeRegex
		case "Domain":
			mode = common.DomainTypeDomain
		case "Full":
			mode = common.DomainTypeFull
		}

		policyNameIndex, ok := policyNameIndexes[policyName]
		if !ok {
			policyNameIndex = uint32(len(policyNameIndexes))
			policyNameIndexes[policyName] = policyNameIndex
			index.Policies[policyNameIndex] = policyName
		}

		chains := builder.NormalizeRule(mode, raw)
		for _, chain := range chains {
			index.AppendChain(chain, policyNameIndex)
		}
	}

	bytes, err := index.Serialize()
	if err != nil {
		panic(err)
	}

	if err := os.WriteFile("./geosite.idx", bytes, 0o644); err != nil {
		panic(err)
	}

	index.Dump()
}
