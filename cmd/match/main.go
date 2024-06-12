package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/vizv/geosite-index/pkg/common"
)

func main() {
	domain := os.Args[1]

	buf, err := os.ReadFile("./geosite.idx")
	if err != nil {
		panic(err)
	}

	index := common.NewPolicyIndex()
	if err := index.Deserialize(buf); err != nil {
		panic(err)
	}

	fmt.Println(strings.Join(index.Match(domain), "\n"))
}
