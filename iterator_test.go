package main

import (
	"context"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIterator(t *testing.T) {
	cases := []struct {
		addrExpression string
		portExpression string
		expect         []string
		expectCount    int
	}{
		{
			addrExpression: "10.233.1.2,10.233.1.3",
			portExpression: "80,443-445",
			expect: []string{
				"10.233.1.2:80",
				"10.233.1.2:443",
				"10.233.1.2:444",
				"10.233.1.2:445",
				"10.233.1.3:80",
				"10.233.1.3:443",
				"10.233.1.3:444",
				"10.233.1.3:445",
			},
		},
		{
			addrExpression: "10.233.1.0/24",
			portExpression: "80,81",
			expectCount:    256 * 2,
		},
	}
	ctx := context.Background()
	for _, c := range cases {
		i, err := NewAddressIterator(ctx, c.addrExpression, c.portExpression)
		if err != nil {
			t.Error(err)
			return
		}
		results := make([]string, 0)
		for addr := range i.Iter() {
			t.Log(addr)
			results = append(results, addr.String())
		}
		sort.Strings(results)
		if c.expectCount > 0 {
			assert.Equal(t, c.expectCount, len(results))
		} else {
			sort.Strings(c.expect)
			assert.Equal(t, c.expect, results)
		}

	}
}
