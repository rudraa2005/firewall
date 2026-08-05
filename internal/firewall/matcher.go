package firewall

import "strings"

type ahoNode struct {
	Next map[rune]int
	Fail int
	Out  []int
}

type AhoCorasick struct {
	nodes    []ahoNode
	patterns []PatternEntry
}

func NewAhoCorasick(patterns []PatternEntry) *AhoCorasick {
	ac := &AhoCorasick{
		nodes:    []ahoNode{{Next: map[rune]int{}}},
		patterns: make([]PatternEntry, 0, len(patterns)),
	}

	for _, pattern := range patterns {
		value := cleanPattern(pattern.Pattern)
		if value == "" {
			continue
		}
		entry := PatternEntry{Pattern: value, Weight: pattern.Weight}
		ac.patterns = append(ac.patterns, entry)
		index := len(ac.patterns) - 1
		node := 0
		for _, r := range value {
			next, ok := ac.nodes[node].Next[r]
			if !ok {
				next = len(ac.nodes)
				ac.nodes[node].Next[r] = next
				ac.nodes = append(ac.nodes, ahoNode{Next: map[rune]int{}})
			}
			node = next
		}
		ac.nodes[node].Out = append(ac.nodes[node].Out, index)
	}

	queue := make([]int, 0)
	for _, child := range ac.nodes[0].Next {
		queue = append(queue, child)
	}

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		for r, child := range ac.nodes[node].Next {
			queue = append(queue, child)
			fail := ac.nodes[node].Fail
			for fail != 0 {
				next, ok := ac.nodes[fail].Next[r]
				if ok {
					ac.nodes[child].Fail = next
					break
				}
				fail = ac.nodes[fail].Fail
			}
			if ac.nodes[child].Fail == 0 {
				if next, ok := ac.nodes[0].Next[r]; ok && next != child {
					ac.nodes[child].Fail = next
				}
			}
			ac.nodes[child].Out = append(ac.nodes[child].Out, ac.nodes[ac.nodes[child].Fail].Out...)
		}
	}

	return ac
}

func (ac *AhoCorasick) Scan(text string) ScanResult {
	result := ScanResult{}
	if ac == nil || len(ac.patterns) == 0 {
		return result
	}

	seen := map[string]struct{}{}
	node := 0
	for _, r := range strings.ToLower(text) {
		for node != 0 {
			if _, ok := ac.nodes[node].Next[r]; ok {
				break
			}
			node = ac.nodes[node].Fail
		}
		if next, ok := ac.nodes[node].Next[r]; ok {
			node = next
		}

		for _, index := range ac.nodes[node].Out {
			entry := ac.patterns[index]
			if _, ok := seen[entry.Pattern]; ok {
				continue
			}
			seen[entry.Pattern] = struct{}{}
			result.Patterns = append(result.Patterns, entry.Pattern)
			result.Score += entry.Weight
		}
	}

	return result
}
