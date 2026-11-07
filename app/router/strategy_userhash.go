package router

import "hash/fnv"

// UserHashStrategy assigns users to a sorted outbound pool without keeping session state.
type UserHashStrategy struct{}

func (s *UserHashStrategy) GetPrincipleTarget(candidates []string) []string {
	return candidates
}

func (s *UserHashStrategy) PickOutbound(candidates []string, user string) string {
	if user == "" || len(candidates) == 0 {
		return ""
	}

	hash := fnv.New64a()
	hash.Write([]byte(user))
	// shortcut: pool changes can remap many users; use consistent hashing if that churn becomes a problem.
	return candidates[hash.Sum64()%uint64(len(candidates))]
}
