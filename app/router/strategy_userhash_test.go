package router_test

import (
	"context"
	"slices"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	outbound_manager "github.com/xtls/xray-core/app/proxyman/outbound"
	. "github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/outbound"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

func TestUserHashAssignments(t *testing.T) {
	pool := []string{"exit-a", "exit-b", "exit-c", "exit-d", "exit-e"}
	strategy := new(UserHashStrategy)
	tests := []struct {
		name       string
		candidates []string
		user       string
		want       string
	}{
		{name: "alice", candidates: pool, user: "alice", want: "exit-d"},
		{name: "bob", candidates: pool, user: "bob", want: "exit-c"},
		{name: "shared_exit", candidates: pool, user: "carol", want: "exit-c"},
		{name: "case_sensitive", candidates: pool, user: "Alice", want: "exit-e"},
		{name: "leading_space", candidates: pool, user: " alice", want: "exit-a"},
		{name: "trailing_space", candidates: pool, user: "alice ", want: "exit-e"},
		{name: "single_candidate", candidates: []string{"only-exit"}, user: "alice", want: "only-exit"},
		{name: "missing_user", candidates: pool},
		{name: "empty_pool", candidates: []string{}, user: "alice"},
		{name: "nil_pool", user: "alice"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			for _, instance := range []*UserHashStrategy{strategy, new(UserHashStrategy), strategy} {
				if got := instance.PickOutbound(test.candidates, test.user); got != test.want {
					t.Fatalf("got %q, want %q", got, test.want)
				}
			}
		})
	}
}

type userHashOutbound struct {
	outbound.Handler
	tag string
}

func (h userHashOutbound) Tag() string { return h.tag }

func TestUserHashRouting(t *testing.T) {
	pool := []string{"exit-c", "other", "exit-a", "exit-b"}
	tests := []struct {
		name      string
		tags      []string
		user      string
		fallback  string
		override  string
		want      string
		wantError bool
	}{
		{name: "alice", tags: pool, user: "alice", want: "exit-c"},
		{name: "bob", tags: pool, user: "bob", want: "exit-a"},
		{name: "reordered_pool", tags: []string{"exit-b", "exit-a", "other", "exit-c"}, user: "alice", want: "exit-c"},
		{name: "configured_fallback", tags: pool, user: "alice", fallback: "fallback", want: "exit-c"},
		{name: "missing_user_fallback", tags: pool, fallback: "fallback", want: "fallback"},
		{name: "empty_pool_fallback", tags: []string{"other"}, user: "alice", fallback: "fallback", want: "fallback"},
		{name: "missing_user_default", tags: pool, wantError: true},
		{name: "empty_pool_default", tags: []string{"other"}, user: "alice", wantError: true},
		{name: "override", tags: pool, user: "alice", override: "exit-b", want: "exit-b"},
		{name: "override_without_user", tags: pool, fallback: "fallback", override: "exit-b", want: "exit-b"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager, err := outbound_manager.New(context.Background(), &proxyman.OutboundConfig{})
			if err != nil {
				t.Fatal(err)
			}
			for _, tag := range test.tags {
				if err := manager.AddHandler(context.Background(), userHashOutbound{tag: tag}); err != nil {
					t.Fatal(err)
				}
			}
			r := new(Router)
			if err := r.Init(context.Background(), &Config{
				Rule: []*RoutingRule{{
					Networks:  []net.Network{net.Network_TCP, net.Network_UDP},
					TargetTag: &RoutingRule_BalancingTag{BalancingTag: "client-exits"},
				}},
				BalancingRule: []*BalancingRule{{
					Tag:              "client-exits",
					Strategy:         "userHash",
					OutboundSelector: []string{"exit-"},
					FallbackTag:      test.fallback,
				}},
			}, nil, manager, nil); err != nil {
				t.Fatal(err)
			}
			targets, err := r.GetPrincipleTarget("client-exits")
			if err != nil {
				t.Fatal(err)
			}
			if want := manager.Select([]string{"exit-"}); !slices.Equal(targets, want) {
				t.Fatalf("principle targets: got %v, want %v", targets, want)
			}
			if err := r.SetOverrideTarget("client-exits", test.override); err != nil {
				t.Fatal(err)
			}

			for _, network := range []net.Network{net.Network_TCP, net.Network_UDP} {
				for _, source := range []string{"192.0.2.1", "2001:db8::1"} {
					ctx := &routing_session.Context{
						Inbound: &session.Inbound{
							User:   &protocol.MemoryUser{Email: test.user},
							Source: net.Destination{Network: network, Address: net.ParseAddress(source), Port: 1234},
						},
						Outbound: &session.Outbound{
							Target: net.Destination{Network: network, Address: net.DomainAddress("example.com"), Port: 443},
						},
					}
					route, err := r.PickRoute(ctx)
					if test.wantError {
						if err == nil {
							t.Fatal("expected selection error so the dispatcher can use its default outbound")
						}
						continue
					}
					if err != nil {
						t.Fatal(err)
					}
					if got := route.GetOutboundTag(); got != test.want {
						t.Fatalf("network %v, source %s: got %q, want %q", network, source, got, test.want)
					}
				}
			}
		})
	}
}
