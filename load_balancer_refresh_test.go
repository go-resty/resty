// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"context"
	"testing"
)

func TestRoundRobinRefreshAfterSelection(t *testing.T) {
	for _, tt := range []struct {
		name     string
		advance  int
		urls     []string
		expected []string
	}{
		{
			name: "shrink to one host", advance: 2,
			urls:     []string{"https://new1.example"},
			expected: []string{"https://new1.example", "https://new1.example"},
		},
		{
			name: "shrink to multiple hosts", advance: 2,
			urls:     []string{"https://new1.example", "https://new2.example"},
			expected: []string{"https://new1.example", "https://new2.example", "https://new1.example"},
		},
		{
			name: "keep valid position when shrinking", advance: 1,
			urls:     []string{"https://new1.example", "https://new2.example"},
			expected: []string{"https://new2.example", "https://new1.example", "https://new2.example"},
		},
		{
			name: "keep position at same size", advance: 2,
			urls:     []string{"https://new1.example", "https://new2.example", "https://new3.example"},
			expected: []string{"https://new3.example", "https://new1.example", "https://new2.example"},
		},
		{
			name: "keep position when growing", advance: 2,
			urls:     []string{"https://new1.example", "https://new2.example", "https://new3.example", "https://new4.example"},
			expected: []string{"https://new3.example", "https://new4.example", "https://new1.example"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rr, err := NewRoundRobin("https://old1.example", "https://old2.example", "https://old3.example")
			assertNil(t, err)
			for range tt.advance {
				_, err = rr.NextWithContext(context.Background())
				assertNil(t, err)
			}
			assertNil(t, rr.Refresh(tt.urls...))
			for _, expected := range tt.expected {
				actual, err := rr.NextWithContext(context.Background())
				assertNil(t, err)
				assertEqual(t, expected, actual)
			}
		})
	}
}

func TestRoundRobinRefreshEmptyThenRepopulate(t *testing.T) {
	rr, err := NewRoundRobin("https://old1.example", "https://old2.example", "https://old3.example")
	assertNil(t, err)
	for range 2 {
		_, err = rr.NextWithContext(context.Background())
		assertNil(t, err)
	}
	assertNil(t, rr.Refresh())
	_, err = rr.NextWithContext(context.Background())
	assertErrorIs(t, ErrNoBaseURLs, err)
	assertNil(t, rr.Refresh("https://new.example"))
	actual, err := rr.NextWithContext(context.Background())
	assertNil(t, err)
	assertEqual(t, "https://new.example", actual)
}

func TestRoundRobinRefreshInvalidPreservesSelection(t *testing.T) {
	rr, err := NewRoundRobin("https://old1.example", "https://old2.example", "https://old3.example")
	assertNil(t, err)
	_, err = rr.NextWithContext(context.Background())
	assertNil(t, err)
	err = rr.Refresh("https://new.example", "://invalid")
	assertNotNil(t, err)
	for _, expected := range []string{"https://old2.example", "https://old3.example", "https://old1.example"} {
		actual, err := rr.NextWithContext(context.Background())
		assertNil(t, err)
		assertEqual(t, expected, actual)
	}
}
