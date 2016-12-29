// +build !go1.8

package resty

import "strings"

func errIsContextCanceled(err error) bool {
	return strings.Contains(err.Error(), "request canceled")
}
