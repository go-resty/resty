// Copyright (c) 2015-2017 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if !IsStringEmpty(s) {
			return s
		}
	}
	return ""
}
