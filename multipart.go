// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"fmt"
	"io"
	"net/textproto"
	"os"
	"strings"
)

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}

// MultipartField struct represents the multipart field to compose
// all [io.Reader] capable input for multipart form request
type MultipartField struct {
	io.Reader
	Name        string
	FileName    string
	ContentType string

	filePath string
}

// Clone method returns the deep copy of m except [io.Reader].
func (m *MultipartField) Clone() *MultipartField {
	mm := new(MultipartField)
	*mm = *m
	return mm
}

func (m *MultipartField) resetReader() error {
	if rs, ok := m.Reader.(io.ReadSeeker); ok {
		_, err := rs.Seek(0, io.SeekStart)
		return err
	}
	return nil
}

func (m *MultipartField) close() {
	closeq(m.Reader)
}

func (m *MultipartField) createHeader() textproto.MIMEHeader {
	h := make(textproto.MIMEHeader)
	if isStringEmpty(m.FileName) {
		h.Set(hdrContentDisposition,
			fmt.Sprintf(`form-data; name="%s"`, escapeQuotes(m.Name)))
	} else {
		h.Set(hdrContentDisposition,
			fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
				escapeQuotes(m.Name), escapeQuotes(m.FileName)))
	}
	if !isStringEmpty(m.ContentType) {
		h.Set(hdrContentTypeKey, m.ContentType)
	}
	return h
}

func (m *MultipartField) openFileIfRequired() (err error) {
	if m.Reader == nil && !isStringEmpty(m.filePath) {
		m.Reader, err = os.Open(m.filePath)
	}
	return
}
