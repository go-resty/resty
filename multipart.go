// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
)

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}

// MultipartField describes a multipart/form-data field and its optional file
// upload metadata.
type MultipartField struct {
	// Name is the multipart field name expected by the server.
	Name string

	// FileName is the filename sent to the server.
	FileName string

	// ContentType is the multipart file content type. It is recommended to set
	// this explicitly when known to avoid auto-detection.
	ContentType string

	// Reader is the [io.Reader] source for multipart upload. It is optional if
	// [MultipartField.FilePath] is set.
	Reader io.Reader

	// FilePath is the file path used for multipart upload. It is optional if
	// [MultipartField.Reader] is set.
	FilePath string

	// FileSize is the file size in bytes, reported via
	// [MultipartFieldCallbackFunc].
	FileSize int64

	// ProgressCallback receives live upload progress details for this field.
	//
	// NOTE: When using [MultipartField.Reader] with this callback, set
	// [MultipartField.FileSize] if known so [MultipartFieldProgress] includes a
	// meaningful total size.
	ProgressCallback MultipartFieldCallbackFunc

	// Values is used to provide ordered multipart form-data values for a field.
	//
	// It is primarily intended for ordered form field use cases.
	Values []string

	// tempBuf is used to preserve the byte(s) read from the file to detect the content type.
	// Or any possible read error early.
	tempBuf []byte
}

// Clone returns a copy of m, except [MultipartField.Reader] which is shared.
func (mf *MultipartField) Clone() *MultipartField {
	mf2 := new(MultipartField)
	*mf2 = *mf
	return mf2
}

func (mf *MultipartField) resetReader() error {
	if rs, ok := mf.Reader.(io.ReadSeeker); ok {
		_, err := rs.Seek(0, io.SeekStart)
		return err
	}
	return ErrReaderNotSeekable
}

func (mf *MultipartField) isValues() bool {
	return len(mf.Values) > 0
}

func (mf *MultipartField) close() {
	closeq(mf.Reader)
}

func (mf *MultipartField) createHeader() textproto.MIMEHeader {
	h := make(textproto.MIMEHeader)
	if isStringEmpty(mf.FileName) {
		h.Set(hdrContentDisposition,
			fmt.Sprintf(`form-data; name="%s"`, escapeQuotes(mf.Name)))
	} else {
		h.Set(hdrContentDisposition,
			fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
				escapeQuotes(mf.Name), escapeQuotes(mf.FileName)))
	}
	if !isStringEmpty(mf.ContentType) {
		h.Set(hdrContentTypeKey, mf.ContentType)
	}
	return h
}

func (mf *MultipartField) openFile() error {
	if isStringEmpty(mf.FilePath) || mf.Reader != nil {
		return nil
	}

	file, err := os.Open(mf.FilePath)
	if err != nil {
		return err
	}

	if isStringEmpty(mf.FileName) {
		mf.FileName = filepath.Base(mf.FilePath)
	}

	// if file open is success, stat will succeed
	fileStat, _ := file.Stat()

	mf.Reader = file
	mf.FileSize = fileStat.Size()

	return nil
}

func (mf *MultipartField) detectContentType() error {
	if !isStringEmpty(mf.ContentType) || mf.Reader == nil {
		return nil
	}

	p := make([]byte, 512)
	size, err := mf.Reader.Read(p)
	if err != nil && err != io.EOF {
		return err
	}
	mf.tempBuf = p[:size]
	mf.ContentType = http.DetectContentType(mf.tempBuf)
	return nil
}

func (mf *MultipartField) wrapProgressCallbackIfPresent(pw io.Writer) io.Writer {
	if mf.ProgressCallback == nil {
		return pw
	}

	return &multipartProgressWriter{
		w: pw,
		f: func(pb int64) {
			mf.ProgressCallback(MultipartFieldProgress{
				Name:     mf.Name,
				FileName: mf.FileName,
				FileSize: mf.FileSize,
				Written:  pb,
			})
		},
	}
}

// MultipartFieldCallbackFunc receives live multipart upload progress updates.
type MultipartFieldCallbackFunc func(MultipartFieldProgress)

// MultipartFieldProgress contains upload progress details for a multipart field.
type MultipartFieldProgress struct {
	Name     string
	FileName string
	FileSize int64
	Written  int64
}

// String returns the string representation of [MultipartFieldProgress].
func (mfp MultipartFieldProgress) String() string {
	return fmt.Sprintf("FieldName: %s, FileName: %s, FileSize: %v, Written: %v",
		mfp.Name, mfp.FileName, mfp.FileSize, mfp.Written)
}

type multipartProgressWriter struct {
	w  io.Writer
	pb int64
	f  func(int64)
}

func (mpw *multipartProgressWriter) Write(p []byte) (n int, err error) {
	n, err = mpw.w.Write(p)
	if n <= 0 {
		return
	}
	mpw.pb += int64(n)
	mpw.f(mpw.pb)
	return
}
