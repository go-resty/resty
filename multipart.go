// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
)

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

// ErrReaderNotSeekable is returned when a multipart field reader
// does not implement [io.ReadSeeker] and no [ReaderFactory] is provided.
// This prevents silent data corruption during retry attempts where a
// consumed [io.Reader] would produce an empty or truncated body.
var ErrReaderNotSeekable = errors.New(
	"resty: multipart reader is not seekable and no factory provided; " +
		"use resty.NewMultipartFieldFromFactory for retry support with non-seekable readers",
)

// ReaderFactory is an interface for creating fresh [io.Reader] instances
// per retry attempt. This is useful for non-seekable readers (cipher streams,
// network pipes, etc.) that cannot be reset via [io.ReadSeeker].
//
// See [NewMultipartFieldFromFactory], [BytesReaderFactory], [StringReaderFactory].
type ReaderFactory interface {
	NewReader() io.Reader
}

// LenReaderFactory is an optional interface that ReaderFactory implementations
// can implement to provide content length.
type LenReaderFactory interface {
	Len() int64
}

func escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}

// MultipartField struct represents the multipart field to compose
// all [io.Reader] capable input for multipart form request
type MultipartField struct {
	// Name of the multipart field name that the server expects it
	Name string

	// FileName is used to set the file name we have to send to the server
	FileName string

	// ContentType is a multipart file content-type value. It is highly
	// recommended setting it if you know the content-type so that Resty
	// don't have to do additional computing to auto-detect (Optional)
	ContentType string

	// Reader is an input of [io.Reader] for multipart upload. It
	// is optional if you set the FilePath value
	Reader io.Reader

	// FilePath is a file path for multipart upload. It
	// is optional if you set the Reader value
	FilePath string

	// FileSize in bytes is used just for the information purpose of
	// sharing via [MultipartFieldCallbackFunc] (Optional)
	FileSize int64

	// ProgressCallback function is used to provide live progress details
	// during a multipart upload (Optional)
	//
	// NOTE: It is recommended to set the FileSize value when using `MultipartField.Reader`
	// with `ProgressCallback` feature so that Resty sends the FileSize
	// value via [MultipartFieldProgress]
	ProgressCallback MultipartFieldCallbackFunc

	// Values field is used to provide form field value. (Optional, unless it's a form-data field)
	//
	// It is primarily added for ordered multipart form-data field use cases
	Values []string

	// Factory is used to create a fresh io.Reader for each retry attempt.
	// This is required for non-seekable readers (e.g., cipher streams, network pipes).
	// When Factory is set, Reader is ignored and Factory.NewReader() is called
	// for each retry attempt.
	Factory ReaderFactory

	// tempBuf is used to preserve the byte(s) read from the file to detect the content type.
	// Or any possible read error early.
	tempBuf []byte
}

// Clone method returns the deep copy of m except [io.Reader].
func (mf *MultipartField) Clone() *MultipartField {
	mf2 := new(MultipartField)
	*mf2 = *mf
	return mf2
}

// NewMultipartFieldFromFactory creates a [MultipartField] with a [ReaderFactory]
// for retry support with non-seekable readers.
//
// When Factory is set, [ReaderFactory.NewReader] is called to obtain a fresh
// [io.Reader] for each attempt (initial + retries).
func NewMultipartFieldFromFactory(name, fileName, contentType string, factory ReaderFactory) *MultipartField {
	return &MultipartField{
		Name:        name,
		FileName:    fileName,
		ContentType: contentType,
		Factory:     factory,
	}
}

func (mf *MultipartField) resetReader() error {
	if mf.Factory != nil {
		mf.close()
		mf.Reader = mf.Factory.NewReader()
		return nil
	}

	if mf.Reader == nil {
		return nil
	}

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

// MultipartFieldCallbackFunc function used to transmit live multipart upload
// progress in bytes count
type MultipartFieldCallbackFunc func(MultipartFieldProgress)

// MultipartFieldProgress struct used to provide multipart field upload progress
// details via callback function
type MultipartFieldProgress struct {
	Name     string
	FileName string
	FileSize int64
	Written  int64
}

// String method creates the string representation of [MultipartFieldProgress]
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

type BytesReaderFactory struct {
	data []byte
}

// NewBytesReaderFactory creates a BytesReaderFactory from a byte slice.
func NewBytesReaderFactory(data []byte) *BytesReaderFactory {
	return &BytesReaderFactory{data: data}
}

func (f *BytesReaderFactory) NewReader() io.Reader {
	return bytes.NewReader(f.data)
}

func (f *BytesReaderFactory) Len() int64 {
	return int64(len(f.data))
}

type StringReaderFactory struct {
	data string
}

// NewStringReaderFactory creates a StringReaderFactory from a string.
func NewStringReaderFactory(data string) *StringReaderFactory {
	return &StringReaderFactory{data: data}
}

func (f *StringReaderFactory) NewReader() io.Reader {
	return strings.NewReader(f.data)
}

func (f *StringReaderFactory) Len() int64 {
	return int64(len(f.data))
}
