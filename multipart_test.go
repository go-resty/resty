// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMultipartFormDataAndUpload(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()
	defer cleanupFiles(".testdata/upload")

	c := dcnl()
	c.SetFormData(map[string]string{"zip_code": "00001", "city": "Los Angeles"})

	t.Run("form data and upload", func(t *testing.T) {
		resp, err := c.R().
			SetFile("profile_img", filepath.Join(getTestDataPath(), "test-img.png")).
			Post(ts.URL + "/upload")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertTrue(t, strings.Contains(resp.String(), "test-img.png"))
	})

	t.Run("request form data and upload", func(t *testing.T) {
		resp, err := c.R().
			SetFormData(map[string]string{
				"welcome1": "welcome value 1",
				"welcome2": "welcome value 2",
				"welcome3": "welcome value 3",
			}).
			SetFile("profile_img", filepath.Join(getTestDataPath(), "test-img.png")).
			Post(ts.URL + "/upload")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertTrue(t, strings.Contains(resp.String(), "test-img.png"))
	})
}

func TestMultipartFormDataAndUploadMethodPatch(t *testing.T) {
	ts := createFormPatchServer(t)
	defer ts.Close()
	defer cleanupFiles(".testdata/upload")

	c := dcnl()
	c.SetFormData(map[string]string{"zip_code": "00001", "city": "Los Angeles"})

	resp, err := c.R().
		SetFormData(map[string]string{"zip_code": "00002", "city": "Los Angeles"}).
		SetFile("profile_img", filepath.Join(getTestDataPath(), "test-img.png")).
		Patch(ts.URL + "/upload")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertTrue(t, strings.Contains(resp.String(), "test-img.png"))
}

func TestMultipartUploadError(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()
	defer cleanupFiles(".testdata/upload")

	c := dcnl()
	c.SetFormData(map[string]string{"zip_code": "00001", "city": "Los Angeles"})

	resp, err := c.R().
		SetFile("profile_img", filepath.Join(getTestDataPath(), "test-img-not-exists.png")).
		Post(ts.URL + "/upload")

	assertNotNil(t, err)
	assertNil(t, resp)
	assertEqual(t, true, errors.Is(err, fs.ErrNotExist))
}

func TestMultipartUploadFiles(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()
	defer cleanupFiles(".testdata/upload")

	basePath := getTestDataPath()

	c := dcnld()

	r := c.R().
		SetFormDataFromValues(url.Values{
			"first_name": []string{"Jeevanandam"},
			"last_name":  []string{"M"},
		}).
		SetFiles(map[string]string{
			"profile_img": filepath.Join(basePath, "test-img.png"),
			"notes":       filepath.Join(basePath, "text-file.txt"),
		})
	resp, err := r.Post(ts.URL + "/upload")

	responseStr := resp.String()

	_ = r.Clone(context.Background())

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertTrue(t, strings.Contains(responseStr, "test-img.png"))
	assertTrue(t, strings.Contains(responseStr, "text-file.txt"))
}

func TestMultipartFilesAndFormDataEmptyGH1046(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()
	defer cleanupFiles(".testdata/upload")

	basePath := getTestDataPath()

	c := dcnld()

	resp, err := c.R().
		SetFiles(map[string]string{
			"profile_img": filepath.Join(basePath, "test-img.png"),
			"notes":       filepath.Join(basePath, "text-file.txt"),
		}).
		Post(ts.URL + "/upload")

	responseStr := resp.String()

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertTrue(t, strings.Contains(responseStr, "test-img.png"))
	assertTrue(t, strings.Contains(responseStr, "text-file.txt"))
}

func TestMultipartIoReaderFiles(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()
	defer cleanupFiles(".testdata/upload")

	basePath := getTestDataPath()
	profileImgBytes, _ := os.ReadFile(filepath.Join(basePath, "test-img.png"))
	notesBytes, _ := os.ReadFile(filepath.Join(basePath, "text-file.txt"))

	// Just info values
	// file := File{
	// 	Name:      "test_file_name.jpg",
	// 	ParamName: "test_param",
	// 	Reader:    bytes.NewBuffer([]byte("test bytes")),
	// }
	// t.Logf("File Info: %v", file.String())

	c := dcnld()

	r := c.R().
		SetFormData(map[string]string{"first_name": "Jeevanandam", "last_name": "M"}).
		SetFileReader("profile_img", "test-img.png", bytes.NewReader(profileImgBytes)).
		SetFileReader("notes", "text-file.txt", bytes.NewReader(notesBytes))
	resp, err := r.Post(ts.URL + "/upload")

	responseStr := resp.String()

	_ = r.Clone(context.Background())

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertTrue(t, strings.Contains(responseStr, "test-img.png"))
	assertTrue(t, strings.Contains(responseStr, "text-file.txt"))
}

func TestMultipartUploadFileNotOnGetOrDelete(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()
	defer cleanupFiles(".testdata/upload")

	basePath := getTestDataPath()

	_, err := dcnldr().
		SetFile("profile_img", filepath.Join(basePath, "test-img.png")).
		Get(ts.URL + "/upload")

	assertEqual(t, "resty: multipart is not allowed in HTTP verb: GET", err.Error())

	_, err = dcnldr().
		SetFile("profile_img", filepath.Join(basePath, "test-img.png")).
		Delete(ts.URL + "/upload")

	assertEqual(t, "resty: multipart is not allowed in HTTP verb: DELETE", err.Error())

	var hook1Count int
	var hook2Count int
	_, err = dcnl().
		OnInvalid(func(r *Request, err error) {
			assertEqual(t, "resty: multipart is not allowed in HTTP verb: HEAD", err.Error())
			assertNotNil(t, r)
			hook1Count++
		}).
		OnInvalid(func(r *Request, err error) {
			assertEqual(t, "resty: multipart is not allowed in HTTP verb: HEAD", err.Error())
			assertNotNil(t, r)
			hook2Count++
		}).
		R().
		SetFile("profile_img", filepath.Join(basePath, "test-img.png")).
		Head(ts.URL + "/upload")

	assertEqual(t, "resty: multipart is not allowed in HTTP verb: HEAD", err.Error())
	assertEqual(t, 1, hook1Count)
	assertEqual(t, 1, hook2Count)
}

func TestMultipartFormData(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()
	resp, err := dcnldr().
		SetMultipartFormData(map[string]string{"first_name": "Jeevanandam", "last_name": "M", "zip_code": "00001"}).
		SetBasicAuth("myuser", "mypass").
		Post(ts.URL + "/profile")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "Success", resp.String())
}

func TestMultipartFormDataFields(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()

	fields := []*MultipartField{
		{
			Name:   "field1",
			Values: []string{"field1value1", "field1value2"},
		},
		{
			Name:   "field1",
			Values: []string{"field1value3", "field1value4"},
		},
		{
			Name:   "field3",
			Values: []string{"field3value1", "field3value2"},
		},
		{
			Name:   "field4",
			Values: []string{"field4value1", "field4value2"},
		},
	}

	resp, err := dcnldr().
		SetMultipartFields(fields...).
		SetBasicAuth("myuser", "mypass").
		Post(ts.URL + "/profile")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, "Success", resp.String())
}

func TestMultipartField(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()
	defer cleanupFiles(".testdata/upload")

	jsonBytes := []byte(`{"input": {"name": "Uploaded document", "_filename" : ["file.txt"]}}`)

	c := dcnld()

	r := c.R().
		SetFormDataFromValues(url.Values{
			"first_name": []string{"Jeevanandam"},
			"last_name":  []string{"M"},
		}).
		SetMultipartField("uploadManifest", "upload-file.json", "application/json", bytes.NewReader(jsonBytes))
	resp, err := r.Post(ts.URL + "/upload")

	responseStr := resp.String()

	_ = r.Clone(context.Background())

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertTrue(t, strings.Contains(responseStr, "upload-file.json"))
}

func TestMultipartFields(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()
	defer cleanupFiles(".testdata/upload")

	jsonStr1 := `{"input": {"name": "Uploaded document 1", "_filename" : ["file1.txt"]}}`
	jsonStr2 := `{"input": {"name": "Uploaded document 2", "_filename" : ["file2.txt"]}}`

	fields := []*MultipartField{
		{
			Name:        "uploadManifest1",
			FileName:    "upload-file-1.json",
			ContentType: "application/json",
			Reader:      bytes.NewBufferString(jsonStr1),
		},
		{
			Name:        "uploadManifest2",
			FileName:    "upload-file-2.json",
			ContentType: "application/json",
			Reader:      bytes.NewBufferString(jsonStr2),
		},
		{
			Name:        "uploadManifest3",
			ContentType: "application/json",
			Reader:      bytes.NewBufferString(jsonStr2),
		},
	}

	c := dcnld()

	r := c.R().
		SetFormData(map[string]string{"first_name": "Jeevanandam", "last_name": "M"}).
		SetMultipartFields(fields...)
	resp, err := r.Post(ts.URL + "/upload")

	responseStr := resp.String()

	_ = r.Clone(context.Background())

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertTrue(t, strings.Contains(responseStr, "upload-file-1.json"))
	assertTrue(t, strings.Contains(responseStr, "upload-file-2.json"))
}

func TestMultipartCustomBoundary(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()
	defer cleanupFiles(".testdata/upload")

	t.Run("incorrect custom boundary", func(t *testing.T) {
		_, err := dcnldr().
			SetMultipartFormData(map[string]string{"first_name": "Jeevanandam", "last_name": "M", "zip_code": "00001"}).
			SetMultipartBoundary(`"custom-boundary"`).
			SetBasicAuth("myuser", "mypass").
			Post(ts.URL + "/profile")

		assertEqual(t, "mime: invalid boundary character", err.Error())
	})

	t.Run("correct custom boundary", func(t *testing.T) {
		resp, err := dcnldr().
			SetMultipartFormData(map[string]string{"first_name": "Jeevanandam", "last_name": "M", "zip_code": "00001"}).
			SetMultipartBoundary("custom-boundary-" + strconv.FormatInt(time.Now().Unix(), 10)).
			Post(ts.URL + "/profile")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertEqual(t, "Success", resp.String())
	})
}

func TestMultipartLargeFile(t *testing.T) {
	ts := createFileUploadServer(t)
	defer ts.Close()

	t.Run("upload a 2+mb image file with content-type and custom boundary", func(t *testing.T) {
		c := dcnl()
		resp, err := c.R().
			SetFile("file", filepath.Join(getTestDataPath(), "test-img.png")).
			SetMultipartBoundary("custom-boundary-" + strconv.FormatInt(time.Now().Unix(), 10)).
			SetContentType("image/png").
			Post(ts.URL + "/upload")
		assertNil(t, err)
		assertNotNil(t, resp)
		assertTrue(t, strings.Contains(resp.String(), "File Uploaded successfully, file size: 2579629")) // 2579697
	})

	t.Run("upload a 2+mb image file with content-type and incorrect custom boundary", func(t *testing.T) {
		c := dcnl()
		_, err := c.R().
			SetFile("file", filepath.Join(getTestDataPath(), "test-img.png")).
			SetMultipartBoundary(`"custom-boundary-"` + strconv.FormatInt(time.Now().Unix(), 10)).
			SetContentType("image/png").
			Post(ts.URL + "/upload")
		assertNotNil(t, err)
		assertEqual(t, "mime: invalid boundary character", err.Error())
	})

	t.Run("upload a 2+mb image file without content-type", func(t *testing.T) {
		c := dcnl()
		resp, err := c.R().
			SetFile("file", filepath.Join(getTestDataPath(), "test-img.png")).
			Post(ts.URL + "/upload")
		assertNil(t, err)
		assertNotNil(t, resp)
		assertTrue(t, strings.Contains(resp.String(), "File Uploaded successfully, file size: 2579697"))
	})

	t.Run("upload a 50+mb binary file", func(t *testing.T) {
		fp := createBinFile("50mbfile.bin", 50<<20)
		defer cleanupFiles(fp)
		c := dcnl()
		resp, err := c.R().
			SetFile("file", fp).
			Post(ts.URL + "/upload")
		assertNil(t, err)
		assertNotNil(t, resp)
		assertTrue(t, strings.Contains(resp.String(), "File Uploaded successfully, file size: 52429044"))
	})
}

func TestMultipartFieldProgressCallback(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()
	defer cleanupFiles(".testdata/upload")

	file1, _ := os.Open(filepath.Join(getTestDataPath(), "test-img.png"))
	file1Stat, _ := file1.Stat()

	fileName2 := "50mbfile.bin"
	filePath2 := createBinFile(fileName2, 50<<20)
	defer cleanupFiles(filePath2)
	file2, _ := os.Open(filePath2)
	file2Stat, _ := file2.Stat()

	fileName3 := "100mbfile.bin"
	filePath3 := createBinFile(fileName3, 100<<20)
	defer cleanupFiles(filePath3)
	file3, _ := os.Open(filePath3)
	file3Stat, _ := file3.Stat()

	progressCallback := func(mp MultipartFieldProgress) {
		t.Logf("%s\n", mp)
	}

	fields := []*MultipartField{
		{
			Name:             "test-image",
			FilePath:         filepath.Join(getTestDataPath(), "test-img.png"),
			ProgressCallback: progressCallback,
		},
		{
			Name:             "test-image-1",
			FileName:         "test-image-1.png",
			ContentType:      "image/png",
			Reader:           file1,
			FileSize:         file1Stat.Size(),
			ProgressCallback: progressCallback,
		},
		{
			Name:             "50mbfile",
			FileName:         fileName2,
			Reader:           file2,
			FileSize:         file2Stat.Size(),
			ProgressCallback: progressCallback,
		},
		{
			Name:             "100mbfile",
			FileName:         fileName3,
			Reader:           file3,
			FileSize:         file3Stat.Size(),
			ProgressCallback: progressCallback,
		},
	}

	c := dcnld()

	r := c.R().
		SetFormData(map[string]string{"first_name": "Jeevanandam", "last_name": "M"}).
		SetMultipartFields(fields...)
	resp, err := r.Post(ts.URL + "/upload")

	responseStr := resp.String()

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertTrue(t, strings.Contains(responseStr, "test-image-1.png"))
	assertTrue(t, strings.Contains(responseStr, "test-img.png"))
	assertTrue(t, strings.Contains(responseStr, "50mbfile.bin"))
	assertTrue(t, strings.Contains(responseStr, "100mbfile.bin"))
}

func TestMultipartOrderedFormData(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()
	defer cleanupFiles(".testdata/upload")

	jsonStr1 := `{"input": {"name": "Uploaded document 1", "_filename" : ["file1.txt"]}}`
	jsonStr2 := `{"input": {"name": "Uploaded document 2", "_filename" : ["file2.txt"]}}`

	fields := []*MultipartField{
		{
			Name:   "field1",
			Values: []string{"field1value1", "field1value2"},
		},
		{
			Name:   "field2",
			Values: []string{"field2value1", "field2value2"},
		},
		{
			Name:        "uploadManifest1",
			FileName:    "upload-file-1.json",
			ContentType: "application/json",
			Reader:      bytes.NewBufferString(jsonStr1),
		},
		{
			Name:   "field3",
			Values: []string{"field3value1", "field3value2"},
		},
		{
			Name:        "uploadManifest2",
			FileName:    "upload-file-2.json",
			ContentType: "application/json",
			Reader:      bytes.NewBufferString(jsonStr2),
		},
		{
			Name:   "field4",
			Values: []string{"field4value1", "field4value2"},
		},
		{
			Name:        "uploadManifest3",
			ContentType: "application/json",
			Reader:      bytes.NewBufferString(jsonStr2),
		},
	}

	c := dcnld().SetBaseURL(ts.URL)

	resp, err := c.R().
		SetMultipartOrderedFormData("first_name", []string{"Jeevanandam"}).
		SetMultipartOrderedFormData("last_name", []string{"M"}).
		SetMultipartFields(fields...).
		Post("/upload")

	responseStr := resp.String()

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertTrue(t, strings.Contains(responseStr, "upload-file-1.json"))
	assertTrue(t, strings.Contains(responseStr, "upload-file-2.json"))
}

var errTestErrorReader = errors.New("fake")

type errorReader struct{}

func (errorReader) Read(p []byte) (n int, err error) {
	return 0, errTestErrorReader
}

func TestMultipartReaderErrors(t *testing.T) {
	ts := createFileUploadServer(t)
	defer ts.Close()

	c := dcnl().SetBaseURL(ts.URL)

	t.Run("multipart fields with errorReader", func(t *testing.T) {
		resp, err := c.R().
			SetMultipartFields(&MultipartField{
				Name:        "foo",
				ContentType: "text/plain",
				Reader:      &errorReader{},
			}).
			Post("/upload")

		assertNotNil(t, err)
		assertEqual(t, errTestErrorReader, err)
		assertNotNil(t, resp)

		err = resp.wrapError(errors.New("test error"), true)
		assertNil(t, err)
		assertEqual(t, "test error", resp.CascadeError.Error())
	})

	t.Run("multipart files with errorReader", func(t *testing.T) {
		resp, err := c.R().
			SetFileReader("foo", "foo.txt", &errorReader{}).
			Post("/upload")

		assertNotNil(t, err)
		assertEqual(t, errTestErrorReader, err)
		assertNil(t, resp)
	})

	t.Run("multipart with file not found", func(t *testing.T) {
		resp, err := c.R().
			SetFile("foo", "foo.txt").
			Post("/upload")

		assertNotNil(t, err)
		assertEqual(t, true, errors.Is(err, fs.ErrNotExist))
		assertNil(t, resp)
	})
}

type mpWriterError struct{}

func (mwe *mpWriterError) Write(p []byte) (int, error) {
	return 0, errors.New("multipart write error")
}

func TestMultipartRequest_Errors(t *testing.T) {
	mw := multipart.NewWriter(&mpWriterError{})

	c := dcnl()
	req1 := c.R().SetFormData(map[string]string{
		"name1": "value1",
		"name2": "value2",
	})

	t.Run("writeFormData", func(t *testing.T) {
		err1 := multipartWriteFormData(mw, req1)
		assertNotNil(t, err1)
		assertEqual(t, "multipart write error", err1.Error())
	})
}

func TestMultipartUploadFailAutoErrorParse(t *testing.T) {
	type ErrorResponse struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}

	ts := createTestServer(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(hdrContentTypeKey, "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{ "code": 403, "message": "forbidden error message" }`))
	})
	defer ts.Close()

	c := dcnl()

	t.Run("single request", func(t *testing.T) {
		res, err := c.R().
			SetFile("profile_img", filepath.Join(getTestDataPath(), "test-img.png")).
			SetResultError(&ErrorResponse{}).
			Post(ts.URL)

		assertNil(t, err)
		assertEqual(t, http.StatusForbidden, res.StatusCode())

		er := res.ResultError().(*ErrorResponse)
		assertEqual(t, 403, er.Code)
		assertEqual(t, "forbidden error message", er.Message)
	})

	t.Run("concurrent requests", func(t *testing.T) {
		concurrencyCount := 50
		wg := sync.WaitGroup{}
		for i := 0; i < concurrencyCount; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, _ := c.R().
					SetFile("profile_img", filepath.Join(getTestDataPath(), "test-img.png")).
					SetResultError(&ErrorResponse{}).
					Post(ts.URL)

				er := res.ResultError().(*ErrorResponse)
				assertEqual(t, http.StatusForbidden, res.StatusCode())
				assertEqual(t, 403, er.Code)
				assertEqual(t, "forbidden error message", er.Message)
			}()
		}
		wg.Wait()
	})

}

func TestMultipartConcurrentRequests(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()
	defer cleanupFiles(".testdata/upload")

	c := dcnl()
	c.SetFormData(map[string]string{"zip_code": "00001", "city": "Los Angeles"})

	concurrencyCount := 100
	wg := sync.WaitGroup{}
	for i := 0; i < concurrencyCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := c.R().
				SetFormData(map[string]string{
					"welcome1": "welcome value 1",
					"welcome2": "welcome value 2",
					"welcome3": "welcome value 3",
				}).
				SetFile("profile_img", filepath.Join(getTestDataPath(), "test-img.png")).
				Post(ts.URL + "/upload")

			assertError(t, err)
			assertEqual(t, http.StatusOK, res.StatusCode())
			assertEqual(t, true, strings.Contains(res.String(), "test-img.png"))
		}()
	}
	wg.Wait()
}

type returnValueTestWriter struct {
}

func (z *returnValueTestWriter) Write(p []byte) (n int, err error) {
	return 0, nil
}

func TestMultipartCornerCoverage(t *testing.T) {
	mf := &MultipartField{
		Name:   "foo",
		Reader: bytes.NewBufferString("I have no seek capability"),
	}
	err := mf.resetReader()
	assertEqual(t, ErrReaderNotSeekable, err)

	mf = &MultipartField{
		Name:   "foo",
		Reader: bytes.NewReader([]byte("I have seek capability")),
	}
	err = mf.resetReader()
	assertNil(t, err)

	mf = &MultipartField{
		Name:    "foo",
		Factory: NewBytesReaderFactory([]byte("factory content")),
	}
	err = mf.resetReader()
	assertNil(t, err)
	assertNotNil(t, mf.Reader)

	// wrap test writer to return 0 written value
	mpw := multipartProgressWriter{w: &returnValueTestWriter{}}
	n, err := mpw.Write([]byte("test return value"))
	assertNil(t, err)
	assertEqual(t, 0, n)
}

func TestBytesReaderFactory(t *testing.T) {
	content := []byte("test content for factory")
	factory := NewBytesReaderFactory(content)

	reader1 := factory.NewReader()
	assertNotNil(t, reader1)

	reader2 := factory.NewReader()
	assertNotNil(t, reader2)

	data1, _ := io.ReadAll(reader1)
	data2, _ := io.ReadAll(reader2)

	assertEqual(t, content, data1)
	assertEqual(t, content, data2)
}

func TestBytesReaderFactoryLen(t *testing.T) {
	content := []byte("test content")
	factory := NewBytesReaderFactory(content)

	assertEqual(t, int64(len(content)), factory.Len())
}

func TestStringReaderFactory(t *testing.T) {
	content := "test string content"
	factory := NewStringReaderFactory(content)

	reader1 := factory.NewReader()
	assertNotNil(t, reader1)

	reader2 := factory.NewReader()
	assertNotNil(t, reader2)

	data1, _ := io.ReadAll(reader1)
	data2, _ := io.ReadAll(reader2)

	assertEqual(t, []byte(content), data1)
	assertEqual(t, []byte(content), data2)
}

type trackingReader struct {
	data      []byte
	readCount int
	closed    bool
}

func (r *trackingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.readCount++
	return n, nil
}

func (r *trackingReader) Close() error {
	r.closed = true
	return nil
}

func TestResetReaderWithFactoryClosesOld(t *testing.T) {
	original := &trackingReader{data: []byte("original data")}
	factory := NewBytesReaderFactory([]byte("new data"))

	mf := &MultipartField{
		Name:    "test",
		Reader:  original,
		Factory: factory,
	}

	err := mf.resetReader()
	assertNil(t, err)
	assertTrue(t, original.closed, "original reader should be closed")

	data, _ := io.ReadAll(mf.Reader)
	assertEqual(t, []byte("new data"), data)
}

func TestResetReaderNilReader(t *testing.T) {
	mf := &MultipartField{
		Name: "test",
	}

	err := mf.resetReader()
	assertNil(t, err)
}

func TestNewMultipartFieldFromFactory(t *testing.T) {
	factory := NewBytesReaderFactory([]byte("test"))
	mf := NewMultipartFieldFromFactory("field", "filename.txt", "application/octet-stream", factory)

	assertEqual(t, "field", mf.Name)
	assertEqual(t, "filename.txt", mf.FileName)
	assertEqual(t, "application/octet-stream", mf.ContentType)
	assertEqual(t, factory, mf.Factory)
	assertNil(t, mf.Reader)
}

func TestCustomReaderFactory(t *testing.T) {
	factory := &customFactory{data: "factory data"}

	mf := NewMultipartFieldFromFactory("test", "file.txt", "text/plain", factory)
	err := mf.resetReader()
	assertNil(t, err)
	assertNotNil(t, mf.Reader)

	data, _ := io.ReadAll(mf.Reader)
	assertEqual(t, []byte("factory data"), data)

	err = mf.resetReader()
	assertNil(t, err)
	data2, _ := io.ReadAll(mf.Reader)
	assertEqual(t, []byte("factory data"), data2)
}

type customFactory struct {
	data string
}

func (f *customFactory) NewReader() io.Reader {
	return strings.NewReader(f.data)
}

func TestRetryWithBytesReaderFactory(t *testing.T) {
	attemptCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		body, _ := io.ReadAll(r.Body)
		assertTrue(t, len(body) > 0, "body should not be empty")
		if attemptCount == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	factory := NewBytesReaderFactory([]byte("factory content"))

	client := dcnl()
	resp, err := client.R().
		SetRetryCount(2).
		SetRetryWaitTime(10 * time.Millisecond).
		SetRetryAllowNonIdempotent(true).
		SetMultipartFields(
			NewMultipartFieldFromFactory("file", "test.txt", "application/octet-stream", factory),
		).
		Post(srv.URL)

	assertNil(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, 2, attemptCount)
}

func TestRetryWithFactoryMiddlewareSeesFreshReader(t *testing.T) {
	attemptCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		if attemptCount == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	middlewareCalled := 0
	factory := NewBytesReaderFactory([]byte("test data"))

	client := dcnl()
	client.AddRequestMiddleware(func(c *Client, r *Request) error {
		middlewareCalled++
		return nil
	})

	resp, err := client.R().
		SetRetryCount(1).
		SetRetryWaitTime(10 * time.Millisecond).
		SetRetryAllowNonIdempotent(true).
		SetMultipartFields(
			NewMultipartFieldFromFactory("file", "test.txt", "application/octet-stream", factory),
		).
		Post(srv.URL)

	assertNil(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, 2, middlewareCalled, "middleware should be called for each attempt")
	assertEqual(t, 2, attemptCount)
}

func TestStringReaderFactoryLen(t *testing.T) {
	content := "test content"
	factory := NewStringReaderFactory(content)

	assertEqual(t, int64(len(content)), factory.Len())
}

func TestRetryNonSeekableReaderWithoutFactoryReturnsError(t *testing.T) {
	attemptCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := dcnl()
	_, err := client.R().
		SetRetryCount(2).
		SetRetryWaitTime(10 * time.Millisecond).
		SetRetryAllowNonIdempotent(true).
		SetMultipartFields(&MultipartField{
			Name:        "file",
			FileName:    "test.txt",
			ContentType: "text/plain",
			Reader:      bytes.NewBufferString("non-seekable"),
		}).
		Post(srv.URL)

	assertErrorIs(t, ErrReaderNotSeekable, err)
	assertEqual(t, 1, attemptCount)
}

