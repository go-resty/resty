// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
			SetContentLength(true).
			Post(ts.URL + "/upload")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertEqual(t, true, strings.Contains(resp.String(), "test-img.png"))
	})

	t.Run("request form data and upload", func(t *testing.T) {
		resp, err := c.R().
			SetFormData(map[string]string{
				"welcome1": "welcome value 1",
				"welcome2": "welcome value 2",
				"welcome3": "welcome value 3",
			}).
			SetFile("profile_img", filepath.Join(getTestDataPath(), "test-img.png")).
			SetContentLength(true).
			Post(ts.URL + "/upload")

		assertError(t, err)
		assertEqual(t, http.StatusOK, resp.StatusCode())
		assertEqual(t, true, strings.Contains(resp.String(), "test-img.png"))
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
		SetContentLength(true).
		Patch(ts.URL + "/upload")

	assertError(t, err)
	assertEqual(t, http.StatusOK, resp.StatusCode())
	assertEqual(t, true, strings.Contains(resp.String(), "test-img.png"))
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
	assertNotNil(t, resp)
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
	assertEqual(t, true, strings.Contains(responseStr, "test-img.png"))
	assertEqual(t, true, strings.Contains(responseStr, "text-file.txt"))
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
	assertEqual(t, true, strings.Contains(responseStr, "test-img.png"))
	assertEqual(t, true, strings.Contains(responseStr, "text-file.txt"))
}

func TestMultipartUploadFileNotOnGetOrDelete(t *testing.T) {
	ts := createFormPostServer(t)
	defer ts.Close()
	defer cleanupFiles(".testdata/upload")

	basePath := getTestDataPath()

	_, err := dcnldr().
		SetFile("profile_img", filepath.Join(basePath, "test-img.png")).
		Get(ts.URL + "/upload")

	assertEqual(t, "multipart content is not allowed in HTTP verb [GET]", err.Error())

	_, err = dcnldr().
		SetFile("profile_img", filepath.Join(basePath, "test-img.png")).
		Delete(ts.URL + "/upload")

	assertEqual(t, "multipart content is not allowed in HTTP verb [DELETE]", err.Error())

	var hook1Count int
	var hook2Count int
	_, err = dcnl().
		OnInvalid(func(r *Request, err error) {
			assertEqual(t, "multipart content is not allowed in HTTP verb [HEAD]", err.Error())
			assertNotNil(t, r)
			hook1Count++
		}).
		OnInvalid(func(r *Request, err error) {
			assertEqual(t, "multipart content is not allowed in HTTP verb [HEAD]", err.Error())
			assertNotNil(t, r)
			hook2Count++
		}).
		R().
		SetFile("profile_img", filepath.Join(basePath, "test-img.png")).
		Head(ts.URL + "/upload")

	assertEqual(t, "multipart content is not allowed in HTTP verb [HEAD]", err.Error())
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
	assertEqual(t, true, strings.Contains(responseStr, "upload-file.json"))
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
	assertEqual(t, true, strings.Contains(responseStr, "upload-file-1.json"))
	assertEqual(t, true, strings.Contains(responseStr, "upload-file-2.json"))
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
	ts := createFilePostServer(t)
	defer ts.Close()

	t.Run("upload a 2+mb image file with content-type and custom boundary", func(t *testing.T) {
		c := dcnl()
		resp, err := c.R().
			SetFile("file", filepath.Join(getTestDataPath(), "test-img.png")).
			SetMultipartBoundary("custom-boundary-"+strconv.FormatInt(time.Now().Unix(), 10)).
			SetHeader("Content-Type", "image/png").
			Post(ts.URL + "/upload")
		assertNil(t, err)
		assertNotNil(t, resp)
		assertEqual(t, true, strings.Contains(resp.String(), "File Uploaded successfully, file size: 2579629")) // 2579697
	})

	t.Run("upload a 2+mb image file with content-type and incorrect custom boundary", func(t *testing.T) {
		c := dcnl()
		_, err := c.R().
			SetFile("file", filepath.Join(getTestDataPath(), "test-img.png")).
			SetMultipartBoundary(`"custom-boundary-"`+strconv.FormatInt(time.Now().Unix(), 10)).
			SetHeader("Content-Type", "image/png").
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
		assertEqual(t, true, strings.Contains(resp.String(), "File Uploaded successfully, file size: 2579697"))
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
		assertEqual(t, true, strings.Contains(resp.String(), "File Uploaded successfully, file size: 52429044"))
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
	assertEqual(t, true, strings.Contains(responseStr, "test-image-1.png"))
	assertEqual(t, true, strings.Contains(responseStr, "50mbfile.bin"))
	assertEqual(t, true, strings.Contains(responseStr, "100mbfile.bin"))
}

var errTestErrorReader = errors.New("fake")

type errorReader struct{}

func (errorReader) Read(p []byte) (n int, err error) {
	return 0, errTestErrorReader
}

func TestMultipartReaderErrors(t *testing.T) {
	ts := createFilePostServer(t)
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
		assertEqual(t, nil, resp.Body)
	})

	t.Run("multipart files with errorReader", func(t *testing.T) {
		resp, err := c.R().
			SetFileReader("foo", "foo.txt", &errorReader{}).
			Post("/upload")

		assertNotNil(t, err)
		assertEqual(t, errTestErrorReader, err)
		assertNotNil(t, resp)
		assertEqual(t, nil, resp.Body)
	})

	t.Run("multipart with file not found", func(t *testing.T) {
		resp, err := c.R().
			SetFile("foo", "foo.txt").
			Post("/upload")

		assertNotNil(t, err)
		assertEqual(t, true, errors.Is(err, fs.ErrNotExist))
		assertNotNil(t, resp)
		assertEqual(t, nil, resp.Body)
	})
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
	assertNil(t, err)

	// wrap test writer to return 0 written value
	mpw := multipartProgressWriter{w: &returnValueTestWriter{}}
	n, err := mpw.Write([]byte("test return value"))
	assertNil(t, err)
	assertEqual(t, 0, n)
}
