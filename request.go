// Copyright (c) 2015-present Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.
// SPDX-License-Identifier: MIT

package resty

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"
)

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// Request struct and methods
//_______________________________________________________________________

// Request struct is used to compose and fire individual requests from
// Resty client. The [Request] provides an option to override client-level
// settings and also an option for the request composition.
type Request struct {
	URL                        string
	Method                     string
	AuthToken                  string
	AuthScheme                 string
	QueryParams                url.Values
	FormData                   url.Values
	PathParams                 map[string]string
	Header                     http.Header
	Time                       time.Time
	Body                       any
	Result                     any
	Error                      any
	RawRequest                 *http.Request
	Cookies                    []*http.Cookie
	Debug                      bool
	CloseConnection            bool
	DoNotParseResponse         bool
	OutputFileName             string
	ExpectResponseContentType  string
	ForceResponseContentType   string
	DebugBodyLimit             int
	ResponseBodyLimit          int64
	ResponseBodyUnlimitedReads bool
	IsTrace                    bool
	AllowMethodGetPayload      bool
	AllowMethodDeletePayload   bool
	IsDone                     bool
	IsSaveResponse             bool
	Timeout                    time.Duration
	HeaderAuthorizationKey     string
	RetryCount                 int
	RetryWaitTime              time.Duration
	RetryMaxWaitTime           time.Duration
	RetryStrategy              RetryStrategyFunc
	IsRetryDefaultConditions   bool
	AllowNonIdempotentRetry    bool

	// RetryTraceID provides GUID for retry count > 0
	RetryTraceID string

	// Attempt provides insights into no. of attempts
	// Resty made.
	//
	//	first attempt + retry count = total attempts
	Attempt int

	credentials         *credentials
	isMultiPart         bool
	isFormData          bool
	setContentLength    bool
	jsonEscapeHTML      bool
	ctx                 context.Context
	ctxCancelFunc       context.CancelFunc
	values              map[string]any
	client              *Client
	bodyBuf             *bytes.Buffer
	trace               *clientTrace
	log                 Logger
	baseURL             string
	multipartBoundary   string
	multipartFields     []*MultipartField
	retryConditions     []RetryConditionFunc
	retryHooks          []RetryHookFunc
	resultCurlCmd       string
	generateCurlCmd     bool
	debugLogCurlCmd     bool
	unescapeQueryParams bool
	multipartErrChan    chan error
}

// SetMethod method used to set the HTTP verb for the request
func (r *Request) SetMethod(m string) *Request {
	r.Method = m
	return r
}

// SetURL method used to set the request URL for the request
func (r *Request) SetURL(url string) *Request {
	r.URL = url
	return r
}

// Context method returns the request's [context.Context]. To change the context, use
// [Request.Clone] or [Request.WithContext].
//
// The returned context is always non-nil; it defaults to the
// background context.
func (r *Request) Context() context.Context {
	if r.ctx == nil {
		return context.Background()
	}
	return r.ctx
}

// SetContext method sets the [context.Context] for current [Request].
// It overwrites the current context in the Request instance; it does not
// affect the [Request].RawRequest that was already created.
//
// If you want this method to take effect, use this method before invoking
// [Request.Send] or [Request].HTTPVerb methods.
//
// See [Request.WithContext], [Request.Clone]
func (r *Request) SetContext(ctx context.Context) *Request {
	r.ctx = ctx
	return r
}

// WithContext method returns a shallow copy of r with its context changed
// to ctx. The provided ctx must be non-nil. It does not
// affect the [Request].RawRequest that was already created.
//
// If you want this method to take effect, use this method before invoking
// [Request.Send] or [Request].HTTPVerb methods.
//
// See [Request.SetContext], [Request.Clone]
func (r *Request) WithContext(ctx context.Context) *Request {
	if ctx == nil {
		panic("resty: Request.WithContext nil context")
	}
	rr := new(Request)
	*rr = *r
	rr.ctx = ctx
	return rr
}

// SetContentType method is a convenient way to set the header Content-Type in the request
//
//	client.R().SetContentType("application/json")
func (r *Request) SetContentType(ct string) *Request {
	r.SetHeader(hdrContentTypeKey, ct)
	return r
}

// SetHeader method sets a single header field and its value in the current request.
//
// For Example: To set `Content-Type` and `Accept` as `application/json`.
//
//	client.R().
//		SetHeader("Content-Type", "application/json").
//		SetHeader("Accept", "application/json")
//
// It overrides the header value set at the client instance level.
func (r *Request) SetHeader(header, value string) *Request {
	r.Header.Set(header, value)
	return r
}

// SetHeaders method sets multiple header fields and their values at one go in the current request.
//
// For Example: To set `Content-Type` and `Accept` as `application/json`
//
//	client.R().
//		SetHeaders(map[string]string{
//			"Content-Type": "application/json",
//			"Accept": "application/json",
//		})
//
// It overrides the header value set at the client instance level.
func (r *Request) SetHeaders(headers map[string]string) *Request {
	for h, v := range headers {
		r.SetHeader(h, v)
	}
	return r
}

// SetHeaderMultiValues sets multiple header fields and their values as a list of strings in the current request.
//
// For Example: To set `Accept` as `text/html, application/xhtml+xml, application/xml;q=0.9, image/webp, */*;q=0.8`
//
//	client.R().
//		SetHeaderMultiValues(map[string][]string{
//			"Accept": []string{"text/html", "application/xhtml+xml", "application/xml;q=0.9", "image/webp", "*/*;q=0.8"},
//		})
//
// It overrides the header value set at the client instance level.
func (r *Request) SetHeaderMultiValues(headers map[string][]string) *Request {
	for key, values := range headers {
		r.SetHeader(key, strings.Join(values, ", "))
	}
	return r
}

// SetHeaderVerbatim method is used to set the HTTP header key and value verbatim in the current request.
// It is typically helpful for legacy applications or servers that require HTTP headers in a certain way
//
// For Example: To set header key as `all_lowercase`, `UPPERCASE`, and `x-cloud-trace-id`
//
//	client.R().
//		SetHeaderVerbatim("all_lowercase", "available").
//		SetHeaderVerbatim("UPPERCASE", "available").
//		SetHeaderVerbatim("x-cloud-trace-id", "798e94019e5fc4d57fbb8901eb4c6cae")
//
// It overrides the header value set at the client instance level.
func (r *Request) SetHeaderVerbatim(header, value string) *Request {
	r.Header[header] = []string{value}
	return r
}

// SetQueryParam method sets a single parameter and its value in the current request.
// It will be formed as a query string for the request.
//
// For Example: `search=kitchen%20papers&size=large` in the URL after the `?` mark.
//
//	client.R().
//		SetQueryParam("search", "kitchen papers").
//		SetQueryParam("size", "large")
//
// It overrides the query parameter value set at the client instance level.
func (r *Request) SetQueryParam(param, value string) *Request {
	r.QueryParams.Set(param, value)
	return r
}

// SetQueryParams method sets multiple parameters and their values at one go in the current request.
// It will be formed as a query string for the request.
//
// For Example: `search=kitchen%20papers&size=large` in the URL after the `?` mark.
//
//	client.R().
//		SetQueryParams(map[string]string{
//			"search": "kitchen papers",
//			"size": "large",
//		})
//
// It overrides the query parameter value set at the client instance level.
func (r *Request) SetQueryParams(params map[string]string) *Request {
	for p, v := range params {
		r.SetQueryParam(p, v)
	}
	return r
}

// SetQueryParamsFromValues method appends multiple parameters with multi-value
// ([url.Values]) at one go in the current request. It will be formed as
// query string for the request.
//
// For Example: `status=pending&status=approved&status=open` in the URL after the `?` mark.
//
//	client.R().
//		SetQueryParamsFromValues(url.Values{
//			"status": []string{"pending", "approved", "open"},
//		})
//
// It overrides the query parameter value set at the client instance level.
func (r *Request) SetQueryParamsFromValues(params url.Values) *Request {
	for p, v := range params {
		for _, pv := range v {
			r.QueryParams.Add(p, pv)
		}
	}
	return r
}

// SetQueryString method provides the ability to use string as an input to set URL query string for the request.
//
//	client.R().
//		SetQueryString("productId=232&template=fresh-sample&cat=resty&source=google&kw=buy a lot more")
//
// It overrides the query parameter value set at the client instance level.
func (r *Request) SetQueryString(query string) *Request {
	params, err := url.ParseQuery(strings.TrimSpace(query))
	if err == nil {
		for p, v := range params {
			for _, pv := range v {
				r.QueryParams.Add(p, pv)
			}
		}
	} else {
		r.log.Errorf("%v", err)
	}
	return r
}

// SetFormData method sets form parameters and their values in the current request.
// The request content type would be set as `application/x-www-form-urlencoded`.
//
//	client.R().
//		SetFormData(map[string]string{
//			"access_token": "BC594900-518B-4F7E-AC75-BD37F019E08F",
//			"user_id": "3455454545",
//		})
//
// It overrides the form data value set at the client instance level.
//
// See [Request.SetFormDataFromValues] for the same field name with multiple values.
func (r *Request) SetFormData(data map[string]string) *Request {
	for k, v := range data {
		r.FormData.Set(k, v)
	}
	return r
}

// SetFormDataFromValues method appends multiple form parameters with multi-value
// ([url.Values]) at one go in the current request.
//
//	client.R().
//		SetFormDataFromValues(url.Values{
//			"search_criteria": []string{"book", "glass", "pencil"},
//		})
//
// It overrides the form data value set at the client instance level.
func (r *Request) SetFormDataFromValues(data url.Values) *Request {
	for k, v := range data {
		for _, kv := range v {
			r.FormData.Add(k, kv)
		}
	}
	return r
}

// SetBody method sets the request body for the request. It supports various practical needs as easy.
// It's quite handy and powerful. Supported request body data types are `string`,
// `[]byte`, `struct`, `map`, `slice` and [io.Reader].
//
// Body value can be pointer or non-pointer. Automatic marshalling for JSON and XML content type, if it is `struct`, `map`, or `slice`.
//
// NOTE: [io.Reader] is processed in bufferless mode while sending a request.
//
// For Example:
//
// `struct` gets marshaled based on the request header `Content-Type`.
//
//	client.R().
//		SetBody(User{
//			Username: "jeeva@myjeeva.com",
//			Password: "welcome2resty",
//		})
//
// 'map` gets marshaled based on the request header `Content-Type`.
//
//	client.R().
//		SetBody(map[string]any{
//			"username": "jeeva@myjeeva.com",
//			"password": "welcome2resty",
//			"address": &Address{
//				Address1: "1111 This is my street",
//				Address2: "Apt 201",
//				City: "My City",
//				State: "My State",
//				ZipCode: 00000,
//			},
//		})
//
// `string` as a body input. Suitable for any need as a string input.
//
//	client.R().
//		SetBody(`{
//			"username": "jeeva@getrightcare.com",
//			"password": "admin"
//		}`)
//
// `[]byte` as a body input. Suitable for raw requests such as file upload, serialize & deserialize, etc.
//
//	client.R().
//		SetBody([]byte("This is my raw request, sent as-is"))
//
// and so on.
func (r *Request) SetBody(body any) *Request {
	r.Body = body
	return r
}

// SetResult method is to register the response `Result` object for automatic
// unmarshalling of the HTTP response if the response status code is
// between 200 and 299, and the content type is JSON or XML.
//
// Note: [Request.SetResult] input can be a pointer or non-pointer.
//
// The pointer with handle
//
//	authToken := &AuthToken{}
//	client.R().SetResult(authToken)
//
//	// Can be accessed via -
//	fmt.Println(authToken) OR fmt.Println(response.Result().(*AuthToken))
//
// OR -
//
// The pointer without handle or non-pointer
//
//	client.R().SetResult(&AuthToken{})
//	// OR
//	client.R().SetResult(AuthToken{})
//
//	// Can be accessed via -
//	fmt.Println(response.Result().(*AuthToken))
func (r *Request) SetResult(v any) *Request {
	r.Result = getPointer(v)
	return r
}

// SetError method is to register the request `Error` object for automatic unmarshalling for the request,
// if the response status code is greater than 399 and the content type is either JSON or XML.
//
// NOTE: [Request.SetError] input can be a pointer or non-pointer.
//
//	client.R().SetError(&AuthError{})
//	// OR
//	client.R().SetError(AuthError{})
//
// Accessing an error value from response instance.
//
//	response.Error().(*AuthError)
//
// If this request Error object is nil, Resty will use the client-level error object Type if it is set.
func (r *Request) SetError(err any) *Request {
	r.Error = getPointer(err)
	return r
}

// SetFile method sets a single file field name and its path for multipart upload.
//
// Resty provides an optional multipart live upload progress callback;
// see method [Request.SetMultipartFields]
//
//	client.R().
//		SetFile("my_file", "/Users/jeeva/Gas Bill - Sep.pdf")
func (r *Request) SetFile(fieldName, filePath string) *Request {
	r.isMultiPart = true
	r.multipartFields = append(r.multipartFields, &MultipartField{
		Name:     fieldName,
		FileName: filepath.Base(filePath),
		FilePath: filePath,
	})
	return r
}

// SetFiles method sets multiple file field names and their paths for multipart uploads.
//
// Resty provides an optional multipart live upload progress callback;
// see method [Request.SetMultipartFields]
//
//	client.R().
//		SetFiles(map[string]string{
//			"my_file1": "/Users/jeeva/Gas Bill - Sep.pdf",
//			"my_file2": "/Users/jeeva/Electricity Bill - Sep.pdf",
//			"my_file3": "/Users/jeeva/Water Bill - Sep.pdf",
//		})
func (r *Request) SetFiles(files map[string]string) *Request {
	r.isMultiPart = true
	for f, fp := range files {
		r.multipartFields = append(r.multipartFields, &MultipartField{
			Name:     f,
			FileName: filepath.Base(fp),
			FilePath: fp,
		})
	}
	return r
}

// SetFileReader method is to set a file using [io.Reader] for multipart upload.
//
// Resty provides an optional multipart live upload progress callback;
// see method [Request.SetMultipartFields]
//
//	client.R().
//		SetFileReader("profile_img", "my-profile-img.png", bytes.NewReader(profileImgBytes)).
//		SetFileReader("notes", "user-notes.txt", bytes.NewReader(notesBytes))
func (r *Request) SetFileReader(fieldName, fileName string, reader io.Reader) *Request {
	r.SetMultipartField(fieldName, fileName, "", reader)
	return r
}

// SetMultipartFormData method allows simple form data to be attached to the request
// as `multipart:form-data`
func (r *Request) SetMultipartFormData(data map[string]string) *Request {
	r.isMultiPart = true
	for k, v := range data {
		r.FormData.Set(k, v)
	}
	return r
}

// SetMultipartOrderedFormData method allows add ordered form data to be attached to the request
// as `multipart:form-data`
func (r *Request) SetMultipartOrderedFormData(name string, values []string) *Request {
	r.isMultiPart = true
	r.multipartFields = append(r.multipartFields, &MultipartField{
		Name:   name,
		Values: values,
	})
	return r
}

// SetMultipartField method sets custom data with Content-Type using [io.Reader] for multipart upload.
//
// Resty provides an optional multipart live upload progress callback;
// see method [Request.SetMultipartFields]
func (r *Request) SetMultipartField(fieldName, fileName, contentType string, reader io.Reader) *Request {
	r.isMultiPart = true
	r.multipartFields = append(r.multipartFields, &MultipartField{
		Name:        fieldName,
		FileName:    fileName,
		ContentType: contentType,
		Reader:      reader,
	})
	return r
}

// SetMultipartFields method sets multiple data fields using [io.Reader] for multipart upload.
//
// Resty provides an optional multipart live upload progress count in bytes; see
// [MultipartField].ProgressCallback and [MultipartFieldProgress]
//
// For Example:
//
//	client.R().SetMultipartFields(
//		&resty.MultipartField{
//			Name:        "uploadManifest1",
//			FileName:    "upload-file-1.json",
//			ContentType: "application/json",
//			Reader:      strings.NewReader(`{"input": {"name": "Uploaded document 1", "_filename" : ["file1.txt"]}}`),
//		},
//		&resty.MultipartField{
//			Name:        "uploadManifest2",
//			FileName:    "upload-file-2.json",
//			ContentType: "application/json",
//			FilePath:    "/path/to/upload-file-2.json",
//		},
//		&resty.MultipartField{
//			Name:             "image-file1",
//			FileName:         "image-file1.png",
//			ContentType:      "image/png",
//			Reader:           bytes.NewReader(fileBytes),
//			ProgressCallback: func(mp MultipartFieldProgress) {
//				// use the progress details
//			},
//		},
//		&resty.MultipartField{
//			Name:             "image-file2",
//			FileName:         "image-file2.png",
//			ContentType:      "image/png",
//			Reader:           imageFile2, // instance of *os.File
//			ProgressCallback: func(mp MultipartFieldProgress) {
//				// use the progress details
//			},
//		})
//
// If you have a `slice` of fields already, then call-
//
//	client.R().SetMultipartFields(fields...)
func (r *Request) SetMultipartFields(fields ...*MultipartField) *Request {
	r.isMultiPart = true
	r.multipartFields = append(r.multipartFields, fields...)
	return r
}

// SetMultipartBoundary method sets the custom multipart boundary for the multipart request.
// Typically, the `mime/multipart` package generates a random multipart boundary if not provided.
func (r *Request) SetMultipartBoundary(boundary string) *Request {
	r.multipartBoundary = boundary
	return r
}

// SetContentLength method sets the current request's HTTP header `Content-Length` value.
// By default, Resty won't set `Content-Length`.
//
// See [Client.SetContentLength]
//
//	client.R().SetContentLength(true)
//
// It overrides the value set at the client instance level.
func (r *Request) SetContentLength(l bool) *Request {
	r.setContentLength = l
	return r
}

// SetBasicAuth method sets the basic authentication header in the current HTTP request.
//
// For Example:
//
//	Authorization: Basic <base64-encoded-value>
//
// To set the header for username "go-resty" and password "welcome"
//
//	client.R().SetBasicAuth("go-resty", "welcome")
//
// It overrides the credentials set by method [Client.SetBasicAuth].
func (r *Request) SetBasicAuth(username, password string) *Request {
	r.credentials = &credentials{Username: username, Password: password}
	return r
}

// SetAuthToken method sets the auth token header(Default Scheme: Bearer) in the current HTTP request. Header example:
//
//	Authorization: Bearer <auth-token-value-comes-here>
//
// For Example: To set auth token BC594900518B4F7EAC75BD37F019E08FBC594900518B4F7EAC75BD37F019E08F
//
//	client.R().SetAuthToken("BC594900518B4F7EAC75BD37F019E08FBC594900518B4F7EAC75BD37F019E08F")
//
// It overrides the Auth token set by method [Client.SetAuthToken].
func (r *Request) SetAuthToken(authToken string) *Request {
	r.AuthToken = authToken
	return r
}

// SetAuthScheme method sets the auth token scheme type in the HTTP request.
//
// Example Header value structure:
//
//	Authorization: <auth-scheme-value-set-here> <auth-token-value>
//
// For Example: To set the scheme to use OAuth
//
//	client.R().SetAuthScheme("OAuth")
//
//	// The outcome will be -
//	Authorization: OAuth <auth-token-value>
//
// Information about Auth schemes can be found in [RFC 7235], IANA [HTTP Auth schemes]
//
// It overrides the `Authorization` scheme set by method [Client.SetAuthScheme].
//
// [RFC 7235]: https://tools.ietf.org/html/rfc7235
// [HTTP Auth schemes]: https://www.iana.org/assignments/http-authschemes/http-authschemes.xhtml#authschemes
func (r *Request) SetAuthScheme(scheme string) *Request {
	r.AuthScheme = scheme
	return r
}

// SetHeaderAuthorizationKey method sets the given HTTP header name for Authorization in the request.
//
// It overrides the `Authorization` header name set by method [Client.SetHeaderAuthorizationKey].
//
//	client.R().SetHeaderAuthorizationKey("X-Custom-Authorization")
func (r *Request) SetHeaderAuthorizationKey(k string) *Request {
	r.HeaderAuthorizationKey = k
	return r
}

// SetOutputFileName method sets the output file for the current HTTP request. The current
// HTTP response will be saved in the given file. It is similar to the `curl -o` flag.
//
// Absolute path or relative path can be used.
//
// If it is a relative path, then the output file goes under the output directory, as mentioned
// in the [Client.SetOutputDirectory].
//
//	client.R().
//		SetOutputFileName("/Users/jeeva/Downloads/ReplyWithHeader-v5.1-beta.zip").
//		Get("http://bit.ly/1LouEKr")
//
// NOTE: In this scenario
//   - [Response.BodyBytes] might be nil.
//   - [Response].Body might have been already read.
func (r *Request) SetOutputFileName(file string) *Request {
	r.OutputFileName = file
	r.SetSaveResponse(true)
	return r
}

// SetSaveResponse method used to enable the save response option for the current requests
//
//	client.R().SetSaveResponse(true)
//
// Resty determines the save filename in the following order -
//   - [Request.SetOutputFileName]
//   - Content-Disposition header
//   - Request URL using [path.Base]
//   - Request URL hostname if path is empty or "/"
//
// It overrides the value set at the client instance level, see [Client.SetSaveResponse]
func (r *Request) SetSaveResponse(save bool) *Request {
	r.IsSaveResponse = save
	return r
}

// SetCloseConnection method sets variable `Close` in HTTP request struct with the given
// value. More info: https://golang.org/src/net/http/request.go
//
// It overrides the value set at the client instance level, see [Client.SetCloseConnection]
func (r *Request) SetCloseConnection(close bool) *Request {
	r.CloseConnection = close
	return r
}

// SetDoNotParseResponse method instructs Resty not to parse the response body automatically.
//
// Resty exposes the raw response body as [io.ReadCloser]. If you use it, do not
// forget to close the body, otherwise, you might get into connection leaks, and connection
// reuse may not happen.
//
// NOTE: The default [Response] middlewares are not executed when using this option. User
// takes over the control of handling response body from Resty.
func (r *Request) SetDoNotParseResponse(notParse bool) *Request {
	r.DoNotParseResponse = notParse
	return r
}

// SetResponseBodyLimit method sets a maximum body size limit in bytes on response,
// avoid reading too much data to memory.
//
// Client will return [resty.ErrResponseBodyTooLarge] if the body size of the body
// in the uncompressed response is larger than the limit.
// Body size limit will not be enforced in the following cases:
//   - ResponseBodyLimit <= 0, which is the default behavior.
//   - [Request.SetOutputFileName] is called to save response data to the file.
//   - "DoNotParseResponse" is set for client or request.
//
// It overrides the value set at the client instance level, see [Client.SetResponseBodyLimit]
func (r *Request) SetResponseBodyLimit(v int64) *Request {
	r.ResponseBodyLimit = v
	return r
}

// SetResponseBodyUnlimitedReads method is to turn on/off the response body in memory
// that provides an ability to do unlimited reads.
//
// It overrides the value set at the client level; see [Client.SetResponseBodyUnlimitedReads]
//
// Unlimited reads are possible in a few scenarios, even without enabling it.
//   - When debug mode is enabled
//
// NOTE: Use with care
//   - Turning on this feature keeps the response body in memory, which might cause additional memory usage.
func (r *Request) SetResponseBodyUnlimitedReads(b bool) *Request {
	r.ResponseBodyUnlimitedReads = b
	return r
}

// SetPathParam method sets a single URL path key-value pair in the
// Resty current request instance.
//
//	client.R().SetPathParam("userId", "sample@sample.com")
//
//	Result:
//	   URL - /v1/users/{userId}/details
//	   Composed URL - /v1/users/sample@sample.com/details
//
//	client.R().SetPathParam("path", "groups/developers")
//
//	Result:
//	   URL - /v1/users/{userId}/details
//	   Composed URL - /v1/users/groups%2Fdevelopers/details
//
// It replaces the value of the key while composing the request URL.
// The values will be escaped using function [url.PathEscape].
//
// It overrides the path parameter set at the client instance level.
func (r *Request) SetPathParam(param, value string) *Request {
	r.PathParams[param] = url.PathEscape(value)
	return r
}

// SetPathParams method sets multiple URL path key-value pairs at one go in the
// Resty current request instance.
//
//	client.R().SetPathParams(map[string]string{
//		"userId":       "sample@sample.com",
//		"subAccountId": "100002",
//		"path":         "groups/developers",
//	})
//
//	Result:
//	   URL - /v1/users/{userId}/{subAccountId}/{path}/details
//	   Composed URL - /v1/users/sample@sample.com/100002/groups%2Fdevelopers/details
//
// It replaces the value of the key while composing the request URL.
// The values will be escaped using function [url.PathEscape].
//
// It overrides the path parameter set at the client instance level.
func (r *Request) SetPathParams(params map[string]string) *Request {
	for p, v := range params {
		r.SetPathParam(p, v)
	}
	return r
}

// SetRawPathParam method sets a single URL path key-value pair in the
// Resty current request instance without path escape.
//
//	client.R().SetPathParam("userId", "sample@sample.com")
//
//	Result:
//	   URL - /v1/users/{userId}/details
//	   Composed URL - /v1/users/sample@sample.com/details
//
//	client.R().SetPathParam("path", "groups/developers")
//
//	Result:
//	   URL - /v1/users/{userId}/details
//	   Composed URL - /v1/users/groups/developers/details
//
// It replaces the value of the key while composing the request URL.
// The value will be used as-is, no path escape applied.
//
// It overrides the raw path parameter set at the client instance level.
func (r *Request) SetRawPathParam(param, value string) *Request {
	r.PathParams[param] = value
	return r
}

// SetRawPathParams method sets multiple URL path key-value pairs at one go in the
// Resty current request instance without path escape.
//
//	client.R().SetPathParams(map[string]string{
//		"userId": "sample@sample.com",
//		"subAccountId": "100002",
//		"path":         "groups/developers",
//	})
//
//	Result:
//	   URL - /v1/users/{userId}/{subAccountId}/{path}/details
//	   Composed URL - /v1/users/sample@sample.com/100002/groups/developers/details
//
// It replaces the value of the key while composing the request URL.
// The value will be used as-is, no path escape applied.
//
// It overrides the raw path parameter set at the client instance level.
func (r *Request) SetRawPathParams(params map[string]string) *Request {
	for p, v := range params {
		r.SetRawPathParam(p, v)
	}
	return r
}

// SetExpectResponseContentType method allows to provide fallback `Content-Type`
// for automatic unmarshalling when the `Content-Type` response header is unavailable.
func (r *Request) SetExpectResponseContentType(contentType string) *Request {
	r.ExpectResponseContentType = contentType
	return r
}

// SetForceResponseContentType method provides a strong sense of response `Content-Type` for
// automatic unmarshalling. Resty gives this a higher priority than the `Content-Type`
// response header.
//
// This means that if both [Request.SetForceResponseContentType] is set and
// the response `Content-Type` is available, `SetForceResponseContentType` value will win.
func (r *Request) SetForceResponseContentType(contentType string) *Request {
	r.ForceResponseContentType = contentType
	return r
}

// SetJSONEscapeHTML method enables or disables the HTML escape on JSON marshal.
// By default, escape HTML is `true`.
//
// NOTE: This option only applies to the standard JSON Marshaller used by Resty.
//
// It overrides the value set at the client instance level, see [Client.SetJSONEscapeHTML]
func (r *Request) SetJSONEscapeHTML(b bool) *Request {
	r.jsonEscapeHTML = b
	return r
}

// SetCookie method appends a single cookie in the current request instance.
//
//	client.R().SetCookie(&http.Cookie{
//				Name:"go-resty",
//				Value:"This is cookie value",
//			})
//
// NOTE: Method appends the Cookie value into existing Cookie even if its already existing.
func (r *Request) SetCookie(hc *http.Cookie) *Request {
	r.Cookies = append(r.Cookies, hc)
	return r
}

// SetCookies method sets an array of cookies in the current request instance.
//
//	cookies := []*http.Cookie{
//		&http.Cookie{
//			Name:"go-resty-1",
//			Value:"This is cookie 1 value",
//		},
//		&http.Cookie{
//			Name:"go-resty-2",
//			Value:"This is cookie 2 value",
//		},
//	}
//
//	// Setting a cookies into resty's current request
//	client.R().SetCookies(cookies)
//
// NOTE: Method appends the Cookie value into existing Cookie even if its already existing.
func (r *Request) SetCookies(rs []*http.Cookie) *Request {
	r.Cookies = append(r.Cookies, rs...)
	return r
}

// SetTimeout method is used to set a timeout for the current request
//
//	client.R().SetTimeout(1 * time.Minute)
//
// It overrides the timeout set at the client instance level, See [Client.SetTimeout]
//
// NOTE: Resty uses [context.WithTimeout] on the request, it does not use [http.Client.Timeout]
func (r *Request) SetTimeout(timeout time.Duration) *Request {
	r.Timeout = timeout
	return r
}

// SetLogger method sets given writer for logging Resty request and response details.
// By default, requests and responses inherit their logger from the client.
//
// Compliant to interface [resty.Logger].
//
// It overrides the logger value set at the client instance level.
func (r *Request) SetLogger(l Logger) *Request {
	r.log = l
	return r
}

// EnableDebug method is a helper method for [Request.SetDebug]
func (r *Request) EnableDebug() *Request {
	r.SetDebug(true)
	return r
}

// DisableDebug method is a helper method for [Request.SetDebug]
func (r *Request) DisableDebug() *Request {
	r.SetDebug(false)
	return r
}

// SetDebug method enables the debug mode on the current request. It logs
// the details current request and response.
//
//	client.R().SetDebug(true)
//	// OR
//	client.R().EnableDebug()
//
// Also, it can be enabled at the request level for a particular request; see [Request.SetDebug].
//   - For [Request], it logs information such as HTTP verb, Relative URL path,
//     Host, Headers, and Body if it has one.
//   - For [Response], it logs information such as Status, Response Time, Headers,
//     and Body if it has one.
func (r *Request) SetDebug(d bool) *Request {
	r.Debug = d
	return r
}

// AddRetryConditions method adds one or more retry condition functions into the request.
// These retry conditions are executed to determine if the request can be retried.
// The request will retry if any functions return `true`, otherwise return `false`.
//
// NOTE:
//   - The default retry conditions are applied first.
//   - The client-level retry conditions are applied to all requests.
//   - The request-level retry conditions are executed first before the client-level
//     retry conditions. See [Request.SetRetryConditions]
func (r *Request) AddRetryConditions(conditions ...RetryConditionFunc) *Request {
	r.retryConditions = append(r.retryConditions, conditions...)
	return r
}

// SetRetryConditions method overwrites the retry conditions in the request.
// These retry conditions are executed to determine if the request can be retried.
// The request will retry if any function returns `true`, otherwise return `false`.
func (r *Request) SetRetryConditions(conditions ...RetryConditionFunc) *Request {
	r.retryConditions = conditions
	return r
}

// AddRetryHooks method adds one or more side-effecting retry hooks in the request.
//
// NOTE:
//   - All the retry hooks are executed on each request retry.
//   - The request-level retry hooks are executed first before the client-level hooks.
func (r *Request) AddRetryHooks(hooks ...RetryHookFunc) *Request {
	r.retryHooks = append(r.retryHooks, hooks...)
	return r
}

// SetRetryHooks method overwrites side-effecting retry hooks in the request.
//
// NOTE:
//   - All the retry hooks are executed on each request retry.
func (r *Request) SetRetryHooks(hooks ...RetryHookFunc) *Request {
	r.retryHooks = hooks
	return r
}

// SetRetryCount method enables retry on Resty client and allows you
// to set no. of retry count.
//
//	first attempt + retry count = total attempts
//
// See [Request.SetRetryStrategy]
//
// NOTE:
//   - By default, Resty only does retry on idempotent HTTP verb, [RFC 9110 Section 9.2.2], [RFC 9110 Section 18.2]
//
// [RFC 9110 Section 9.2.2]: https://datatracker.ietf.org/doc/html/rfc9110.html#name-idempotent-methods
// [RFC 9110 Section 18.2]: https://datatracker.ietf.org/doc/html/rfc9110.html#name-method-registration
func (r *Request) SetRetryCount(count int) *Request {
	r.RetryCount = count
	return r
}

// SetRetryWaitTime method sets the default wait time for sleep before retrying
//
// Default is 100 milliseconds.
func (r *Request) SetRetryWaitTime(waitTime time.Duration) *Request {
	r.RetryWaitTime = waitTime
	return r
}

// SetRetryMaxWaitTime method sets the max wait time for sleep before retrying
//
// Default is 2 seconds.
func (r *Request) SetRetryMaxWaitTime(maxWaitTime time.Duration) *Request {
	r.RetryMaxWaitTime = maxWaitTime
	return r
}

// SetRetryStrategy method used to set the custom Retry strategy on request,
// it is used to get wait time before each retry. It overrides the retry
// strategy set at the client instance level, see [Client.SetRetryStrategy]
//
// Default (nil) implies capped exponential backoff with a jitter strategy
func (r *Request) SetRetryStrategy(rs RetryStrategyFunc) *Request {
	r.RetryStrategy = rs
	return r
}

// EnableRetryDefaultConditions method enables the Resty's default retry
// conditions on request level
func (r *Request) EnableRetryDefaultConditions() *Request {
	r.SetRetryDefaultConditions(true)
	return r
}

// DisableRetryDefaultConditions method disables the Resty's default retry
// conditions on request level
func (r *Request) DisableRetryDefaultConditions() *Request {
	r.SetRetryDefaultConditions(false)
	return r
}

// SetRetryDefaultConditions method is used to enable/disable the Resty's default
// retry conditions on request level
//
// It overrides value set at the client instance level, see [Client.SetRetryDefaultConditions]
func (r *Request) SetRetryDefaultConditions(b bool) *Request {
	r.IsRetryDefaultConditions = b
	return r
}

// SetAllowNonIdempotentRetry method is used to enable/disable non-idempotent HTTP
// methods retry. By default, Resty only allows idempotent HTTP methods, see
// [RFC 9110 Section 9.2.2], [RFC 9110 Section 18.2]
//
// It overrides value set at the client instance level, see [Client.SetAllowNonIdempotentRetry]
//
// [RFC 9110 Section 9.2.2]: https://datatracker.ietf.org/doc/html/rfc9110.html#name-idempotent-methods
// [RFC 9110 Section 18.2]: https://datatracker.ietf.org/doc/html/rfc9110.html#name-method-registration
func (r *Request) SetAllowNonIdempotentRetry(b bool) *Request {
	r.AllowNonIdempotentRetry = b
	return r
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// HTTP request tracing
//_______________________________________________________________________

// EnableTrace method enables trace for the current request
// using [httptrace.ClientTrace] and provides insights.
//
//	client := resty.New()
//
//	resp, err := client.R().EnableTrace().Get("https://httpbin.org/get")
//	fmt.Println("Error:", err)
//	fmt.Println("Trace Info:", resp.Request.TraceInfo())
//
// See [Client.EnableTrace], [Client.SetTrace] are also available to
// get trace info for all requests.
func (r *Request) EnableTrace() *Request {
	r.SetTrace(true)
	return r
}

// DisableTrace method disables the request trace for the current request
func (r *Request) DisableTrace() *Request {
	r.SetTrace(false)
	return r
}

// SetTrace method is used to turn on/off the trace capability at the request level
//
// See [Request.EnableTrace] or [Client.SetTrace]
func (r *Request) SetTrace(t bool) *Request {
	r.IsTrace = t
	return r
}

// EnableGenerateCurlCmd method enables the generation of curl commands for the current request.
//
// By default, Resty does not log the curl command in the debug log since it has the potential
// to leak sensitive data unless explicitly enabled via [Request.SetDebugLogCurlCmd] or
// [Client.SetDebugLogCurlCmd].
//
// It overrides the options set in the [Client].
//
// NOTE: Use with care.
//   - Potential to leak sensitive data from [Request] and [Response] in the debug log
//     when the debug log option is enabled.
//   - Additional memory usage since the request body was reread.
//   - curl body is not generated for [io.Reader] and multipart request flow.
func (r *Request) EnableGenerateCurlCmd() *Request {
	r.SetGenerateCurlCmd(true)
	return r
}

// DisableGenerateCurlCmd method disables the option set by [Request.EnableGenerateCurlCmd] or
// [Request.SetGenerateCurlCmd].
//
// It overrides the options set in the [Client].
func (r *Request) DisableGenerateCurlCmd() *Request {
	r.SetGenerateCurlCmd(false)
	return r
}

// SetGenerateCurlCmd method is used to turn on/off the generate curl command for the current request.
//
// By default, Resty does not log the curl command in the debug log since it has the potential
// to leak sensitive data unless explicitly enabled via [Request.SetDebugLogCurlCmd] or
// [Client.SetDebugLogCurlCmd].
//
// It overrides the options set by the [Client.SetGenerateCurlCmd]
//
// NOTE: Use with care.
//   - Potential to leak sensitive data from [Request] and [Response] in the debug log
//     when the debug log option is enabled.
//   - Additional memory usage since the request body was reread.
//   - curl body is not generated for [io.Reader] and multipart request flow.
func (r *Request) SetGenerateCurlCmd(b bool) *Request {
	r.generateCurlCmd = b
	return r
}

// SetDebugLogCurlCmd method enables the curl command to be logged in the debug log
// for the current request.
//
// It can be overridden at the request level; see [Client.SetDebugLogCurlCmd]
func (r *Request) SetDebugLogCurlCmd(b bool) *Request {
	r.debugLogCurlCmd = b
	return r
}

// CurlCmd method generates the curl command for the request.
func (r *Request) CurlCmd() string {
	return r.generateCurlCommand()
}

func (r *Request) generateCurlCommand() string {
	if !r.generateCurlCmd {
		return ""
	}
	if len(r.resultCurlCmd) > 0 {
		return r.resultCurlCmd
	}
	if r.RawRequest == nil {
		if err := r.client.executeRequestMiddlewares(r); err != nil {
			r.log.Errorf("%v", err)
			return ""
		}
	}
	r.resultCurlCmd = buildCurlCmd(r)
	return r.resultCurlCmd
}

// SetUnescapeQueryParams method sets the choice of unescape query parameters for the request URL.
// To prevent broken URL, Resty replaces space (" ") with "+" in the query parameters.
//
// This method overrides the value set by [Client.SetUnescapeQueryParams]
//
// NOTE: Request failure is possible due to non-standard usage of Unescaped Query Parameters.
func (r *Request) SetUnescapeQueryParams(unescape bool) *Request {
	r.unescapeQueryParams = unescape
	return r
}

// SetAllowMethodGetPayload method allows the GET method with payload on the request level.
// By default, Resty does not allow.
//
//	client.R().SetAllowMethodGetPayload(true)
//
// It overrides the option set by the [Client.SetAllowMethodGetPayload]
func (r *Request) SetAllowMethodGetPayload(allow bool) *Request {
	r.AllowMethodGetPayload = allow
	return r
}

// SetAllowMethodDeletePayload method allows the DELETE method with payload on the request level.
// By default, Resty does not allow.
//
//	client.R().SetAllowMethodDeletePayload(true)
//
// More info, refer to GH#881
//
// It overrides the option set by the [Client.SetAllowMethodDeletePayload]
func (r *Request) SetAllowMethodDeletePayload(allow bool) *Request {
	r.AllowMethodDeletePayload = allow
	return r
}

// TraceInfo method returns the trace info for the request.
// If either the [Client.EnableTrace] or [Request.EnableTrace] function has not been called
// before the request is made, an empty [resty.TraceInfo] object is returned.
func (r *Request) TraceInfo() TraceInfo {
	ct := r.trace

	if ct == nil {
		return TraceInfo{}
	}

	ti := TraceInfo{
		DNSLookup:      ct.dnsDone.Sub(ct.dnsStart),
		TLSHandshake:   ct.tlsHandshakeDone.Sub(ct.tlsHandshakeStart),
		ServerTime:     ct.gotFirstResponseByte.Sub(ct.gotConn),
		IsConnReused:   ct.gotConnInfo.Reused,
		IsConnWasIdle:  ct.gotConnInfo.WasIdle,
		ConnIdleTime:   ct.gotConnInfo.IdleTime,
		RequestAttempt: r.Attempt,
	}

	// Calculate the total time accordingly,
	// when connection is reused
	if ct.gotConnInfo.Reused {
		ti.TotalTime = ct.endTime.Sub(ct.getConn)
	} else {
		ti.TotalTime = ct.endTime.Sub(ct.dnsStart)
	}

	// Only calculate on successful connections
	if !ct.connectDone.IsZero() {
		ti.TCPConnTime = ct.connectDone.Sub(ct.dnsDone)
	}

	// Only calculate on successful connections
	if !ct.gotConn.IsZero() {
		ti.ConnTime = ct.gotConn.Sub(ct.getConn)
	}

	// Only calculate on successful connections
	if !ct.gotFirstResponseByte.IsZero() {
		ti.ResponseTime = ct.endTime.Sub(ct.gotFirstResponseByte)
	}

	// Capture remote address info when connection is non-nil
	if ct.gotConnInfo.Conn != nil {
		ti.RemoteAddr = ct.gotConnInfo.Conn.RemoteAddr().String()
	}

	return ti
}

//‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
// HTTP verb method starts here
//_______________________________________________________________________

// Get method does GET HTTP request. It's defined in section 9.3.1 of [RFC 9110].
//
// [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110.html#section-9.3.1
func (r *Request) Get(url string) (*Response, error) {
	return r.Execute(MethodGet, url)
}

// Head method does HEAD HTTP request. It's defined in section 9.3.2 of [RFC 9110].
//
// [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110.html#section-9.3.2
func (r *Request) Head(url string) (*Response, error) {
	return r.Execute(MethodHead, url)
}

// Post method does POST HTTP request. It's defined in section 9.3.3 of [RFC 9110].
//
// [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110.html#section-9.3.3
func (r *Request) Post(url string) (*Response, error) {
	return r.Execute(MethodPost, url)
}

// Put method does PUT HTTP request. It's defined in section 9.3.4 of [RFC 9110].
//
// [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110.html#section-9.3.4
func (r *Request) Put(url string) (*Response, error) {
	return r.Execute(MethodPut, url)
}

// Patch method does PATCH HTTP request. It's defined in section 2 of [RFC 5789].
//
// [RFC 5789]: https://datatracker.ietf.org/doc/html/rfc5789.html#section-2
func (r *Request) Patch(url string) (*Response, error) {
	return r.Execute(MethodPatch, url)
}

// Delete method does DELETE HTTP request. It's defined in section 9.3.5 of [RFC 9110].
//
// [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110.html#section-9.3.5
func (r *Request) Delete(url string) (*Response, error) {
	return r.Execute(MethodDelete, url)
}

// Options method does OPTIONS HTTP request. It's defined in section 9.3.7 of [RFC 9110].
//
// [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110.html#section-9.3.7
func (r *Request) Options(url string) (*Response, error) {
	return r.Execute(MethodOptions, url)
}

// Trace method does TRACE HTTP request. It's defined in section 9.3.8 of [RFC 9110].
//
// [RFC 9110]: https://datatracker.ietf.org/doc/html/rfc9110.html#section-9.3.8
func (r *Request) Trace(url string) (*Response, error) {
	return r.Execute(MethodTrace, url)
}

// Send method performs the HTTP request using the method and URL already defined
// for current [Request].
//
//	res, err := client.R().
//		SetMethod(resty.MethodGet).
//		SetURL("http://httpbin.org/get").
//		Send()
func (r *Request) Send() (*Response, error) {
	return r.Execute(r.Method, r.URL)
}

// Execute method performs the HTTP request with the given HTTP method and URL
// for current [Request].
//
//	resp, err := client.R().Execute(resty.MethodGet, "http://httpbin.org/get")
func (r *Request) Execute(method, url string) (res *Response, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			if err, ok := rec.(error); ok {
				r.client.onPanicHooks(r, err)
			} else {
				r.client.onPanicHooks(r, fmt.Errorf("panic %v", rec))
			}
			panic(rec)
		}
	}()

	r.Method = method

	if r.RetryCount < 0 {
		r.RetryCount = 0 // default behavior is no retry
	}

	isIdempotent := r.isIdempotent()
	var backoff *backoffWithJitter
	if r.RetryCount > 0 && isIdempotent {
		backoff = newBackoffWithJitter(r.RetryWaitTime, r.RetryMaxWaitTime)
		r.RetryTraceID = newGUID()
	}

	isInvalidRequestErr := false
	// first attempt + retry count = total attempts
	for i := 0; i <= r.RetryCount; i++ {
		r.Attempt++
		err = nil
		r.URL = url
		res, err = r.client.execute(r)
		if err != nil {
			if irErr, ok := err.(*invalidRequestError); ok {
				err = irErr.Err
				isInvalidRequestErr = true
				break
			}
			if r.Context().Err() != nil {
				if r.ctxCancelFunc != nil {
					r.ctxCancelFunc()
					r.ctxCancelFunc = nil
				}
				if !errors.Is(err, context.DeadlineExceeded) {
					err = wrapErrors(r.Context().Err(), err)
					break
				}
			}
		}

		// we have reached the maximum no. of requests
		// or request method is not an idempotent
		if r.Attempt-1 == r.RetryCount || !isIdempotent {
			break
		}

		if backoff != nil {
			needsRetry, isCtxDone := false, false

			// apply default retry conditions
			if r.IsRetryDefaultConditions {
				needsRetry = applyRetryDefaultConditions(res, err)
			}

			// apply user-defined retry conditions if default one
			// is still false
			if !needsRetry && res != nil {
				// user defined retry conditions
				for _, retryCondition := range r.retryConditions {
					if needsRetry = retryCondition(res, err); needsRetry {
						break
					}
				}
			}

			// retry not required stop here
			if !needsRetry {
				break
			}

			// by default reset file readers
			if err = r.resetFileReaders(); err != nil {
				// if any error in reset readers, stop here
				break
			}

			// run user-defined retry hooks
			for _, retryHookFunc := range r.retryHooks {
				retryHookFunc(res, err)
			}

			// let's drain the response body, before retry wait
			drainBody(res)

			waitDuration, waitErr := backoff.NextWaitDuration(r.client, res, err, r.Attempt)
			if waitErr != nil {
				// if any error in retry strategy, stop here
				err = wrapErrors(waitErr, err)
				break
			}

			timer := time.NewTimer(waitDuration)
			select {
			case <-r.Context().Done():
				isCtxDone = true
				err = wrapErrors(r.Context().Err(), err)
				break
			case <-timer.C:
			}
			timer.Stop()
			if isCtxDone {
				break
			}
		}
	}

	if r.isMultiPart {
		for _, mf := range r.multipartFields {
			mf.close()
		}
	}

	r.IsDone = true

	if isInvalidRequestErr {
		r.client.onInvalidHooks(r, err)
	} else {
		r.client.onErrorHooks(r, res, err)
	}

	r.sendLoadBalancerFeedback(res, err)
	backToBufPool(r.bodyBuf)
	return
}

// Clone returns a deep copy of r with its context changed to ctx.
// It does clone appropriate fields, reset, and reinitialize, so
// [Request] can be used again.
//
// The body is not copied, but it's a reference to the original body.
//
//	req := client.R().
//		SetBody("body").
//		SetHeader("header", "value")
//	clonedRequest := req.Clone(context.Background())
func (r *Request) Clone(ctx context.Context) *Request {
	if ctx == nil {
		panic("resty: Request.Clone nil context")
	}
	rr := new(Request)
	*rr = *r

	// set new context
	rr.ctx = ctx

	// RawRequest should not copied, since its created on request execution flow.
	rr.RawRequest = nil

	// clone values
	rr.Header = r.Header.Clone()
	rr.FormData = cloneURLValues(r.FormData)
	rr.QueryParams = cloneURLValues(r.QueryParams)
	rr.PathParams = maps.Clone(r.PathParams)

	// clone basic auth
	if r.credentials != nil {
		rr.credentials = r.credentials.Clone()
	}

	// clone cookies
	if l := len(r.Cookies); l > 0 {
		rr.Cookies = make([]*http.Cookie, l)
		for _, cookie := range r.Cookies {
			rr.Cookies = append(rr.Cookies, cloneCookie(cookie))
		}
	}

	// create new interface for result and error
	rr.Result = newInterface(r.Result)
	rr.Error = newInterface(r.Error)

	// clone multipart fields
	if l := len(r.multipartFields); l > 0 {
		rr.multipartFields = make([]*MultipartField, l)
		for i, mf := range r.multipartFields {
			rr.multipartFields[i] = mf.Clone()
		}
	}

	// reset values
	rr.Time = time.Time{}
	rr.Attempt = 0
	rr.initTraceIfEnabled()
	r.values = make(map[string]any)
	r.multipartErrChan = nil
	r.ctxCancelFunc = nil

	// copy bodyBuf
	if r.bodyBuf != nil {
		rr.bodyBuf = acquireBuffer()
		rr.bodyBuf.Write(r.bodyBuf.Bytes())
	}

	return rr
}

// Funcs method gets executed on request composition that passes the
// current request instance to provided [RequestFunc], which could be
// used to apply common/reusable logic to the given request instance.
//
//	func addRequestContentType(r *Request) *Request {
//		return r.SetHeader("Content-Type", "application/json").
//			SetHeader("Accept", "application/json")
//	}
//
//	func addRequestQueryParams(page, size int) func(r *Request) *Request {
//		return func(r *Request) *Request {
//			return r.SetQueryParam("page", strconv.Itoa(page)).
//				SetQueryParam("size", strconv.Itoa(size)).
//				SetQueryParam("request_no", strconv.Itoa(int(time.Now().Unix())))
//		}
//	}
//
//	client.R().
//		Funcs(addRequestContentType, addRequestQueryParams(1, 100)).
//		Get("https://localhost:8080/foobar")
func (r *Request) Funcs(funcs ...RequestFunc) *Request {
	for _, f := range funcs {
		r = f(r)
	}
	return r
}

func (r *Request) fmtBodyString(sl int) (body string) {
	body = "***** NO CONTENT *****"
	if !r.isPayloadSupported() {
		return
	}

	if _, ok := r.Body.(io.Reader); ok {
		body = "***** BODY IS io.Reader *****"
		return
	}

	// multipart or form-data
	if r.isMultiPart || r.isFormData {
		bodySize := r.bodyBuf.Len()
		if bodySize > sl {
			body = fmt.Sprintf("***** REQUEST TOO LARGE (size - %d) *****", bodySize)
			return
		}
		body = r.bodyBuf.String()
		return
	}

	// request body data
	if r.Body == nil {
		return
	}
	var prtBodyBytes []byte
	var err error

	contentType := r.Header.Get(hdrContentTypeKey)
	ctKey := inferContentTypeMapKey(contentType)

	kind := inferKind(r.Body)
	if jsonKey == ctKey &&
		(kind == reflect.Struct || kind == reflect.Map || kind == reflect.Slice) {
		buf := acquireBuffer()
		defer releaseBuffer(buf)
		if err = encodeJSONEscapeHTMLIndent(buf, &r.Body, false, "   "); err == nil {
			prtBodyBytes = buf.Bytes()
		}
	} else if xmlKey == ctKey && kind == reflect.Struct {
		prtBodyBytes, err = xml.MarshalIndent(&r.Body, "", "   ")
	} else {
		switch b := r.Body.(type) {
		case string:
			prtBodyBytes = []byte(b)
			if jsonKey == ctKey {
				prtBodyBytes = jsonIndent(prtBodyBytes)
			}
		case []byte:
			body = fmt.Sprintf("***** BODY IS byte(s) (size - %d) *****", len(b))
			return
		}
	}

	bodySize := len(prtBodyBytes)
	if bodySize > sl {
		body = fmt.Sprintf("***** REQUEST TOO LARGE (size - %d) *****", bodySize)
		return
	}

	if prtBodyBytes != nil && err == nil {
		body = string(prtBodyBytes)
	}

	return
}

func (r *Request) initValuesMap() {
	if r.values == nil {
		r.values = make(map[string]any)
	}
}

func (r *Request) initTraceIfEnabled() {
	if r.IsTrace {
		r.trace = new(clientTrace)
		r.ctx = r.trace.createContext(r.Context())
	}
}

func (r *Request) isHeaderExists(k string) bool {
	_, f := r.Header[k]
	return f
}

func (r *Request) writeFormData(w *multipart.Writer) error {
	for k, v := range r.FormData {
		for _, iv := range v {
			if err := w.WriteField(k, iv); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Request) isPayloadSupported() bool {
	if r.Method == "" {
		r.Method = MethodGet
	}

	if r.Method == MethodGet && r.AllowMethodGetPayload {
		return true
	}

	// More info, refer to GH#881
	if r.Method == MethodDelete && r.AllowMethodDeletePayload {
		return true
	}

	if r.Method == MethodPost || r.Method == MethodPut || r.Method == MethodPatch {
		return true
	}

	return false
}

func (r *Request) sendLoadBalancerFeedback(res *Response, err error) {
	if r.client.LoadBalancer() == nil {
		return
	}

	success := true

	// load balancer feedback mainly focuses on connection
	// failures and status code >= 500
	// so that we can prevent sending the request to
	// that server which may fail
	if err != nil {
		var noe *net.OpError
		if errors.As(err, &noe) {
			success = !errors.Is(noe.Err, syscall.ECONNREFUSED) || noe.Timeout()
		}
	}
	if success && res != nil &&
		(res.StatusCode() >= 500 && res.StatusCode() != http.StatusNotImplemented) {
		success = false
	}

	r.client.LoadBalancer().Feedback(&RequestFeedback{
		BaseURL: r.baseURL,
		Success: success,
		Attempt: r.Attempt,
	})
}

func (r *Request) resetFileReaders() error {
	for _, f := range r.multipartFields {
		if err := f.resetReader(); err != nil {
			return err
		}
	}
	return nil
}

// https://datatracker.ietf.org/doc/html/rfc9110.html#name-idempotent-methods
// https://datatracker.ietf.org/doc/html/rfc9110.html#name-method-registration
var idempotentMethods = map[string]struct{}{
	MethodDelete:  {},
	MethodGet:     {},
	MethodHead:    {},
	MethodOptions: {},
	MethodPut:     {},
	MethodTrace:   {},
}

func (r *Request) isIdempotent() bool {
	_, found := idempotentMethods[r.Method]
	return found || r.AllowNonIdempotentRetry
}

func (r *Request) withTimeout() *http.Request {
	if _, found := r.Context().Deadline(); found {
		return r.RawRequest
	}
	if r.Timeout > 0 {
		ctx, ctxCancelFunc := context.WithTimeout(r.Context(), r.Timeout)
		r.ctxCancelFunc = ctxCancelFunc
		return r.RawRequest.WithContext(ctx)
	}
	return r.RawRequest
}

func jsonIndent(v []byte) []byte {
	buf := acquireBuffer()
	defer releaseBuffer(buf)
	if err := json.Indent(buf, v, "", "   "); err != nil {
		return v
	}
	return buf.Bytes()
}
