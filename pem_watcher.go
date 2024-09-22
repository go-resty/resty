// Copyright (c) 2015-2024 Jeevanandam M (jeeva@myjeeva.com), All rights reserved.
// resty source code and usage is governed by a MIT style
// license that can be found in the LICENSE file.

package resty

import (
	"crypto/x509"
	"errors"
	"os"
	"time"
)

const (
	defaultWatcherPoolingInterval = 1 * time.Minute
)

// WatcherOptions struct is used to enable TLS Certificate hot reloading.
type WatcherOptions struct {
	// PemFilePath is the path of the PEM file
	PemFilePath string

	// PoolingInterval is the frequency at which resty will check if the PEM file needs to be reloaded.
	// Default is 1 min.
	PoolingInterval time.Duration
}

type pemWatcher struct {
	opt *WatcherOptions

	certPool    *x509.CertPool
	modTime     time.Time
	lastChecked time.Time
	log         Logger
	debug       bool
}

func newPemWatcher(options *WatcherOptions, log Logger, debug bool) (*pemWatcher, error) {
	if options.PemFilePath == "" {
		return nil, errors.New("PemFilePath is required")
	}

	if options.PoolingInterval == 0 {
		options.PoolingInterval = defaultWatcherPoolingInterval
	}

	cw := &pemWatcher{
		opt:   options,
		log:   log,
		debug: debug,
	}

	if err := cw.checkRefresh(); err != nil {
		return nil, err
	}

	return cw, nil
}

func (pw *pemWatcher) CertPool() (*x509.CertPool, error) {
	if err := pw.checkRefresh(); err != nil {
		return nil, err
	}

	return pw.certPool, nil
}

func (pw *pemWatcher) checkRefresh() error {
	if time.Since(pw.lastChecked) <= pw.opt.PoolingInterval {
		return nil
	}

	pw.Debugf("Checking if cert has changed...")

	newModTime, err := pw.getModTime()
	if err != nil {
		return err
	}

	if pw.modTime.Equal(newModTime) {
		pw.lastChecked = time.Now().UTC()
		pw.Debugf("No change")
		return nil
	}

	if err := pw.refreshCertPool(); err != nil {
		return err
	}

	pw.modTime = newModTime
	pw.lastChecked = time.Now().UTC()

	pw.Debugf("Cert refreshed")

	return nil
}

func (pw *pemWatcher) getModTime() (time.Time, error) {
	info, err := os.Stat(pw.opt.PemFilePath)
	if err != nil {
		return time.Time{}, err
	}

	return info.ModTime().UTC(), nil
}

func (pw *pemWatcher) refreshCertPool() error {
	pemCert, err := os.ReadFile(pw.opt.PemFilePath)
	if err != nil {
		return nil
	}

	pw.certPool = x509.NewCertPool()
	pw.certPool.AppendCertsFromPEM(pemCert)
	return nil
}

func (pw *pemWatcher) Debugf(format string, v ...interface{}) {
	if !pw.debug {
		return
	}

	pw.log.Debugf(format, v...)
}
