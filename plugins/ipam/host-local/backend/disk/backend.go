// Copyright 2015 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package disk

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/containernetworking/plugins/plugins/ipam/host-local/backend"
)

const lastIPFilePrefix = "last_reserved_ip."
const revokedIdIPFile = "revoked_id_ifname_ip_list" // <id>,<ifname>,<ip>
const LineBreak = "\r\n"

var defaultDataDir = "/var/lib/cni/networks"

// Store is a simple disk-backed store that creates one file per IP
// address in a given directory. The contents of the file are the container ID.
type Store struct {
	*FileLock
	dataDir string
}

// Store implements the Store interface
var _ backend.Store = &Store{}

func New(network, dataDir string) (*Store, error) {
	if dataDir == "" {
		dataDir = defaultDataDir
	}
	dir := filepath.Join(dataDir, network)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	lk, err := NewFileLock(dir)
	if err != nil {
		return nil, err
	}
	return &Store{lk, dir}, nil
}

// Reserve reserves the specified IP with the given range and persists
// reservation to the disk.
func (s *Store) Reserve(id string, ifname string, ip net.IP, rangeID string) (reserved bool, err error) {
	if reserved, err = s.ReserveEphemeral(id, ifname, ip, rangeID); err != nil {
		return false, err
	}
	if !reserved {
		return false, nil
	}

	// store the reserved IP in lastIPFile
	ipfile := GetEscapedPath(s.dataDir, lastIPFilePrefix+rangeID)
	err = ioutil.WriteFile(ipfile, []byte(ip.String()), 0644)
	if err != nil {
		return false, err
	}
	return reserved, nil
}

// ReserveEphemeral reserves the specified IP with the given range without updating
// the last IP state.
func (s *Store) ReserveEphemeral(id string, ifname string, ip net.IP, rangeID string) (bool, error) {
	fname := GetEscapedPath(s.dataDir, ip.String())

	f, err := os.OpenFile(fname, os.O_RDWR|os.O_EXCL|os.O_CREATE, 0644)
	if os.IsExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := f.WriteString(strings.TrimSpace(id) + LineBreak + ifname); err != nil {
		f.Close()
		os.Remove(f.Name())
		return false, err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return false, err
	}
	return true, nil
}

// LastReservedIP returns the last reserved IP if exists
func (s *Store) LastReservedIP(rangeID string) (net.IP, error) {
	ipfile := GetEscapedPath(s.dataDir, lastIPFilePrefix+rangeID)
	data, err := ioutil.ReadFile(ipfile)
	if err != nil {
		return nil, err
	}
	return net.ParseIP(string(data)), nil
}

func (s *Store) Release(ip net.IP) error {
	return os.Remove(GetEscapedPath(s.dataDir, ip.String()))
}

func (s *Store) FindByKey(id string, ifname string, match string) (bool, error) {
	found := false

	err := filepath.Walk(s.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return nil
		}
		if strings.TrimSpace(string(data)) == match {
			found = true
		}
		return nil
	})
	return found, err

}

func (s *Store) FindByID(id string, ifname string) bool {
	s.Lock()
	defer s.Unlock()

	found := false
	match := strings.TrimSpace(id) + LineBreak + ifname
	found, err := s.FindByKey(id, ifname, match)

	// Match anything created by this id
	if !found && err == nil {
		match := strings.TrimSpace(id)
		found, err = s.FindByKey(id, ifname, match)
	}

	return found
}

var errAbort = errors.New("iteration aborted")

func (s *Store) releaseByKey(match string) (ip string, err error) {
	err = filepath.Walk(s.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(data)) == match {
			if err := os.Remove(path); err != nil {
				return err
			}
			ip = filepath.Base(path)
			return errAbort
		}
		return nil
	})
	if err != errAbort {
		return "", err
	}
	return ip, nil
}

func (s *Store) revokeIP(id, ifname, ip string) (err error) {
	path := GetEscapedPath(s.dataDir, revokedIdIPFile)
	record := fmt.Sprintf("%s,%s,%s\n", id, ifname, ip)

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		bytes, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		if !strings.Contains(string(bytes), record) {
			return nil
		}
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			return
		}
		err = file.Close()
	}()

	if _, err = file.WriteString(record); err != nil {
		return err
	}
	return nil
}

// N.B. This function eats errors to be tolerant and
// release as much as possible
func (s *Store) ReleaseByID(id string, ifname string) error {
	match := strings.TrimSpace(id) + LineBreak + ifname
	ip, err := s.releaseByKey(match)
	if err != nil {
		return err
	}
	if ip == "" {
		// For backwards compatibility, look for files written by a previous version
		match = strings.TrimSpace(id)
		ip, err = s.releaseByKey(match)
		if err != nil {
			return err
		}
	}
	return s.revokeIP(id, ifname, ip)
}

// GetByID returns the IPs which have been allocated to the specific ID
func (s *Store) GetByID(id string, ifname string) []net.IP {
	var ips []net.IP

	match := strings.TrimSpace(id) + LineBreak + ifname
	// matchOld for backwards compatibility
	matchOld := strings.TrimSpace(id)

	// walk through all ips in this network to get the ones which belong to a specific ID
	_ = filepath.Walk(s.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return nil
		}
		if strings.TrimSpace(string(data)) == match || strings.TrimSpace(string(data)) == matchOld {
			_, ipString := filepath.Split(path)
			if ip := net.ParseIP(ipString); ip != nil {
				ips = append(ips, ip)
			}
		}
		return nil
	})

	return ips
}

func (s *Store) GetRevokedIPbyID(id string, ifname string) (net.IP, error) {
	path := GetEscapedPath(s.dataDir, revokedIdIPFile)

	file, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	for {
		str, err := reader.ReadString('\n')
		if err != nil {
			switch err {
			case io.EOF:
				return nil, nil
			default:
				return nil, err
			}
		}

		idipPair := strings.SplitN(strings.TrimSuffix(str, "\n"), ",", 3)
		if len(idipPair) != 3 {
			return nil, errors.New(fmt.Sprintf(
				"failed to get ID (%s:%s) and IP from %s",
				id,
				ifname,
				path,
			))
		}

		if idipPair[0] == id && idipPair[1] == ifname {
			return net.ParseIP(idipPair[2]), nil
		}
	}
}

func GetEscapedPath(dataDir string, fname string) string {
	if runtime.GOOS == "windows" {
		fname = strings.Replace(fname, ":", "_", -1)
	}
	return filepath.Join(dataDir, fname)
}
