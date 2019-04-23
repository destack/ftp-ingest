package tests

import (
	"crypto/tls"
	"errors"
	"io/ioutil"
	"os"

	ftpserver "eljefedelrodeodeljefe/ftp-ingest/pkg/ftpserver"

	"github.com/go-kit/kit/log"
)

// NewTestServer provides a test server with or without debugging
func NewTestServer(debug bool) *ftpserver.FtpServer {
	return NewTestServerWithDriver(&ServerDriver{Debug: debug})
}

// NewTestServerWithDriver provides a server instantiated with some settings
func NewTestServerWithDriver(driver *ServerDriver) *ftpserver.FtpServer {
	if driver.Settings == nil {
		driver.Settings = &ftpserver.Settings{}
	}

	if driver.Settings.ListenAddr == "" {
		driver.Settings.ListenAddr = "127.0.0.1:0"
	}

	s := ftpserver.NewFtpServer(driver)

	// If we are in debug mode, we should log things
	if driver.Debug {
		s.Logger = log.With(
			log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout)),
			"ts", log.DefaultTimestampUTC,
			"caller", log.DefaultCaller,
		)
	}

	if err := s.Listen(); err != nil {
		return nil
	}
	go s.Serve()
	return s
}

// ServerDriver defines a minimal serverftp server driver
type ServerDriver struct {
	Debug bool // To display connection logs information
	TLS   bool

	Settings *ftpserver.Settings // Settings
	ftpserver.FileStream
}

// ClientDriver defines a minimal serverftp client driver
type ClientDriver struct {
	baseDir string
	ftpserver.FileStream
}

// NewClientDriver creates a client driver
func NewClientDriver() *ClientDriver {
	dir, _ := ioutil.TempDir("", "example")
	os.MkdirAll(dir, 0777)
	return &ClientDriver{baseDir: dir}
}

// WelcomeUser is the very first message people will see
func (driver *ServerDriver) WelcomeUser(cc ftpserver.ClientContext) (string, error) {
	cc.SetDebug(driver.Debug)
	// This will remain the official name for now
	return "TEST Server", nil
}

// AuthUser with authenticate users
func (driver *ServerDriver) AuthUser(cc ftpserver.ClientContext, user, pass string) (ftpserver.ClientHandlingDriver, error) {
	if user == "test" && pass == "test" {
		clientdriver := NewClientDriver()
		if driver.FileStream != nil {
			clientdriver.FileStream = driver.FileStream
		}
		return clientdriver, nil
	}
	return nil, errors.New("bad username or password")
}

// UserLeft is called when the user disconnects
func (driver *ServerDriver) UserLeft(cc ftpserver.ClientContext) {

}

// GetSettings fetches the basic server settings
func (driver *ServerDriver) GetSettings() (*ftpserver.Settings, error) {
	return driver.Settings, nil
}

// GetTLSConfig fetches the TLS config
func (driver *ServerDriver) GetTLSConfig() (*tls.Config, error) {
	if driver.TLS {
		keypair, err := tls.X509KeyPair(localhostCert, localhostKey)
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{keypair}}, nil
	}
	return nil, nil
}

// ChangeDirectory changes the current working directory
func (driver *ClientDriver) ChangeDirectory(cc ftpserver.ClientContext, directory string) error {
	_, err := os.Stat(driver.baseDir + directory)
	return err
}

// MakeDirectory creates a directory
func (driver *ClientDriver) MakeDirectory(cc ftpserver.ClientContext, directory string) error {
	return os.Mkdir(driver.baseDir+directory, 0777)
}

// ListFiles lists the files of a directory
func (driver *ClientDriver) ListFiles(cc ftpserver.ClientContext) ([]os.FileInfo, error) {
	path := driver.baseDir + cc.Path()
	files, err := ioutil.ReadDir(path)
	return files, err
}

// OpenFile opens a file in 3 possible modes: read, write, appending write (use appropriate flags)
func (driver *ClientDriver) OpenFile(cc ftpserver.ClientContext, path string, flag int) (ftpserver.FileStream, error) {
	path = driver.baseDir + path

	// If we are writing and we are not in append mode, we should remove the file
	if (flag & os.O_WRONLY) != 0 {
		flag |= os.O_CREATE
		if (flag & os.O_APPEND) == 0 {
			os.Remove(path)
		}
	}

	if driver.FileStream != nil {
		return driver.FileStream, nil
	}

	return os.OpenFile(path, flag, 0666)
}

// GetFileInfo gets some info around a file or a directory
func (driver *ClientDriver) GetFileInfo(cc ftpserver.ClientContext, path string) (os.FileInfo, error) {
	path = driver.baseDir + path

	return os.Stat(path)
}

// CanAllocate gives the approval to allocate some data
func (driver *ClientDriver) CanAllocate(cc ftpserver.ClientContext, size int) (bool, error) {
	return true, nil
}

// ChmodFile changes the attributes of the file
func (driver *ClientDriver) ChmodFile(cc ftpserver.ClientContext, path string, mode os.FileMode) error {
	path = driver.baseDir + path
	return os.Chmod(path, mode)
}

// DeleteFile deletes a file or a directory
func (driver *ClientDriver) DeleteFile(cc ftpserver.ClientContext, path string) error {
	path = driver.baseDir + path
	return os.Remove(path)
}

// RenameFile renames a file or a directory
func (driver *ClientDriver) RenameFile(cc ftpserver.ClientContext, from, to string) error {
	from = driver.baseDir + from
	to = driver.baseDir + to
	return os.Rename(from, to)
}

// (copied from net/http/httptest)
// localhostCert is a PEM-encoded TLS cert with SAN IPs
// "127.0.0.1" and "[::1]", expiring at the last second of 2049 (the end
// of ASN.1 time).
// generated from src/crypto/tls:
// go run generate_cert.go  --rsa-bits 512 --host 127.0.0.1,::1,example.com --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIIBjjCCATigAwIBAgIQMon9v0s3pDFXvAMnPgelpzANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJB
AM0u/mNXKkhAzNsFkwKZPSpC4lZZaePQ55IyaJv3ovMM2smvthnlqaUfVKVmz7FF
wLP9csX6vGtvkZg1uWAtvfkCAwEAAaNoMGYwDgYDVR0PAQH/BAQDAgKkMBMGA1Ud
JQQMMAoGCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8wLgYDVR0RBCcwJYILZXhh
bXBsZS5jb22HBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDQYJKoZIhvcNAQELBQAD
QQBOZsFVC7IwX+qibmSbt2IPHkUgXhfbq0a9MYhD6tHcj4gbDcTXh4kZCbgHCz22
gfSj2/G2wxzopoISVDucuncj
-----END CERTIFICATE-----`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAM0u/mNXKkhAzNsFkwKZPSpC4lZZaePQ55IyaJv3ovMM2smvthnl
qaUfVKVmz7FFwLP9csX6vGtvkZg1uWAtvfkCAwEAAQJART2qkxODLUbQ2siSx7m2
rmBLyR/7X+nLe8aPDrMOxj3heDNl4YlaAYLexbcY8d7VDfCRBKYoAOP0UCP1Vhuf
UQIhAO6PEI55K3SpNIdc2k5f0xz+9rodJCYzu51EwWX7r8ufAiEA3C9EkLiU2NuK
3L3DHCN5IlUSN1Nr/lw8NIt50Yorj2cCIQCDw1VbvCV6bDLtSSXzAA51B4ZzScE7
sHtB5EYF9Dwm9QIhAJuCquuH4mDzVjUntXjXOQPdj7sRqVGCNWdrJwOukat7AiAy
LXLEwb77DIPoI5ZuaXQC+MnyyJj1ExC9RFcGz+bexA==
-----END RSA PRIVATE KEY-----`)
