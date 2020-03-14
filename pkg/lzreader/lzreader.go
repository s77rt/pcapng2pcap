package lzreader

import (
	"os"
	"io"
	"io/ioutil"
	gzip "github.com/klauspost/pgzip"
)

type FILE struct {
	Handler *os.File // pointer to the file handler
	Data []byte // unused data
	Buff []byte // in use data
}

func (file *FILE) Load() {
	file.Data, _ = ioutil.ReadAll(file.Handler)
	return
}

func (file *FILE) LoadGZIP() {
	gz, _ := gzip.NewReader(file.Handler)
	defer gz.Close()
	file.Data, _ = ioutil.ReadAll(gz)
	return
}

func (file *FILE) Read(nbytes int64) (error) {
	if int64(len(file.Data)) < nbytes {
		return io.EOF
	} else {
		file.Buff, file.Data = file.Data[:nbytes], file.Data[nbytes:]
	}
	return nil
}
