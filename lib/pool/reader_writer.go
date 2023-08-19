package pool

import (
	"errors"
	"io"
)

// RW contains the state for the read/writer
type RW struct {
	pool       *Pool    // pool to get pages from
	pages      [][]byte // backing store
	size       int      // size written
	out        int      // offset we are reading from
	lastOffset int      // size in last page
}

var (
	errInvalidWhence = errors.New("pool.RW Seek: invalid whence")
	errNegativeSeek  = errors.New("pool.RW Seek: negative position")
	errSeekPastEnd   = errors.New("pool.RW Seek: attempt to seek past end of data")
)

// NewRW returns a reader / writer which is backed from pages from the
// pool passed in.
//
// Data can be stored in it by calling Write and read from it by
// calling Read.
//
// When writing it only appends data. Seek only applies to reading.
func NewRW(pool *Pool) *RW {
	return &RW{
		pool:  pool,
		pages: make([][]byte, 0, 16),
	}
}

// Returns the page and offset of i for reading.
//
// Ensure there are pages before calling this.
func (rw *RW) readPage(i int) (page []byte) {
	pageNumber := i / rw.pool.bufferSize
	offset := i % rw.pool.bufferSize
	page = rw.pages[pageNumber]
	// Clip the last page to the amount written
	if pageNumber == len(rw.pages)-1 {
		page = page[:rw.lastOffset]
	}
	return page[offset:]
}

// Read reads up to len(p) bytes into p. It returns the number of
// bytes read (0 <= n <= len(p)) and any error encountered. If some
// data is available but not len(p) bytes, Read returns what is
// available instead of waiting for more.
func (rw *RW) Read(p []byte) (n int, err error) {
	var (
		nn   int
		page []byte
	)
	for len(p) > 0 {
		if rw.out >= rw.size {
			return n, io.EOF
		}
		page = rw.readPage(rw.out)
		nn = copy(p, page)
		p = p[nn:]
		n += nn
		rw.out += nn
	}
	return n, nil
}

// WriteTo writes data to w until there's no more data to write or
// when an error occurs. The return value n is the number of bytes
// written. Any error encountered during the write is also returned.
//
// The Copy function uses WriteTo if available. This avoids an
// allocation and a copy.
func (rw *RW) WriteTo(w io.Writer) (n int64, err error) {
	var (
		nn   int
		page []byte
	)
	for rw.out < rw.size {
		page = rw.readPage(rw.out)
		nn, err = w.Write(page)
		n += int64(nn)
		rw.out += nn
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// Get the page we are writing to
func (rw *RW) writePage() (page []byte) {
	if len(rw.pages) > 0 && rw.lastOffset < rw.pool.bufferSize {
		return rw.pages[len(rw.pages)-1][rw.lastOffset:]
	}
	page = rw.pool.Get()
	rw.pages = append(rw.pages, page)
	rw.lastOffset = 0
	return page
}

// Write writes len(p) bytes from p to the underlying data stream. It returns
// the number of bytes written len(p). It cannot return an error.
func (rw *RW) Write(p []byte) (n int, err error) {
	var (
		nn   int
		page []byte
	)
	for len(p) > 0 {
		page = rw.writePage()
		nn = copy(page, p)
		p = p[nn:]
		n += nn
		rw.size += nn
		rw.lastOffset += nn
	}
	return n, nil
}

// ReadFrom reads data from r until EOF or error. The return value n is the
// number of bytes read. Any error except EOF encountered during the read is
// also returned.
//
// The Copy function uses ReadFrom if available. This avoids an
// allocation and a copy.
func (rw *RW) ReadFrom(r io.Reader) (n int64, err error) {
	var (
		nn   int
		page []byte
	)
	for err == nil {
		page = rw.writePage()
		nn, err = r.Read(page)
		n += int64(nn)
		rw.size += nn
		rw.lastOffset += nn
	}
	if err == io.EOF {
		err = nil
	}
	return n, err
}

// Seek sets the offset for the next Read (not Write - this is always
// appended) to offset, interpreted according to whence: SeekStart
// means relative to the start of the file, SeekCurrent means relative
// to the current offset, and SeekEnd means relative to the end (for
// example, offset = -2 specifies the penultimate byte of the file).
// Seek returns the new offset relative to the start of the file or an
// error, if any.
//
// Seeking to an offset before the start of the file is an error. Seeking
// beyond the end of the written data is an error.
func (rw *RW) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	size := int64(rw.size)
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = int64(rw.out) + offset
	case io.SeekEnd:
		abs = size + offset
	default:
		return 0, errInvalidWhence
	}
	if abs < 0 {
		return 0, errNegativeSeek
	}
	if abs > size {
		return offset - (abs - size), errSeekPastEnd
	}
	rw.out = int(abs)
	return abs, nil
}

// Close the buffer returning memory to the pool
func (rw *RW) Close() error {
	for _, page := range rw.pages {
		rw.pool.Put(page)
	}
	rw.pages = nil
	return nil
}

// Size returns the number of bytes in the buffer
func (rw *RW) Size() int64 {
	return int64(rw.size)
}

// Check interfaces
var (
	_ io.Reader     = (*RW)(nil)
	_ io.ReaderFrom = (*RW)(nil)
	_ io.Writer     = (*RW)(nil)
	_ io.WriterTo   = (*RW)(nil)
	_ io.Seeker     = (*RW)(nil)
	_ io.Closer     = (*RW)(nil)
)
