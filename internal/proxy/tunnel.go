package proxy

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// splice copies bytes in both directions until either side closes or both go
// idle, and reports how much moved each way.
//
// The idle timeout exists because a relay that never reaps silent tunnels
// accumulates them until it runs out of file descriptors, and the clients that
// leave them behind are exactly the ones nobody is watching.
func splice(client, server net.Conn, idle time.Duration) (up, down int64) {
	var upCount, downCount atomic.Int64

	activity := make(chan struct{}, 2)
	touch := func() {
		select {
		case activity <- struct{}{}:
		default:
		}
	}

	done := make(chan struct{})
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			close(done)
			client.Close()
			server.Close()
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := copyWithActivity(server, client, touch)
		upCount.Add(n)
		closeBoth()
	}()
	go func() {
		defer wg.Done()
		n, _ := copyWithActivity(client, server, touch)
		downCount.Add(n)
		closeBoth()
	}()

	if idle > 0 {
		go func() {
			timer := time.NewTimer(idle)
			defer timer.Stop()
			for {
				select {
				case <-done:
					return
				case <-activity:
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					timer.Reset(idle)
				case <-timer.C:
					closeBoth()
					return
				}
			}
		}()
	}

	wg.Wait()
	closeBoth()
	return upCount.Load(), downCount.Load()
}

func copyWithActivity(dst io.Writer, src io.Reader, touch func()) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, err := src.Read(buf)
		if n > 0 {
			touch()
			written, werr := dst.Write(buf[:n])
			total += int64(written)
			if werr != nil {
				return total, werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}

// countingConn tallies bytes crossing an inspected connection, where the copy is
// performed by the HTTP machinery rather than by splice.
type countingConn struct {
	net.Conn
	read    atomic.Int64
	written atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(int64(n))
	return n, err
}

// readerConn lets a connection be read through a bufio.Reader that has already
// consumed part of the stream.
type readerConn struct {
	net.Conn
	r io.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }
