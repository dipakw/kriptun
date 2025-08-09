package server

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

type RelayOptsTCP struct {
	Src net.Conn
	Dst net.Conn

	RToS uint16 // Source read timeout
	WToS uint16 // Source write timeout
	RToD uint16 // Destination read timeout
	WToD uint16 // Destination write timeout

	// s -> 0 = source, 1 = destination
	// o -> 0 = read, 1 = write
	// n -> number of bytes
	Report func(s uint8, o uint8, n int)
}

// trackedConn wraps a net.Conn to manage timeouts and track bytes
type trackedConn struct {
	conn    net.Conn
	readTO  time.Duration
	writeTO time.Duration
	report  func(s uint8, d uint8, n int)
	source  uint8 // 0 for source, 1 for destination
}

func newTrackedConnTCP(conn net.Conn, readTO, writeTO uint16, report func(s uint8, d uint8, n int), source uint8) *trackedConn {
	return &trackedConn{
		conn:    conn,
		readTO:  time.Duration(readTO) * time.Second,
		writeTO: time.Duration(writeTO) * time.Second,
		report:  report,
		source:  source,
	}
}

func (tc *trackedConn) Read(b []byte) (n int, err error) {
	if tc.readTO > 0 {
		if err := tc.conn.SetReadDeadline(time.Now().Add(tc.readTO)); err != nil {
			return 0, err
		}
	}
	n, err = tc.conn.Read(b)
	if err == nil && tc.readTO > 0 {
		// Renew deadline on successful read
		if err := tc.conn.SetReadDeadline(time.Now().Add(tc.readTO)); err != nil {
			return n, err
		}
	}
	if n > 0 && tc.report != nil {
		go tc.report(tc.source, 0, n) // Report read bytes
	}
	return n, err
}

func (tc *trackedConn) Write(b []byte) (n int, err error) {
	if tc.writeTO > 0 {
		if err := tc.conn.SetWriteDeadline(time.Now().Add(tc.writeTO)); err != nil {
			return 0, err
		}
	}
	n, err = tc.conn.Write(b)
	if err == nil && tc.writeTO > 0 {
		// Renew deadline on successful write
		if err := tc.conn.SetWriteDeadline(time.Now().Add(tc.writeTO)); err != nil {
			return n, err
		}
	}
	if n > 0 && tc.report != nil {
		go tc.report(tc.source, 1, n) // Report written bytes
	}
	return n, err
}

func (tc *trackedConn) Close() error {
	return tc.conn.Close()
}

func relayTCP(ctx context.Context, opts *RelayOptsTCP) error {
	var wg sync.WaitGroup
	wg.Add(2)

	// Create wrapped connections with timeout and byte counting
	srcConn := newTrackedConnTCP(opts.Src, opts.RToS, opts.WToS, opts.Report, 0)
	dstConn := newTrackedConnTCP(opts.Dst, opts.RToD, opts.WToD, opts.Report, 1)

	// Channel to capture errors from copy operations
	errCh := make(chan error, 2)
	// Channel to signal when either connection is closed or context is done
	done := make(chan struct{}, 1)

	// Copy from src to dst
	go func() {
		defer wg.Done()
		defer dstConn.Close()

		_, err := io.Copy(dstConn, srcConn)
		if err != nil {
			select {
			case errCh <- err:
			case done <- struct{}{}:
			default:
			}
		}
	}()

	// Copy from dst to src
	go func() {
		defer wg.Done()
		defer srcConn.Close()

		_, err := io.Copy(srcConn, dstConn)
		if err != nil {
			select {
			case errCh <- err:
			case done <- struct{}{}:
			default:
			}
		}
	}()

	// Handle context cancellation and errors
	go func() {
		select {
		case <-ctx.Done():
			errCh <- ctx.Err()
		case <-done:
		}
		srcConn.Close()
		dstConn.Close()
	}()

	// Wait for both copy operations to complete
	wg.Wait()

	// Check for any errors
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}
