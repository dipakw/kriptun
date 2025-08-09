package server

import (
	"context"
	"net"
	"time"
)

const (
	MAX_UDP_PACKET_SIZE = 65507
	MAX_UDP_TIMEOUT     = 60
)

type RelayOptsUDP struct {
	Src net.Conn
	Dst *net.UDPConn

	RToS uint16 // Source read timeout (milliseconds)
	WToS uint16 // Source write timeout (milliseconds)
	RToD uint16 // Destination read timeout (milliseconds)
	WToD uint16 // Destination write timeout (milliseconds)

	// s -> 0 = source, 1 = destination
	// o -> 0 = read, 1 = write
	// n -> number of bytes
	Report func(s uint8, o uint8, n int)
}

// relayUDP relays UDP packets between source and destination with timeouts and bandwidth tracking
func relayUDP(ctx context.Context, opts *RelayOptsUDP) error {
	if opts == nil || opts.Src == nil || opts.Dst == nil {
		return net.ErrClosed
	}

	// Create a cancelable context to handle cleanup
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Convert timeouts to time.Duration
	srcReadTimeout := time.Duration(opts.RToS) * time.Second
	srcWriteTimeout := time.Duration(opts.WToS) * time.Second
	dstReadTimeout := time.Duration(opts.RToD) * time.Second
	dstWriteTimeout := time.Duration(opts.WToD) * time.Second

	// Error channel to handle errors from goroutines
	errChan := make(chan error, 2)

	// Read from source and write to destination
	go func() {
		defer cancel() // Cancel context when goroutine exits
		buf := make([]byte, MAX_UDP_PACKET_SIZE)

		for {
			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				// Set read deadline
				if srcReadTimeout > 0 {
					if err := opts.Src.SetReadDeadline(time.Now().Add(srcReadTimeout)); err != nil {
						errChan <- err
						return
					}
				}

				n, err := opts.Src.Read(buf)
				if err != nil {
					errChan <- err
					return
				}

				// Report bytes read from source
				if opts.Report != nil {
					go opts.Report(0, 0, n)
				}

				// Set write deadline for destination
				if dstWriteTimeout > 0 {
					if err := opts.Dst.SetWriteDeadline(time.Now().Add(dstWriteTimeout)); err != nil {
						errChan <- err
						return
					}
				}

				_, err = opts.Dst.Write(buf[:n])
				if err != nil {
					errChan <- err
					return
				}

				// Report bytes written to destination
				if opts.Report != nil {
					go opts.Report(1, 1, n)
				}
			}
		}
	}()

	// Read from destination and write to source
	go func() {
		defer cancel() // Cancel context when goroutine exits
		buf := make([]byte, MAX_UDP_PACKET_SIZE)

		for {
			select {
			case <-ctx.Done():
				errChan <- ctx.Err()
				return
			default:
				// Set read deadline for destination
				if dstReadTimeout > 0 {
					if err := opts.Dst.SetReadDeadline(time.Now().Add(dstReadTimeout)); err != nil {
						errChan <- err
						return
					}
				}

				n, _, err := opts.Dst.ReadFromUDP(buf)
				if err != nil {
					errChan <- err
					return
				}

				// Report bytes read from destination
				if opts.Report != nil {
					go opts.Report(1, 0, n)
				}

				// Set write deadline for source
				if srcWriteTimeout > 0 {
					if err := opts.Src.SetWriteDeadline(time.Now().Add(srcWriteTimeout)); err != nil {
						errChan <- err
						return
					}
				}

				_, err = opts.Src.Write(buf[:n])
				if err != nil {
					errChan <- err
					return
				}

				// Report bytes written to source
				if opts.Report != nil {
					go opts.Report(0, 1, n)
				}
			}
		}
	}()

	// Wait for an error or context cancellation
	select {
	case err := <-errChan:
		// Close both connections on error
		opts.Src.Close()
		opts.Dst.Close()
		return err
	case <-ctx.Done():
		// Close both connections on context cancellation
		opts.Src.Close()
		opts.Dst.Close()
		return ctx.Err()
	}
}
