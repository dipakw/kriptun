package shared

import (
	"encoding/binary"
	"errors"
)

func (t *Target) Pack() ([]byte, error) {
	buf := make([]byte, 1+len(t.Net)+1+len(t.Host)+2+2+2+2+2+2+2)
	idx := 0

	// Write net size
	if len(t.Net) > 8 {
		return nil, errors.New("net size is too big")
	}

	buf[idx] = byte(uint8(len(t.Net)))
	idx++

	// Write net
	copy(buf[idx:], t.Net)
	idx += len(t.Net)

	// Write host size
	if len(t.Host) > 255 {
		return nil, errors.New("host size is too big")
	}

	buf[idx] = byte(uint8(len(t.Host)))
	idx++

	// Write host
	copy(buf[idx:], t.Host)
	idx += len(t.Host)

	// Write port
	binary.BigEndian.PutUint16(buf[idx:], t.Port)
	idx += 2

	// Write read timeoutA
	binary.BigEndian.PutUint16(buf[idx:], t.RToA)
	idx += 2

	// Write read timeoutB
	binary.BigEndian.PutUint16(buf[idx:], t.RToB)
	idx += 2

	// Write write timeoutA
	binary.BigEndian.PutUint16(buf[idx:], t.WToA)
	idx += 2

	// Write write timeoutB
	binary.BigEndian.PutUint16(buf[idx:], t.WToB)
	idx += 2

	// Write connect timeoutA
	binary.BigEndian.PutUint16(buf[idx:], t.CToA)
	idx += 2

	// Write connect timeoutB
	binary.BigEndian.PutUint16(buf[idx:], t.CToB)
	idx += 2

	return buf, nil
}

func (t *Target) Unpack(buf []byte) (*Target, error) {
	malformed := errors.New("malformed target")

	idx := 0
	siz := int(buf[idx])
	idx++
	end := idx + siz

	if end > len(buf) {
		return nil, malformed
	}

	// Read net size
	if siz > 8 {
		return nil, errors.New("net size is too big")
	}

	t.Net = string(buf[idx:end])
	idx = end

	// Read host size
	if idx >= len(buf) {
		return nil, malformed
	}

	siz = int(buf[idx])
	idx++
	end = idx + siz

	if end > len(buf) {
		return nil, malformed
	}

	t.Host = string(buf[idx:end])
	idx = end

	// Read port
	if idx >= len(buf) {
		return nil, malformed
	}

	end = idx + 2

	if end > len(buf) {
		return nil, malformed
	}

	t.Port = binary.BigEndian.Uint16(buf[idx:end])
	idx = end

	// Read read timeoutA
	if idx >= len(buf) {
		return nil, malformed
	}

	end = idx + 2

	if end > len(buf) {
		return nil, malformed
	}

	t.RToA = binary.BigEndian.Uint16(buf[idx:end])
	idx = end

	// Read read timeoutB
	if idx >= len(buf) {
		return nil, malformed
	}

	end = idx + 2

	if end > len(buf) {
		return nil, malformed
	}

	t.RToB = binary.BigEndian.Uint16(buf[idx:end])
	idx = end

	// Read write timeoutA
	if idx >= len(buf) {
		return nil, malformed
	}

	end = idx + 2

	if end > len(buf) {
		return nil, malformed
	}

	t.WToA = binary.BigEndian.Uint16(buf[idx:end])
	idx = end

	// Read write timeoutB
	if idx >= len(buf) {
		return nil, malformed
	}

	end = idx + 2

	if end > len(buf) {
		return nil, malformed
	}

	t.WToB = binary.BigEndian.Uint16(buf[idx:end])
	idx = end

	// Read connect timeoutA
	if idx >= len(buf) {
		return nil, malformed
	}

	end = idx + 2

	if end > len(buf) {
		return nil, malformed
	}

	t.CToA = binary.BigEndian.Uint16(buf[idx:end])
	idx = end

	// Read connect timeoutB
	if idx >= len(buf) {
		return nil, malformed
	}

	end = idx + 2

	t.CToB = binary.BigEndian.Uint16(buf[idx:end])
	idx = end

	return t, nil
}
