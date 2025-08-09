package shared

import (
	"fmt"
	"testing"
)

func TestTargetPackUnpack(t *testing.T) {
	target := &Target{
		Net:  "tcp",
		Host: "www.example.com",
		Port: 8080,
		RToA: 111,
		RToB: 222,
		WToA: 333,
		WToB: 444,
		CToA: 555,
		CToB: 666,
	}

	buf, err := target.Pack()

	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Packed:", buf)

	unpacked, err := (&Target{}).Unpack(buf)

	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("Unpacked: %+v\n", unpacked)
}
