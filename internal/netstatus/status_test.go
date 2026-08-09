package netstatus

import (
	"fmt"
	"syscall"
	"testing"
)

func TestKindOfClassifiesPortableAndWinsockErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want Kind
	}{
		{name: "portable refused", err: syscall.ECONNREFUSED, want: ConnectionRefused},
		{name: "Winsock refused", err: fmt.Errorf("dial: %w", syscall.Errno(10061)), want: ConnectionRefused},
		{name: "Winsock network", err: syscall.Errno(10051), want: NetworkUnreachable},
		{name: "Winsock host", err: syscall.Errno(10065), want: HostUnreachable},
		{name: "Winsock timeout", err: syscall.Errno(10060), want: Timeout},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := KindOf(test.err); got != test.want {
				t.Fatalf("KindOf() = %v, want %v", got, test.want)
			}
		})
	}
}
