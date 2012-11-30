package nagios

import (
	"fmt"
	"os"
)

// From https://github.com/laziac/go-nagios
type Status int

const (
	OK Status = iota
	WARNING
	CRITICAL
	UNKNOWN
)

var (
	Service   string = "UNDEFINED"
	Verbosity uint   = 0
)

func (status Status) String() string {
	switch status {
	case OK:
		return "OK"
	case WARNING:
		return "WARNING"
	case CRITICAL:
		return "CRITICAL"
	case UNKNOWN:
		return "UNKNOWN"
	}
	return "UNDEFINED"
}

func ExitStatus(status Status, msg string, extraMessages []string, forceDisplay bool) {
	fmt.Printf("%s %s: %s\n", Service, status.String(), msg)
	if forceDisplay || (Verbosity >= 2) {
		for i := 0; i < len(extraMessages); i++ {
			fmt.Printf("%s\n", extraMessages[i])
		}
	}
	os.Exit(int(status))
}
