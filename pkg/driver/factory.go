package driver

import (
	"fmt"
	"runtime"
)

// New creates a new sandbox driver based on the platform
func New(driverType string) (SandboxDriver, error) {
	switch driverType {
	case "bwrap", "bubblewrap":
		return NewChrootDriver(), nil
	case "lima":
		return NewLimaDriver(), nil
	case "auto":
		// Auto-detect based on platform
		switch runtime.GOOS {
		case "linux", "android":
			return NewChrootDriver(), nil
		case "darwin", "windows":
			return NewLimaDriver(), nil
		default:
			return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
		}
	default:
		return nil, fmt.Errorf("unsupported driver: %s", driverType)
	}
}

// SupportedDrivers returns a list of supported drivers for the current platform
func SupportedDrivers() []string {
	switch runtime.GOOS {
	case "linux", "android":
		return []string{"bwrap", "lima", "auto"}
	case "darwin", "windows":
		return []string{"lima", "auto"}
	default:
		return []string{"auto"}
	}
}