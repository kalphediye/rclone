// Build for cmount for unsupported platforms to stop go complaining
// about "no buildable Go source files "

// +build !linux,!darwin,!freebsd,!windows !brew !cgo !cmount

package cmount
