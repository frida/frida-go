package frida

import "fmt"

type DeviceType int

const (
	DEVICE_TYPE_LOCAL DeviceType = iota
	DEVICE_TYPE_REMOTE
	DEVICE_TYPE_USB
)

func (d DeviceType) String() string {
	return [...]string{"local",
		"remote",
		"usb"}[d]
}

type Realm int

const (
	REALM_NATIVE Realm = iota
	REALM_EMULATED
)

func (r Realm) String() string {
	return [...]string{"native",
		"emulated"}[r]
}

type ScriptRuntime int

const (
	SCRIPT_RUNTIME_DEFAULT ScriptRuntime = iota
	SCRIPT_RUNTIME_QJS
	SCRIPT_RUNTIME_V8
)

func (s ScriptRuntime) String() string {
	return [...]string{"default",
		"qjs",
		"v8"}[s]
}

type Scope int

const (
	SCOPE_MINIMAL Scope = iota
	SCOPE_METADATA
	SCOPE_FULL
)

func (s Scope) String() string {
	return [...]string{"minimal",
		"metadata",
		"full"}[s]
}

type Stdio int

const (
	STDIO_INHERIT Stdio = iota
	STDIO_PIPE
)

func (s Stdio) String() string {
	return [...]string{"inherit",
		"pipe"}[s]
}

type Runtime int

const (
	RUNTIME_DEFAULT Runtime = iota
	RUNTIME_QJS
	RUNTIME_V8
)

func (r Runtime) String() string {
	return [...]string{"default",
		"qjs",
		"v8"}[r]
}

type ChildOrigin int

const (
	CHILD_ORIGIN_FORK ChildOrigin = iota
	CHILD_ORIGIN_EXEC
	CHILD_ORIGIN_SPAWN
)

func (origin ChildOrigin) String() string {
	return [...]string{"fork",
		"exec",
		"spawn"}[origin]
}

type RelayKind int

const (
	RELAY_KIND_TURN_UDP RelayKind = iota
	RELAY_KIND_TURN_TCP
	RELAY_KIND_TURN_TLS
)

func (kind RelayKind) String() string {
	return [...]string{"turn-udp",
		"turn-tcp",
		"turn-tls"}[kind]
}

type SessionDetachReason int

const (
	SESSION_DETACH_REASON_APPLICATION_REQUESTED SessionDetachReason = iota + 1
	SESSION_DETACH_REASON_PROCESS_REPLACED
	SESSION_DETACH_REASON_PROCESS_TERMINATED
	SESSION_DETACH_REASON_SERVER_TERMINATED
	SESSION_DETACH_REASON_DEVICE_LOST
)

func (reason SessionDetachReason) String() string {
	return [...]string{"",
		"application-requested",
		"process-replaced",
		"process-terminated",
		"server-terminated",
		"device-list"}[reason]
}

// Address represents structure returned by some specific signals
type Address struct {
	Addr string
	Port uint16
}

// String representation of Address in format ADDR:PORT
func (a *Address) String() string {
	return fmt.Sprintf("%s:%d", a.Addr, a.Port)
}
