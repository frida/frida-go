package frida

import "fmt"

// FridaDeviceType is equal to enum FridaDeviceType from frida-core
type DeviceType int

const (
	FRIDA_DEVICE_TYPE_LOCAL  DeviceType = iota // Corresponds to FRIDA_DEVICE_TYPE_LOCAL
	FRIDA_DEVICE_TYPE_REMOTE                   // Corresponds to FRIDA_DEVICE_TYPE_REMOTE
	FRIDA_DEVICE_TYPE_USB                      // Corresponds to FRIDA_DEVICE_TYPE_USB
)

// FridaRealm is equal to enum FridaRealm from frida-core
type Realm int

const (
	FRIDA_REALM_NATIVE   Realm = iota // Native device
	FRIDA_REALM_EMULATED              // Emulated device
)

// FridaScriptRuntime is equal to enum FridaScriptRuntime from frida-core
type ScriptRuntime int

const (
	FRIDA_SCRIPT_RUNTIME_DEFAULT ScriptRuntime = iota // Default frida script runtime
	FRIDA_SCRIPT_RUNTIME_QJS                          // QuickJS
	FRIDA_SCRIPT_RUNTIME_V8                           // V8
)

type Scope int

const (
	FRIDA_SCOPE_MINIMAL Scope = iota
	FRIDA_SCOPE_METADATA
	FRIDA_SCOPE_FULL
)

type Stdio int

const (
	FRIDA_STDIO_INHERIT Stdio = iota
	FRIDA_STDIO_PIPE
)

type Runtime int

const (
	RUNTIME_DEFAULT Runtime = iota
	RUNTIME_QJS
	RUNTIME_V8
)

type ChildOrigin int

const (
	FRIDA_CHILD_ORIGIN_FORK ChildOrigin = iota
	FRIDA_CHILD_ORIGIN_EXEC
	FRIDA_CHILD_ORIGIN_SPAWN
)

type SessionDetachReason int

const (
	FRIDA_SESSION_DETACH_REASON_APPLICATION_REQUESTED SessionDetachReason = iota + 1
	FRIDA_SESSION_DETACH_REASON_PROCESS_REPLACED
	FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED
	FRIDA_SESSION_DETACH_REASON_SERVER_TERMINATED
	FRIDA_SESSION_DETACH_REASON_DEVICE_LOST
)

func (reason SessionDetachReason) String() string {
	return [...]string{"",
		"application-requested",
		"process-replaced",
		"process-terminated",
		"server-terminated",
		"device-list"}[reason]
}

type Address struct {
	Addr string
	Port uint16
}

func (a *Address) String() string {
	return fmt.Sprintf("%s:%d", a.Addr, a.Port)
}
