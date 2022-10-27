package frida

//#include <frida-core.h>
import "C"

type Spawn struct {
	spawn *C.FridaSpawn
}

// GetPid returns process id of the spawn
func (s *Spawn) GetPid() int {
	return int(C.frida_spawn_get_pid(s.spawn))
}

// GetIdentifier returns identifier of the spawn
func (s *Spawn) GetIdentifier() string {
	return C.GoString(C.frida_spawn_get_identifier(s.spawn))
}
