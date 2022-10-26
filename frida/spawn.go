package frida

//#include <frida-core.h>
import "C"

type Spawn struct {
	spawn *C.FridaSpawn
}

func (s *Spawn) GetPid() int {
	return int(C.frida_spawn_get_pid(s.spawn))
}

func (s *Spawn) GetIdentifier() string {
	return C.GoString(C.frida_spawn_get_identifier(s.spawn))
}
