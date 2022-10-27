package frida

//#include <frida-core.h>
import "C"
import (
	"fmt"
	"unsafe"
)

// SpawnOptions struct is responsible for setting/getting argv, envp etc
type SpawnOptions struct {
	opts *C.FridaSpawnOptions
}

// NewSpawnOptions create new instance of SpawnOptions.
func NewSpawnOptions() *SpawnOptions {
	opts := C.frida_spawn_options_new()
	return &SpawnOptions{
		opts: opts,
	}
}

// SetArgv set spawns argv with the argv provided.
func (s *SpawnOptions) SetArgv(argv []string) {
	arr, len := stringSliceToCharArr(argv)

	C.frida_spawn_options_set_argv(s.opts, arr, len)
}

// GetArgv returns argv of the spawn.
func (s *SpawnOptions) GetArgv() []string {
	var count C.gint
	argvC := C.frida_spawn_options_get_argv(s.opts, &count)

	argv := cArrayToStringSlice(argvC, C.int(count))

	return argv
}

// SetEnvp set spawns envp with the envp provided.
func (s *SpawnOptions) SetEnvp(envp map[string]string) {
	var sl []string

	for k, v := range envp {
		sl = append(sl, fmt.Sprintf("%s=%s", k, v))
	}

	arr, len := stringSliceToCharArr(sl)
	C.frida_spawn_options_set_envp(s.opts, arr, len)
}

// GetEnvp returns envp of the spawn.
func (s *SpawnOptions) GetEnvp() []string {
	var count C.gint
	envpC := C.frida_spawn_options_get_argv(s.opts, &count)

	envp := cArrayToStringSlice(envpC, C.int(count))

	return envp
}

// SetEnv set spawns env with the env provided.
func (s *SpawnOptions) SetEnv(env map[string]string) {
	var sl []string

	for k, v := range env {
		sl = append(sl, fmt.Sprintf("%s=%s", k, v))
	}

	arr, len := stringSliceToCharArr(sl)
	C.frida_spawn_options_set_env(s.opts, arr, len)
}

// GetEnv returns env of the spawn.
func (s *SpawnOptions) GetEnv() []string {
	var count C.gint
	envpC := C.frida_spawn_options_get_env(s.opts, &count)

	env := cArrayToStringSlice(envpC, C.int(count))

	return env
}

// SetCwd sets current working directory (CWD) for the spawn.
func (s *SpawnOptions) SetCwd(cwd string) {
	cwdC := C.CString(cwd)
	defer C.free(unsafe.Pointer(cwdC))

	C.frida_spawn_options_set_cwd(s.opts, cwdC)
}

// GetCwd returns current working directory (CWD) of the spawn.
func (s *SpawnOptions) GetCwd() string {
	return C.GoString(C.frida_spawn_options_get_cwd(s.opts))
}

// SetStdio sets standard input/output of the spawn with the stdio provided.
func (s *SpawnOptions) SetStdio(stdio Stdio) {
	C.frida_spawn_options_set_stdio(s.opts, C.FridaStdio(stdio))
}

// GetStdio returns spawns stdio.
func (s *SpawnOptions) GetStdio() Stdio {
	return Stdio(int(C.frida_spawn_options_get_stdio(s.opts)))
}

// TODO
func (s *SpawnOptions) SetAux(aux map[string]interface{}) {

}

// GetAux returns aux of the spawn.
func (s *SpawnOptions) GetAux() map[string]interface{} {
	ht := C.frida_spawn_get_aux(s.opts)
	aux := gHashTableToMap(ht)
	return aux
}
