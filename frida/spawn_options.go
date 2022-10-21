package frida

//#include <frida-core.h>
import "C"
import (
	"fmt"
	"unsafe"
)

type SpawnOptions struct {
	opts *C.FridaSpawnOptions
}

func NewFridaSpawnOptions() *SpawnOptions {
	opts := C.frida_spawn_options_new()
	return &SpawnOptions{
		opts: opts,
	}
}

func (f *SpawnOptions) SetArgv(argv []string) {
	arr, len := stringSliceToCharArr(argv)

	C.frida_spawn_options_set_argv(f.opts, arr, len)
}

func (f *SpawnOptions) GetArgv() []string {
	var count C.gint
	argvC := C.frida_spawn_options_get_argv(f.opts, &count)

	argv := cArrayToStringSlice(argvC, C.int(count))

	return argv
}

func (f *SpawnOptions) SetEnvp(envp map[string]string) {
	var s []string

	for k, v := range envp {
		s = append(s, fmt.Sprintf("%s=%s"), k, v)
	}

	arr, len := stringSliceToCharArr(s)
	C.frida_spawn_options_set_envp(f.opts, arr, len)
}

func (f *SpawnOptions) GetEnvp() []string {
	var count C.gint
	envpC := C.frida_spawn_options_get_argv(f.opts, &count)

	envp := cArrayToStringSlice(envpC, C.int(count))

	return envp
}

func (f *SpawnOptions) SetEnv(env map[string]string) {
	var s []string

	for k, v := range env {
		s = append(s, fmt.Sprintf("%s=%s"), k, v)
	}

	arr, len := stringSliceToCharArr(s)
	C.frida_spawn_options_set_env(f.opts, arr, len)
}

func (f *SpawnOptions) GetEnv() []string {
	var count C.gint
	envpC := C.frida_spawn_options_get_env(f.opts, &count)

	env := cArrayToStringSlice(envpC, C.int(count))

	return env
}

func (f *SpawnOptions) SetCwd(cwd string) {
	cwdC := C.CString(cwd)
	defer C.free(unsafe.Pointer(cwdC))

	C.frida_spawn_options_set_cwd(f.opts, cwdC)
}

func (f *SpawnOptions) GetCwd() string {
	return C.GoString(C.frida_spawn_options_get_cwd(f.opts))
}

func (f *SpawnOptions) SetStdio(stdio Stdio) {
	C.frida_spawn_options_set_stdio(f.opts, C.FridaStdio(stdio))
}

func (f *SpawnOptions) GetStdio() Stdio {
	return Stdio(int(C.frida_spawn_options_get_stdio(f.opts)))
}
