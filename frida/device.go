package frida

//#include <frida-core.h>
import "C"
import (
	"errors"
	"reflect"
	"sort"
	"unsafe"
)

const (
	defaultProcesstimeout = 10
)

// Device represents FridaDevice struct from frida-core
type Device struct {
	device *C.FridaDevice
}

// GetID will return the ID of the device.
func (d *Device) GetID() string {
	return C.GoString(C.frida_device_get_id(d.device))
}

// GetName will return the name of the device.
func (d *Device) GetName() string {
	return C.GoString(C.frida_device_get_name(d.device))
}

// GetDeviceIcon will return the device icon.
func (d *Device) GetDeviceIcon() *C.GVariant {
	var icon *C.GVariant
	icon = C.frida_device_get_icon(d.device)
	dt := gPointerToGo((C.gpointer)(icon))
	_ = dt
	return icon
}

// GetDeviceType returns type of the device.
func (d *Device) GetDeviceType() DeviceType {
	fdt := C.frida_device_get_dtype(d.device)
	return DeviceType(fdt)
}

// GetBus returns device bus.
func (d *Device) GetBus() *Bus {
	bus := C.frida_device_get_bus(d.device)
	return &Bus{
		bus: bus,
	}
}

// GetManager returns device manager for the device.
func (d *Device) GetManager() *DeviceManager {
	mgr := C.frida_device_get_manager(d.device)
	return &DeviceManager{mgr}
}

// IsLost returns boolean whether device is lost or not.
func (d *Device) IsLost() bool {
	lost := C.frida_device_is_lost(d.device)
	if int(lost) == 1 {
		return true
	}
	return false
}

// Params returns system parameters of the device
func (d *Device) Params() (map[string]interface{}, error) {
	var err *C.GError
	ht := C.frida_device_query_system_parameters_sync(d.device, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}

	params := gHashTableToMap(ht)

	return params, nil
}

// GetFrontMostApplication will return the frontmost application or the application in focus
// on the device.
func (d *Device) GetFrontmostApplication(scope Scope) (*Application, error) {
	var err *C.GError
	app := &Application{}

	sc := C.FridaScope(scope)
	queryOpts := C.frida_frontmost_query_options_new()
	C.frida_frontmost_query_options_set_scope(queryOpts, sc)
	app.application = C.frida_device_get_frontmost_application_sync(d.device,
		queryOpts,
		nil,
		&err)
	if err != nil {
		return nil, &FridaError{err}
	}

	if app.application == nil {
		return nil, errors.New("Could not obtain frontmost application! Is any application started?")
	}

	return app, nil
}

// EnumerateApplications will return slice of applications on the device
func (d *Device) EnumerateApplications(identifier string, scope Scope) ([]*Application, error) {
	queryOpts := C.frida_application_query_options_new()
	C.frida_application_query_options_set_scope(queryOpts, C.FridaScope(scope))

	if identifier != "" {
		identifierC := C.CString(identifier)
		defer C.free(unsafe.Pointer(identifierC))
		C.frida_application_query_options_select_identifier(queryOpts, identifierC)
	}

	var err *C.GError
	appList := C.frida_device_enumerate_applications_sync(d.device, queryOpts, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}

	var apps []*Application

	for i := 0; i < int(C.frida_application_list_size(appList)); i++ {
		app := C.frida_application_list_get(appList, C.gint(i))
		apps = append(apps, &Application{app})
	}

	sort.Slice(apps, func(i, j int) bool {
		return apps[i].GetPid() > apps[j].GetPid()
	})

	return apps, nil
}

// GetProcessByPid returns the process by passed pid.
func (d *Device) GetProcessByPid(pid int, scope Scope) (*Process, error) {
	opts := C.frida_process_match_options_new()
	C.frida_process_match_options_set_timeout(opts, C.gint(defaultProcesstimeout))
	C.frida_process_match_options_set_scope(opts, C.FridaScope(scope))

	var err *C.GError
	proc := C.frida_device_get_process_by_pid_sync(d.device, C.guint(pid), opts, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}
	return &Process{proc}, nil
}

// GetProcessByName returns the process by passed name.
func (d *Device) GetProcessByName(name string, scope Scope) (*Process, error) {
	nameC := C.CString(name)
	defer C.free(unsafe.Pointer(nameC))

	opts := C.frida_process_match_options_new()
	C.frida_process_match_options_set_timeout(opts, C.gint(defaultProcesstimeout))
	C.frida_process_match_options_set_scope(opts, C.FridaScope(scope))

	var err *C.GError
	proc := C.frida_device_get_process_by_name_sync(d.device, nameC, opts, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}
	return &Process{proc}, nil
}

// FindDeviceById will try to find the process with given pid.
func (d *Device) FindProcessByPid(pid int, scope Scope) (*Process, error) {
	opts := C.frida_process_match_options_new()
	C.frida_process_match_options_set_timeout(opts, C.gint(defaultProcesstimeout))
	C.frida_process_match_options_set_scope(opts, C.FridaScope(scope))

	var err *C.GError
	proc := C.frida_device_find_process_by_pid_sync(d.device, C.guint(pid), opts, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}
	return &Process{proc}, nil
}

// FindProcessByName will try to find the process with name specified.
func (d *Device) FindProcessByName(name string, scope Scope) (*Process, error) {
	nameC := C.CString(name)
	defer C.free(unsafe.Pointer(nameC))

	opts := C.frida_process_match_options_new()
	C.frida_process_match_options_set_timeout(opts, C.gint(defaultProcesstimeout))
	C.frida_process_match_options_set_scope(opts, C.FridaScope(scope))

	var err *C.GError
	proc := C.frida_device_find_process_by_name_sync(d.device, nameC, opts, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}
	return &Process{proc}, nil
}

// EnumerateProcesses will slice of processes running with scope provided
func (d *Device) EnumerateProcesses(scope Scope) ([]*Process, error) {
	opts := C.frida_process_query_options_new()
	C.frida_process_query_options_set_scope(opts, C.FridaScope(scope))

	var err *C.GError
	procList := C.frida_device_enumerate_processes_sync(d.device, opts, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}

	var procs []*Process

	for i := 0; i < int(C.frida_process_list_size(procList)); i++ {
		proc := C.frida_process_list_get(procList, C.gint(i))
		procs = append(procs, &Process{proc})
	}

	return procs, nil
}

// EnableSpawnGating will enable spawn gating on the device.
func (d *Device) EnableSpawnGating() error {
	var err *C.GError
	C.frida_device_enable_spawn_gating_sync(d.device, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

// DisableSpawnGating will disable spawn gating on the device.
func (d *Device) DisableSpawnGating() error {
	var err *C.GError
	C.frida_device_disable_spawn_gating_sync(d.device, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

// EnumeratePendingSpawn will return the slice of pending spawns.
func (d *Device) EnumeratePendingSpawn() ([]*Spawn, error) {
	var err *C.GError
	spawnList := C.frida_device_enumerate_pending_spawn_sync(d.device, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}

	var spawns []*Spawn

	for i := 0; i < int(C.frida_spawn_list_size(spawnList)); i++ {
		spawn := C.frida_spawn_list_get(spawnList, C.gint(i))
		spawns = append(spawns, &Spawn{spawn})
	}

	return spawns, nil
}

// EnumeratePendingChildren will return the slice of pending children.
func (d *Device) EnumeratePendingChildren() ([]*Child, error) {
	var err *C.GError
	childList := C.frida_device_enumerate_pending_children_sync(d.device, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}

	var childs []*Child

	for i := 0; i < int(C.frida_child_list_size(childList)); i++ {
		chld := C.frida_child_list_get(childList, C.gint(i))
		c := &Child{
			child: chld,
		}
		childs = append(childs, c)
	}

	return childs, nil
}

// Spawn will spawn an application or binary.
func (d *Device) Spawn(name string, opts *SpawnOptions) (int, error) {
	var opt *C.FridaSpawnOptions = nil
	if opts != nil {
		opt = opts.opts
	}

	var err *C.GError
	pid := C.frida_device_spawn_sync(d.device, C.CString(name), opt, nil, &err)
	if err != nil {
		return -1, &FridaError{err}
	}

	return int(pid), nil
}

// Input inputs []bytes into the process with pid specified.
func (d *Device) Input(pid int, data []byte) error {
	arr, len := uint8ArrayFromByteSlice(data)
	defer C.free(unsafe.Pointer(arr))
	gBytesData := C.g_bytes_new((C.gconstpointer)(unsafe.Pointer(arr)), C.gsize(len))
	defer clean(unsafe.Pointer(gBytesData), CleanPOD)

	var err *C.GError
	C.frida_device_input_sync(d.device, C.guint(pid), gBytesData, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

// Resume will resume the process with pid.
func (d *Device) Resume(pid int) error {
	var err *C.GError
	C.frida_device_resume_sync(d.device, C.guint(pid), nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

// Kill kills process with pid specified.
func (d *Device) Kill(pid int) error {
	var err *C.GError
	C.frida_device_kill_sync(d.device, C.guint(pid), nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

// Attach will attach on specified process name or PID.
// You can pass the nil as SessionOptions or you can create it if you want
// the session to persist for specific timeout.
func (d *Device) Attach(val interface{}, opts *SessionOptions) (*Session, error) {
	var pid int
	switch v := reflect.ValueOf(val); v.Kind() {
	case reflect.String:
		proc, err := d.GetProcessByName(val.(string), SCOPE_MINIMAL)
		if err != nil {
			return nil, err
		}
		pid = proc.GetPid()
	case reflect.Int:
		pid = val.(int)
	default:
		return nil, errors.New("Expected name of app/process or PID")
	}

	var opt *C.FridaSessionOptions = nil
	if opts != nil {
		opt = opts.opts
	}

	var err *C.GError
	s := C.frida_device_attach_sync(d.device, C.guint(pid), opt, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}
	return &Session{s}, nil
}

// InjectLibraryFile will inject the library in the target with path to library specified.
// Entrypoint is the entrypoint to the library and the data is any data you need to pass
// to the library.
func (d *Device) InjectLibraryFile(target interface{}, path, entrypoint, data string) (uint, error) {
	var pid int
	switch v := reflect.ValueOf(target); v.Kind() {
	case reflect.String:
		proc, err := d.GetProcessByName(target.(string), SCOPE_MINIMAL)
		if err != nil {
			return 0, err
		}
		pid = proc.GetPid()
	case reflect.Int:
		pid = target.(int)
	default:
		return 0, errors.New("Expected name of app/process or PID")
	}

	if path == "" {
		return 0, errors.New("You need to provide path to library")
	}

	var pathC *C.char
	var entrypointC *C.char = nil
	var dataC *C.char = nil

	pathC = C.CString(path)
	defer C.free(unsafe.Pointer(pathC))

	if entrypoint != "" {
		entrypointC = C.CString(entrypoint)
		defer C.free(unsafe.Pointer(entrypointC))
	}

	if data != "" {
		dataC = C.CString(data)
		defer C.free(unsafe.Pointer(dataC))
	}

	var err *C.GError
	id := C.frida_device_inject_library_file_sync(d.device,
		C.guint(pid),
		pathC,
		entrypointC,
		dataC,
		nil,
		&err)
	if err != nil {
		return 0, &FridaError{err}
	}

	return uint(id), nil
}

// InjectLibraryBlob will inject the library in the target with byteData path.
// Entrypoint is the entrypoint to the library and the data is any data you need to pass
// to the library.
func (d *Device) InjectLibraryBlob(target interface{}, byteData []byte, entrypoint, data string) (uint, error) {
	var pid int
	switch v := reflect.ValueOf(target); v.Kind() {
	case reflect.String:
		proc, err := d.GetProcessByName(target.(string), SCOPE_MINIMAL)
		if err != nil {
			return 0, err
		}
		pid = proc.GetPid()
	case reflect.Int:
		pid = target.(int)
	default:
		return 0, errors.New("Expected name of app/process or PID")
	}

	if len(byteData) == 0 {
		return 0, errors.New("You need to provide byteData")
	}

	var entrypointC *C.char = nil
	var dataC *C.char = nil

	if entrypoint != "" {
		entrypointC = C.CString(entrypoint)
		defer C.free(unsafe.Pointer(entrypointC))
	}

	if data != "" {
		dataC = C.CString(data)
		defer C.free(unsafe.Pointer(dataC))
	}

	arr, len := uint8ArrayFromByteSlice(byteData)
	defer C.free(unsafe.Pointer(arr))
	gBytesData := C.g_bytes_new((C.gconstpointer)(unsafe.Pointer(arr)), C.gsize(len))
	defer clean(unsafe.Pointer(gBytesData), CleanPOD)

	var err *C.GError
	id := C.frida_device_inject_library_blob_sync(d.device,
		C.guint(pid),
		gBytesData,
		entrypointC,
		dataC,
		nil,
		&err)
	if err != nil {
		return 0, &FridaError{err}
	}

	return uint(id), nil
}

// OpenChannel open channel with the address and returns the IOStream
func (d *Device) OpenChannel(address string) (*IOStream, error) {
	addressC := C.CString(address)
	defer C.free(unsafe.Pointer(addressC))

	var err *C.GError
	stream := C.frida_device_open_channel_sync(d.device, addressC, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}
	return NewIOStream(stream), nil
}

// GetHostSession returns device host session.
func (d *Device) GetHostSession() (*HostSession, error) {
	var err *C.GError
	hs := C.frida_device_get_host_session_sync(d.device, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}
	return &HostSession{hs}, nil
}

func (d *Device) On(sigName string, fn interface{}) {
	connectClosure(unsafe.Pointer(d.device), sigName, fn)
}
