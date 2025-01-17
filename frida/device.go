package frida

//#include <frida-core.h>
import "C"
import (
	"context"
	"errors"
	"reflect"
	"runtime"
	"sort"
	"unsafe"
)

type DeviceInt interface {
	ID() string
	Name() string
	DeviceIcon() any
	DeviceType() DeviceType
	Bus() *Bus
	IsLost() bool
	Params(opts ...OptFunc) (map[string]any, error)
	ParamsWithContext(ctx context.Context) (map[string]any, error)
	FrontmostApplication(scope Scope) (*Application, error)
	EnumerateApplications(identifier string, scope Scope, opts ...OptFunc) ([]*Application, error)
	ProcessByPID(pid int, scope Scope) (*Process, error)
	ProcessByName(name string, scope Scope) (*Process, error)
	FindProcessByPID(pid int, scope Scope) (*Process, error)
	FindProcessByName(name string, scope Scope) (*Process, error)
	EnumerateProcesses(scope Scope) ([]*Process, error)
	EnableSpawnGating() error
	DisableSpawnGating() error
	EnumeratePendingSpawn() ([]*Spawn, error)
	EnumeratePendingChildren() ([]*Child, error)
	Spawn(name string, opts *SpawnOptions) (int, error)
	Input(pid int, data []byte) error
	Resume(pid int) error
	Kill(pid int) error
	Attach(val any, sessionOpts *SessionOptions, opts ...OptFunc) (*Session, error)
	AttachWithContext(ctx context.Context, val any, opts *SessionOptions) (*Session, error)
	InjectLibraryFile(target any, path, entrypoint, data string) (uint, error)
	InjectLibraryBlob(target any, byteData []byte, entrypoint, data string) (uint, error)
	OpenChannel(address string) (*IOStream, error)
	OpenService(address string) (*Service, error)
	Clean()
	On(sigName string, fn any)
}

// Device represents Device struct from frida-core
type Device struct {
	device *C.FridaDevice
}

// ID will return the ID of the device.
func (d *Device) ID() string {
	if d.device != nil {
		return C.GoString(C.frida_device_get_id(d.device))
	}
	return ""
}

// Name will return the name of the device.
func (d *Device) Name() string {
	if d.device != nil {
		return C.GoString(C.frida_device_get_name(d.device))
	}
	return ""
}

// DeviceIcon will return the device icon.
func (d *Device) DeviceIcon() any {
	if d.device != nil {
		icon := C.frida_device_get_icon(d.device)
		dt := gPointerToGo((C.gpointer)(icon))
		return dt
	}
	return nil
}

// DeviceType returns type of the device.
func (d *Device) DeviceType() DeviceType {
	if d.device != nil {
		fdt := C.frida_device_get_dtype(d.device)
		return DeviceType(fdt)
	}
	return -1
}

// Bus returns device bus.
func (d *Device) Bus() *Bus {
	if d.device != nil {
		bus := C.frida_device_get_bus(d.device)
		return &Bus{
			bus: bus,
		}
	}
	return nil
}

// IsLost returns boolean whether device is lost or not.
func (d *Device) IsLost() bool {
	if d.device != nil {
		lost := C.frida_device_is_lost(d.device)
		return int(lost) == 1
	}
	return false
}

// ParamsWithContext runs Params but with context.
// This function will properly handle cancelling the frida operation.
// It is advised to use this rather than handling Cancellable yourself.
func (d *Device) ParamsWithContext(ctx context.Context) (map[string]any, error) {
	rawParams, err := handleWithContext(ctx, func(c *Cancellable, doneC chan any, errC chan error) {
		params, err := d.Params(WithCancel(c))
		if err != nil {
			errC <- err
			return
		}
		doneC <- params
	})
	params, _ := rawParams.(map[string]any)
	return params, err
}

// Params returns system parameters of the device
// You can add an option with the variadic opts argument.
//
// Example:
//
//	params, err := device.Params()
//
//
//	// or WithCancel
//
//	cancel := frida.NewCancellable()
//	params, err := device.Params(frida.WithCancel(c))
//
//	// ...
//
//	cancel.Cancel()
func (d *Device) Params(opts ...OptFunc) (map[string]any, error) {
	o := setupOptions(opts)
	return d.params(o)
}

func (d *Device) params(opts options) (map[string]any, error) {
	if d.device == nil {
		return nil, errors.New("could not obtain params for nil device")
	}

	var err *C.GError
	ht := C.frida_device_query_system_parameters_sync(d.device, opts.cancellable, &err)
	if err != nil {
		return nil, handleGError(err)
	}
	return gHashTableToMap(ht), nil
}

// FrontmostApplication will return the frontmost application or the application in focus
// on the device.
func (d *Device) FrontmostApplication(scope Scope) (*Application, error) {
	if d.device != nil {
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
			return nil, handleGError(err)
		}

		if app.application == nil {
			return nil, errors.New("could not obtain frontmost application! Is any application started?")
		}

		return app, nil
	}
	return nil, errors.New("could not obtain frontmost app for nil device")
}

// EnumerateApplications will return slice of applications on the device
// You can add an option with the variadic opts argument
//
// Example:
//
//	apps, err := device.EnumerateApplications("", frida.ScopeFull)
//
//	// or providing the option to cancel
//
//	cancel := frida.NewCancellable()
//	apps, err := device.EnumerateApplications("", frida.ScopeFull, frida.WithCancel(c))
//
//	// ...
//
//	cancel.Cancel()
func (d *Device) EnumerateApplications(identifier string, scope Scope, opts ...OptFunc) ([]*Application, error) {
	o := setupOptions(opts)
	return d.enumerateApplications(identifier, scope, o)
}

func (d *Device) enumerateApplications(identifier string, scope Scope, opts options) ([]*Application, error) {
	if d.device == nil {
		return nil, errors.New("could not enumerate applications for nil device")
	}

	queryOpts := C.frida_application_query_options_new()
	C.frida_application_query_options_set_scope(queryOpts, C.FridaScope(scope))

	if identifier != "" {
		identifierC := C.CString(identifier)
		defer C.free(unsafe.Pointer(identifierC))
		C.frida_application_query_options_select_identifier(queryOpts, identifierC)
	}

	var err *C.GError
	appList := C.frida_device_enumerate_applications_sync(d.device, queryOpts, opts.cancellable, &err)
	if err != nil {
		return nil, handleGError(err)
	}

	appListSize := int(C.frida_application_list_size(appList))
	apps := make([]*Application, appListSize)

	for i := 0; i < appListSize; i++ {
		app := C.frida_application_list_get(appList, C.gint(i))
		apps[i] = &Application{app}
	}

	sort.Slice(apps, func(i, j int) bool {
		return apps[i].PID() > apps[j].PID()
	})

	clean(unsafe.Pointer(queryOpts), unrefFrida)
	clean(unsafe.Pointer(appList), unrefFrida)

	return apps, nil
}

// ProcessByPID returns the process by passed pid.
func (d *Device) ProcessByPID(pid int, scope Scope) (*Process, error) {
	if d.device == nil {
		return nil, errors.New("could not obtain process for nil device")
	}

	opts := C.frida_process_match_options_new()
	C.frida_process_match_options_set_timeout(opts, C.gint(defaultProcessTimeout))
	C.frida_process_match_options_set_scope(opts, C.FridaScope(scope))
	defer clean(unsafe.Pointer(opts), unrefFrida)

	var err *C.GError
	proc := C.frida_device_get_process_by_pid_sync(d.device, C.guint(pid), opts, nil, &err)
	return &Process{proc}, handleGError(err)
}

// ProcessByName returns the process by passed name.
func (d *Device) ProcessByName(name string, scope Scope) (*Process, error) {
	if d.device == nil {
		return nil, errors.New("could not obtain process for nil device")
	}
	nameC := C.CString(name)
	defer C.free(unsafe.Pointer(nameC))

	opts := C.frida_process_match_options_new()
	C.frida_process_match_options_set_timeout(opts, C.gint(defaultProcessTimeout))
	C.frida_process_match_options_set_scope(opts, C.FridaScope(scope))
	defer clean(unsafe.Pointer(opts), unrefFrida)

	var err *C.GError
	proc := C.frida_device_get_process_by_name_sync(d.device, nameC, opts, nil, &err)
	return &Process{proc}, handleGError(err)
}

// FindProcessByPID will try to find the process with given pid.
func (d *Device) FindProcessByPID(pid int, scope Scope) (*Process, error) {
	if d.device == nil {
		return nil, errors.New("could not find process for nil device")
	}

	opts := C.frida_process_match_options_new()
	C.frida_process_match_options_set_timeout(opts, C.gint(defaultProcessTimeout))
	C.frida_process_match_options_set_scope(opts, C.FridaScope(scope))
	defer clean(unsafe.Pointer(opts), unrefFrida)

	var err *C.GError
	proc := C.frida_device_find_process_by_pid_sync(d.device, C.guint(pid), opts, nil, &err)
	return &Process{proc}, handleGError(err)
}

// FindProcessByName will try to find the process with name specified.
func (d *Device) FindProcessByName(name string, scope Scope) (*Process, error) {
	if d.device == nil {
		return nil, errors.New("could not find process for nil device")
	}

	nameC := C.CString(name)
	defer C.free(unsafe.Pointer(nameC))

	opts := C.frida_process_match_options_new()
	C.frida_process_match_options_set_timeout(opts, C.gint(defaultProcessTimeout))
	C.frida_process_match_options_set_scope(opts, C.FridaScope(scope))
	defer clean(unsafe.Pointer(opts), unrefFrida)

	var err *C.GError
	proc := C.frida_device_find_process_by_name_sync(d.device, nameC, opts, nil, &err)
	return &Process{proc}, handleGError(err)
}

// EnumerateProcesses will slice of processes running with scope provided
func (d *Device) EnumerateProcesses(scope Scope) ([]*Process, error) {
	if d.device != nil {
		opts := C.frida_process_query_options_new()
		C.frida_process_query_options_set_scope(opts, C.FridaScope(scope))
		defer clean(unsafe.Pointer(opts), unrefFrida)

		var err *C.GError
		procList := C.frida_device_enumerate_processes_sync(d.device, opts, nil, &err)
		if err != nil {
			return nil, handleGError(err)
		}

		procListSize := int(C.frida_process_list_size(procList))
		procs := make([]*Process, procListSize)

		for i := 0; i < procListSize; i++ {
			proc := C.frida_process_list_get(procList, C.gint(i))
			procs[i] = &Process{proc}
		}

		clean(unsafe.Pointer(procList), unrefFrida)
		return procs, nil
	}
	return nil, errors.New("could not enumerate processes for nil device")
}

// EnableSpawnGating will enable spawn gating on the device.
func (d *Device) EnableSpawnGating() error {
	if d.device == nil {
		return errors.New("could not enable spawn gating for nil device")
	}

	var err *C.GError
	C.frida_device_enable_spawn_gating_sync(d.device, nil, &err)
	return handleGError(err)
}

// DisableSpawnGating will disable spawn gating on the device.
func (d *Device) DisableSpawnGating() error {
	if d.device == nil {
		return errors.New("could not disable spawn gating for nil device")
	}

	var err *C.GError
	C.frida_device_disable_spawn_gating_sync(d.device, nil, &err)
	return handleGError(err)
}

// EnumeratePendingSpawn will return the slice of pending spawns.
func (d *Device) EnumeratePendingSpawn() ([]*Spawn, error) {
	if d.device != nil {
		var err *C.GError
		spawnList := C.frida_device_enumerate_pending_spawn_sync(d.device, nil, &err)
		if err != nil {
			return nil, handleGError(err)
		}

		spawnListSize := int(C.frida_spawn_list_size(spawnList))
		spawns := make([]*Spawn, spawnListSize)

		for i := 0; i < spawnListSize; i++ {
			spawn := C.frida_spawn_list_get(spawnList, C.gint(i))
			spawns[i] = &Spawn{spawn}
		}

		clean(unsafe.Pointer(spawnList), unrefFrida)
		return spawns, nil
	}
	return nil, errors.New("could not enumerate pending spawn for nil device")
}

// EnumeratePendingChildren will return the slice of pending children.
func (d *Device) EnumeratePendingChildren() ([]*Child, error) {
	if d.device != nil {
		var err *C.GError
		childList := C.frida_device_enumerate_pending_children_sync(d.device, nil, &err)
		if err != nil {
			return nil, handleGError(err)
		}

		childListSize := int(C.frida_child_list_size(childList))
		children := make([]*Child, childListSize)

		for i := 0; i < childListSize; i++ {
			child := C.frida_child_list_get(childList, C.gint(i))
			children[i] = &Child{child}
		}

		clean(unsafe.Pointer(childList), unrefFrida)
		return children, nil
	}
	return nil, errors.New("could not enumerate pending children for nil device")
}

// Spawn will spawn an application or binary.
func (d *Device) Spawn(name string, opts *SpawnOptions) (int, error) {
	if d.device == nil {
		return -1, errors.New("could not spawn for nil device")
	}

	var opt *C.FridaSpawnOptions = nil
	if opts != nil {
		opt = opts.opts
	}
	defer clean(unsafe.Pointer(opt), unrefFrida)

	nameC := C.CString(name)
	defer C.free(unsafe.Pointer(nameC))

	var err *C.GError
	pid := C.frida_device_spawn_sync(d.device, nameC, opt, nil, &err)

	return int(pid), handleGError(err)
}

// Input inputs []bytes into the process with pid specified.
func (d *Device) Input(pid int, data []byte) error {
	if d.device == nil {
		return errors.New("could not input bytes into nil device")

	}
	gBytesData := goBytesToGBytes(data)
	runtime.SetFinalizer(gBytesData, func(g *C.GBytes) {
		clean(unsafe.Pointer(g), unrefGObject)
	})

	var err *C.GError
	C.frida_device_input_sync(d.device, C.guint(pid), gBytesData, nil, &err)
	runtime.KeepAlive(gBytesData)
	return handleGError(err)
}

// Resume will resume the process with pid.
func (d *Device) Resume(pid int) error {
	if d.device == nil {
		return errors.New("could not resume for nil device")
	}
	var err *C.GError
	C.frida_device_resume_sync(d.device, C.guint(pid), nil, &err)
	return handleGError(err)
}

// Kill kills process with pid specified.
func (d *Device) Kill(pid int) error {
	if d.device == nil {
		return errors.New("could not kill for nil device")
	}
	var err *C.GError
	C.frida_device_kill_sync(d.device, C.guint(pid), nil, &err)
	return handleGError(err)
}

// AttachWithContext runs Attach but with context.
// This function will properly handle cancelling the frida operation.
// It is advised to use this rather than handling Cancellable yourself.
func (d *Device) AttachWithContext(ctx context.Context, val any, sessionOpts *SessionOptions) (*Session, error) {
	rawSession, err := handleWithContext(ctx, func(c *Cancellable, doneC chan any, errC chan error) {
		session, err := d.Attach(val, sessionOpts, WithCancel(c))
		if err != nil {
			errC <- err
			return
		}
		doneC <- session
	})
	session, _ := rawSession.(*Session)
	return session, err
}

// Attach will attach on specified process name or PID.
// You can pass the nil as SessionOptions or you can create it if you want
// the session to persist for specific timeout.
func (d *Device) Attach(val any, sessionOpts *SessionOptions, opts ...OptFunc) (*Session, error) {
	o := setupOptions(opts)
	return d.attach(val, sessionOpts, o)
}

func (d *Device) attach(val any, sessionOpts *SessionOptions, opts options) (*Session, error) {
	if d.device == nil {
		return nil, errors.New("could not attach for nil device")
	}
	var pid int
	switch v := reflect.ValueOf(val); v.Kind() {
	case reflect.String:
		proc, err := d.ProcessByName(val.(string), ScopeMinimal)
		if err != nil {
			return nil, err
		}
		pid = proc.PID()
	case reflect.Int:
		pid = val.(int)
	default:
		return nil, errors.New("expected name of app/process or PID")
	}

	var opt *C.FridaSessionOptions = nil
	if sessionOpts != nil {
		opt = sessionOpts.opts
		defer clean(unsafe.Pointer(opt), unrefFrida)
	}

	var err *C.GError
	s := C.frida_device_attach_sync(d.device, C.guint(pid), opt, opts.cancellable, &err)
	return &Session{s}, handleGError(err)
}

// InjectLibraryFile will inject the library in the target with path to library specified.
// Entrypoint is the entrypoint to the library and the data is any data you need to pass
// to the library.
func (d *Device) InjectLibraryFile(target any, path, entrypoint, data string) (uint, error) {
	if d.device == nil {
		return 0, errors.New("could not inject library for nil device")
	}
	var pid int
	switch v := reflect.ValueOf(target); v.Kind() {
	case reflect.String:
		proc, err := d.ProcessByName(target.(string), ScopeMinimal)
		if err != nil {
			return 0, err
		}
		pid = proc.PID()
	case reflect.Int:
		pid = target.(int)
	default:
		return 0, errors.New("expected name of app/process or PID")
	}

	if path == "" {
		return 0, errors.New("you need to provide path to library")
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

	return uint(id), handleGError(err)
}

// InjectLibraryBlob will inject the library in the target with byteData path.
// Entrypoint is the entrypoint to the library and the data is any data you need to pass
// to the library.
func (d *Device) InjectLibraryBlob(target any, byteData []byte, entrypoint, data string) (uint, error) {
	if d.device == nil {
		return 0, errors.New("could not inject library blob for nil device")
	}
	var pid int
	switch v := reflect.ValueOf(target); v.Kind() {
	case reflect.String:
		proc, err := d.ProcessByName(target.(string), ScopeMinimal)
		if err != nil {
			return 0, err
		}
		pid = proc.PID()
	case reflect.Int:
		pid = target.(int)
	default:
		return 0, errors.New("expected name of app/process or PID")
	}

	if len(byteData) == 0 {
		return 0, errors.New("you need to provide byteData")
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

	gBytesData := goBytesToGBytes(byteData)
	runtime.SetFinalizer(gBytesData, func(g *C.GBytes) {
		defer clean(unsafe.Pointer(g), unrefGObject)
	})

	var err *C.GError
	id := C.frida_device_inject_library_blob_sync(d.device,
		C.guint(pid),
		gBytesData,
		entrypointC,
		dataC,
		nil,
		&err)
	runtime.KeepAlive(gBytesData)

	return uint(id), handleGError(err)
}

// OpenChannel open channel with the address and returns the IOStream
func (d *Device) OpenChannel(address string) (*IOStream, error) {
	if d.device == nil {
		return nil, errors.New("could not open channel for nil device")
	}
	addressC := C.CString(address)
	defer C.free(unsafe.Pointer(addressC))

	var err *C.GError
	stream := C.frida_device_open_channel_sync(d.device, addressC, nil, &err)
	return NewIOStream(stream), handleGError(err)
}

func (d *Device) OpenService(address string) (*Service, error) {
	if d.device == nil {
		return nil, errors.New("could not open service")
	}
	addrC := C.CString(address)
	defer C.free(unsafe.Pointer(addrC))

	var err *C.GError
	svc := C.frida_device_open_service_sync(d.device, addrC, nil, &err)
	return &Service{svc}, handleGError(err)
}

// Clean will clean the resources held by the device.
func (d *Device) Clean() {
	if d.device != nil {
		clean(unsafe.Pointer(d.device), unrefFrida)
	}
}

// On connects device to specific signals. Once sigName is triggered,
// fn callback will be called with parameters populated.
//
// Signals available are:
//   - "spawn_added" with callback as func(spawn *frida.Spawn) {}
//   - "spawn_removed" with callback as func(spawn *frida.Spawn) {}
//   - "child_added" with callback as func(child *frida.Child) {}
//   - "child_removed" with callback as func(child *frida.Child) {}
//   - "process_crashed" with callback as func(crash *frida.Crash) {}
//   - "output" with callback as func(pid, fd int, data []byte) {}
//   - "uninjected" with callback as func(id int) {}
//   - "lost" with callback as func() {}
func (d *Device) On(sigName string, fn any) {
	if d.device != nil {
		connectClosure(unsafe.Pointer(d.device), sigName, fn)
	}
}
