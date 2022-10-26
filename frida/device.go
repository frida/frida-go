package frida

//#include <frida-core.h>
import "C"
import (
	"errors"
	"reflect"
	"unsafe"
)

// Device represents FridaDevice struct from frida-core
type Device struct {
	device     *C.FridaDevice
	attachedTo int
}

// Clean will delete
func (f *Device) Clean() {
	fridaUnref(unsafe.Pointer(f.device))
}

// GetApplicationList will return pointer to FridaApplicationList which holds the list
// of all the applications installed and can be enumerated with EnumerateApplications.
func (f *Device) ApplicationList(scope Scope) (*ApplicationList, error) {
	var err *C.GError
	sc := C.FridaScope(scope)

	queryOpts := C.frida_application_query_options_new()
	C.frida_application_query_options_set_scope(queryOpts, sc)

	appList := C.frida_device_enumerate_applications_sync(f.device, queryOpts, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}
	return &ApplicationList{appList}, nil
}

// GetDeviceIcon will return the device icon by calling frida_device_get_icon(FridaDevice*) function.
func (f *Device) DeviceIcon() *C.GVariant {
	var icon *C.GVariant
	icon = C.frida_device_get_icon(f.device)
	/*var res *C.char
	C.iter_array(icon, unsafe.Pointer(res))*/
	dt := gPointerToGo((C.gpointer)(icon))
	_ = dt
	return icon
}

func (f *Device) DeviceType() DeviceType {
	fdt := C.frida_device_get_dtype(f.device)
	return DeviceType(int(fdt))
}

// GetFrontMostApplication will return the frontmost application or the application in focus
// on the device.
func (f *Device) FrontMostApplication(scope Scope) (*Application, error) {
	var err *C.GError
	app := &Application{}

	sc := C.FridaScope(scope)
	queryOpts := C.frida_frontmost_query_options_new()
	C.frida_frontmost_query_options_set_scope(queryOpts, sc)
	app.application = C.frida_device_get_frontmost_application_sync(f.device, queryOpts, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}

	app.getParams()

	if app.application == nil {
		return nil, errors.New("Could not obtain frontmost application! Is any application started?")
	}

	return app, nil
}

// GetID will return the ID of the current device.
func (f *Device) ID() string {
	return C.GoString(C.frida_device_get_id(f.device))
}

// GetName will return the name of the current device.
func (f *Device) Name() string {
	return C.GoString(C.frida_device_get_name(f.device))
}

func (f *Device) Params() map[string]interface{} {
	var err *C.GError
	ht := C.frida_device_query_system_parameters_sync(f.device, nil, &err)
	if err != nil {
		panic(err)
	}

	params := gHashTableToMap(ht)

	return params
}

// GetProcessList will return pointer to FridaProcessList
func (f *Device) Processes() (*ProcessList, error) {
	procs := &ProcessList{}
	var err *C.GError
	procList := C.frida_device_enumerate_processes_sync(f.device, nil, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}
	procLength := int(C.frida_process_list_size(procList))

	for i := 0; i < procLength; i++ {
		proc := C.frida_process_list_get(procList, C.gint(i))
		procs.processes = append(procs.processes, Process{proc})
	}

	procs.pList = procList
	return procs, nil
}

// GetProcessByPid returns the process by passed int
func (f *Device) ProcessByPid(pid int) (*Process, error) {
	var err *C.GError
	nPid := C.guint(pid)
	proc := C.frida_device_get_process_by_pid_sync(f.device, nPid, nil, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}
	return &Process{proc}, nil
}

// GetProcessByName returns the process by passed name
func (f *Device) ProcessByName(name string) (*Process, error) {
	var err *C.GError
	nName := C.CString(name)
	defer objectFree(unsafe.Pointer(nName))
	proc := C.frida_device_get_process_by_name_sync(f.device, nName, nil, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}
	return &Process{proc}, nil
}

func (f *Device) EnableSpawnGating() error {
	var err *C.GError
	C.frida_device_enable_spawn_gating_sync(f.device, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

func (f *Device) DisableSpawnGating() error {
	/*
		void frida_device_disable_spawn_gating_sync
		(FridaDevice * self, GCancellable * cancellable,
			GError ** error);
	*/
	var err *C.GError
	C.frida_device_disable_spawn_gating_sync(f.device, nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

func (f *Device) EnumeratePendingChildren() ([]*Child, error) {
	var err *C.GError
	childList := C.frida_device_enumerate_pending_children_sync(f.device, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}

	var childs []*Child
	sz := C.frida_child_list_size(childList)

	for i := 0; i < int(sz); i++ {
		chld := C.frida_child_list_get(childList, C.gint(i))
		c := &Child{
			child: chld,
		}
		childs = append(childs, c)
	}

	return childs, nil
}

// Spawn will spawn an application or binary and call Attach afterwards
func (f *Device) Spawn(name string, opts *SpawnOptions) (int, error) {
	var err *C.GError
	pid := C.frida_device_spawn_sync(f.device, C.CString(name), opts.opts, nil, &err)
	if err != nil {
		return -1, &FridaError{err}
	}

	return int(pid), nil
}

// Resume will resume the application using frida_device_resume_sync
func (f *Device) Resume(pid int) error {
	var err *C.GError
	C.frida_device_resume_sync(f.device, C.guint(pid), nil, &err)
	if err != nil {
		return &FridaError{err}
	}
	return nil
}

// Attach will attach on specified process name or PID
func (f *Device) Attach(val interface{}) (*Session, error) {
	var pid int
	switch v := reflect.ValueOf(val); v.Kind() {
	case reflect.String:
		proc, err := f.ProcessByName(val.(string))
		if err != nil {
			return nil, err
		}
		pid = proc.GetPid()
	case reflect.Int:
		pid = val.(int)
	default:
		return nil, errors.New("Expected name of app/process or PID")
	}

	var err *C.GError
	s := C.frida_device_attach_sync(f.device, C.guint(pid), nil, nil, &err)
	if err != nil {
		return nil, &FridaError{err}
	}
	f.attachedTo = pid
	return &Session{s}, nil
}

func (f *Device) Bus() *Bus {
	bus := C.frida_device_get_bus(f.device)
	return &Bus{
		bus: bus,
	}
}

func (f *Device) On(sigName string, fn interface{}) {
	connectClosure(unsafe.Pointer(f.device), sigName, fn)
}

func (f *Device) InjectLibrary(target interface{}, path, entrypoint, data string) (uint, error) {
	var pid int
	switch v := reflect.ValueOf(target); v.Kind() {
	case reflect.String:
		proc, err := f.ProcessByName(target.(string))
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
		return 0, errors.New("You need to provide path to cmodule")
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
	id := C.frida_device_inject_library_file_sync(f.device,
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
