package frida

/*#include <frida-core.h>
extern gboolean predicateFn(FridaDevice* device, gpointer user_data);

static FridaDeviceManagerPredicate manager_predicate() {
	return (FridaDeviceManagerPredicate)predicateFn;
}
*/
import "C"

import (
	"unsafe"
)

//export predicateFn
func predicateFn(device *C.FridaDevice, userData C.gpointer) C.gboolean {
	name := C.GoString(C.frida_device_get_name(device))
	id := C.GoString(C.frida_device_get_id(device))
	predicate := C.GoString((*C.char)(unsafe.Pointer(userData)))

	if name == predicate || id == predicate {
		return C.gboolean(1)
	}

	return C.gboolean(0)
}

// DeviceManagerInt is the device DeviceManagerInt interface
type DeviceManagerInt interface {
	Close() error
	EnumerateDevices() ([]DeviceInt, error)
	LocalDevice() (DeviceInt, error)
	USBDevice() (DeviceInt, error)
	RemoteDevice() (DeviceInt, error)
	Device(id string) (DeviceInt, error)
	DeviceByID(id string) (DeviceInt, error)
	DeviceByType(devType DeviceType) (DeviceInt, error)
	FindDeviceByID(id string) (DeviceInt, error)
	FindDeviceByType(devType DeviceType) (DeviceInt, error)
	AddRemoteDevice(address string, remoteOpts *RemoteDeviceOptions) (DeviceInt, error)
	RemoveRemoteDevice(address string) error
	Clean()
	On(sigName string, fn any)

	getManager() *C.FridaDeviceManager
}

// DeviceManager is the main structure which holds on devices available to Frida
// Single instance of the DeviceManager is created when you call frida.Attach() or frida.LocalDevice().
type DeviceManager struct {
	manager *C.FridaDeviceManager
}

// NewDeviceManager returns new frida device manager.
func NewDeviceManager() *DeviceManager {
	manager := C.frida_device_manager_new()
	return &DeviceManager{manager}
}

// Close method will close current manager.
func (d *DeviceManager) Close() error {
	var err *C.GError
	C.frida_device_manager_close_sync(d.manager, nil, &err)
	return handleGError(err)
}

// EnumerateDevices will return all connected devices.
func (d *DeviceManager) EnumerateDevices() ([]DeviceInt, error) {
	var err *C.GError
	deviceList := C.frida_device_manager_enumerate_devices_sync(d.manager, nil, &err)
	if err != nil {
		return nil, handleGError(err)
	}

	numDevices := int(C.frida_device_list_size(deviceList))
	devices := make([]DeviceInt, numDevices)

	for i := 0; i < numDevices; i++ {
		device := C.frida_device_list_get(deviceList, C.gint(i))
		devices[i] = &Device{device}
	}

	clean(unsafe.Pointer(deviceList), unrefFrida)
	return devices, nil
}

// LocalDevice returns the device with type DeviceTypeLocal.
func (d *DeviceManager) LocalDevice() (DeviceInt, error) {
	return d.DeviceByType(DeviceTypeLocal)
}

// USBDevice returns the device with type DeviceTypeUsb.
func (d *DeviceManager) USBDevice() (DeviceInt, error) {
	return d.DeviceByType(DeviceTypeUsb)
}

// RemoteDevice returns the device with type DeviceTypeRemote.
func (d *DeviceManager) RemoteDevice() (DeviceInt, error) {
	return d.DeviceByType(DeviceTypeRemote)
}

// Device returns the device based on the id that will match either device name or its ID
func (d *DeviceManager) Device(id string) (DeviceInt, error) {
	idc := C.CString(id)
	defer C.free(unsafe.Pointer(idc))

	// result = frida_device_manager_get_device_sync (PY_GOBJECT_HANDLE (self), (FridaDeviceManagerPredicate) PyDeviceManager_is_matching_device,
	// predicate, timeout, g_cancellable_get_current (), &error);
	var err *C.GError
	device := C.frida_device_manager_get_device_sync(d.manager, C.manager_predicate(), C.gpointer(idc), C.gint(1000), nil, &err)
	return &Device{device: device}, handleGError(err)
}

// DeviceByID will return device with id passed or an error if it can't find any.
// Note: the caller must call EnumerateDevices() to get devices that are of type usb
func (d *DeviceManager) DeviceByID(id string) (DeviceInt, error) {
	idC := C.CString(id)
	defer C.free(unsafe.Pointer(idC))

	timeout := C.gint(defaultDeviceTimeout)

	var err *C.GError
	device := C.frida_device_manager_get_device_by_id_sync(d.manager, idC, timeout, nil, &err)
	return &Device{device: device}, handleGError(err)
}

// DeviceByType will return device or an error by device type specified.
// Note: the caller must call EnumerateDevices() to get devices that are of type usb
func (d *DeviceManager) DeviceByType(devType DeviceType) (DeviceInt, error) {
	var err *C.GError
	device := C.frida_device_manager_get_device_by_type_sync(d.manager,
		C.FridaDeviceType(devType),
		1,
		nil,
		&err)
	return &Device{device: device}, handleGError(err)
}

// FindDeviceByID will try to find the device by id specified
// Note: the caller must call EnumerateDevices() to get devices that are of type usb
func (d *DeviceManager) FindDeviceByID(id string) (DeviceInt, error) {
	devID := C.CString(id)
	defer C.free(unsafe.Pointer(devID))

	timeout := C.gint(defaultDeviceTimeout)

	var err *C.GError
	device := C.frida_device_manager_find_device_by_id_sync(d.manager,
		devID,
		timeout,
		nil,
		&err)

	return &Device{device: device}, handleGError(err)
}

// FindDeviceByType will try to find the device by device type specified
// Note: the caller must call EnumerateDevices() to get devices that are of type usb
func (d *DeviceManager) FindDeviceByType(devType DeviceType) (DeviceInt, error) {
	timeout := C.gint(defaultDeviceTimeout)

	var err *C.GError
	device := C.frida_device_manager_find_device_by_type_sync(d.manager,
		C.FridaDeviceType(devType),
		C.gint(timeout),
		nil,
		&err)

	return &Device{device: device}, handleGError(err)
}

// AddRemoteDevice add a remote device from the provided address with remoteOpts populated
func (d *DeviceManager) AddRemoteDevice(address string, remoteOpts *RemoteDeviceOptions) (DeviceInt, error) {
	addressC := C.CString(address)
	defer C.free(unsafe.Pointer(addressC))

	var err *C.GError
	device := C.frida_device_manager_add_remote_device_sync(d.manager, addressC, remoteOpts.opts, nil, &err)

	return &Device{device: device}, handleGError(err)
}

// RemoveRemoteDevice removes remote device available at address
func (d *DeviceManager) RemoveRemoteDevice(address string) error {
	addressC := C.CString(address)
	defer C.free(unsafe.Pointer(addressC))

	var err *C.GError
	C.frida_device_manager_remove_remote_device_sync(d.manager,
		addressC,
		nil,
		&err)
	return handleGError(err)
}

// Clean will clean the resources held by the manager.
func (d *DeviceManager) Clean() {
	clean(unsafe.Pointer(d.manager), unrefFrida)
}

// On connects manager to specific signals. Once sigName is triggered,
// fn callback will be called with parameters populated.
//
// Signals available are:
//   - "added" with callback as func(device *frida.Device) {}
//   - "removed" with callback as func(device *frida.Device) {}
//   - "changed" with callback as func() {}
func (d *DeviceManager) On(sigName string, fn any) {
	connectClosure(unsafe.Pointer(d.manager), sigName, fn)
}

func (d *DeviceManager) getManager() *C.FridaDeviceManager {
	return d.manager
}
