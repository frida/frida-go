// Package frida provides golang binding for frida.
package frida

/*
#cgo LDFLAGS: -lfrida-core -lm -ldl
#cgo CFLAGS: -I/usr/local/include/ -w
#cgo darwin LDFLAGS: -lbsm -framework Foundation -framework AppKit -lresolv -lpthread
#cgo android LDFLAGS: -lrt -llog
#cgo linux,!android LDFLAGS: -lrt -lresolv -lpthread
#cgo linux CFLAGS: -pthread
#include <frida-core.h>
*/
import "C"
import (
	"sync"
)

var data = &sync.Map{}

// Version returns currently used frida version
func Version() string {
	return C.GoString(C.frida_version_string())
}

func getDeviceManager() *DeviceManager {
	v, ok := data.Load("mgr")
	if !ok {
		mgr := NewDeviceManager()
		data.Store("mgr", mgr)
		return mgr
	}
	return v.(*DeviceManager)
}

// LocalDevice is a wrapper around DeviceByType(DeviceTypeLocal).
func LocalDevice() *Device {
	mgr := getDeviceManager()
	v, ok := data.Load("localDevice")
	if !ok {
		dev, _ := mgr.DeviceByType(DeviceTypeLocal)
		data.Store("localDevice", dev)
		return dev
	}
	return v.(*Device)
}

// USBDevice is a wrapper around DeviceByType(DeviceTypeUsb).
func USBDevice() *Device {
	mgr := getDeviceManager()
	v, ok := data.Load("usbDevice")
	if !ok {
		_, ok := data.Load("enumeratedDevices")
		if !ok {
			mgr.EnumerateDevices()
			data.Store("enumeratedDevices", true)
		}
		dev, err := mgr.DeviceByType(DeviceTypeUsb)
		if err != nil {
			return nil
		}
		data.Store("usbDevice", dev)
		return dev
	}
	return v.(*Device)
}

// Attach attaches at val(string or int pid) using local device.
func Attach(val interface{}) (*Session, error) {
	dev := LocalDevice()
	return dev.Attach(val, nil)
}
