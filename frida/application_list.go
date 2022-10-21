package frida

//#include <frida-core.h>
import "C"
import (
	"sort"
	"sync"
)

var (
	appParams = &sync.Map{}
)

// ApplicationList struct represents FridaApplicationList from frida-core and can be used to enumerate
// applications.
type ApplicationList struct {
	al *C.FridaApplicationList
}

// EnumerateApplication will return list of all applications
//  // Obtaining the FridaApplicationList
//  for _, app := range applicationList.EnumerateApplications {
//	fmt.Println(app.GetName())
//	fmt.Println(app.GetIdentifier())
//	fmt.Println(app.GetPid())
//  }

// Count of installed applications
func (f *ApplicationList) Count() int {
	return int(C.frida_application_list_size(f.al))
}

// Applications returns the slice of of *FridaApplication
func (f *ApplicationList) Applications() []*Application {
	var apps []*Application
	for i := 0; i < f.Count(); i++ {
		app := C.frida_application_list_get(f.al, C.gint(i))
		fridaApp := &Application{
			application: app,
		}
		fridaApp.getParams()
		apps = append(apps, fridaApp)
	}

	sort.Slice(apps, func(i, j int) bool {
		return apps[i].Pid() > apps[j].Pid()
	})

	return apps
}
