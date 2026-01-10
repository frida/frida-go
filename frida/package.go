package frida

//#include <frida-core.h>
import "C"
import "unsafe"

type PackageManager struct {
	p *C.FridaPackageManager
}

func NewPackageManager() *PackageManager {
	p := C.frida_package_manager_new()
	return &PackageManager{p}
}

func (p *PackageManager) Install(options *PackageInstallOptions) (*PackageInstallResult, error) {
	var err *C.GError
	rt := C.frida_package_manager_install_sync(p.p, options.p, nil, &err)
	return &PackageInstallResult{rt}, handleGError(err)
}

func (p *PackageManager) GetRegistry() string {
	rt := C.frida_package_manager_get_registry(p.p)
	return C.GoString(rt)
}

func (p *PackageManager) SetRegistry(value string) {
	valueC := C.CString(value)
	defer C.free(unsafe.Pointer(valueC))

	C.frida_package_manager_set_registry(p.p, valueC)
}

func (p *PackageManager) Search(query string, options *PackageSearchOptions) (*PackageSearchResult, error) {
	queryC := C.CString(query)
	defer C.free(unsafe.Pointer(queryC))

	psearchOpts := options
	if psearchOpts == nil {
		psearchOpts = NewPackageSearchOptions()
	}

	var err *C.GError
	rt := C.frida_package_manager_search_sync(p.p, queryC, psearchOpts.p, nil, &err)
	return &PackageSearchResult{rt}, handleGError(err)
}

type Package struct {
	p *C.FridaPackage
}

func (p *Package) GetName() string {
	rt := C.frida_package_get_name(p.p)
	return C.GoString(rt)
}

func (p *Package) GetVersion() string {
	rt := C.frida_package_get_version(p.p)
	return C.GoString(rt)
}

func (p *Package) GetDescription() string {
	rt := C.frida_package_get_description(p.p)
	return C.GoString(rt)
}

func (p *Package) GetUrl() string {
	rt := C.frida_package_get_url(p.p)
	return C.GoString(rt)
}

type PackageList struct {
	p *C.FridaPackageList
}

func (p *PackageList) Size() int {
	rt := C.frida_package_list_size(p.p)
	return int(rt)
}

func (p *PackageList) Get(index int) *Package {
	rt := C.frida_package_list_get(p.p, C.gint(index))
	return &Package{rt}
}

type PackageSearchOptions struct {
	p *C.FridaPackageSearchOptions
}

func NewPackageSearchOptions() *PackageSearchOptions {
	p := C.frida_package_search_options_new()
	return &PackageSearchOptions{p}
}

func (p *PackageSearchOptions) SetOffset(value uint) {
	valueC := C.uint(value)

	C.frida_package_search_options_set_offset(p.p, valueC)
}

func (p *PackageSearchOptions) GetLimit() uint {
	rt := C.frida_package_search_options_get_limit(p.p)
	return uint(rt)
}

func (p *PackageSearchOptions) SetLimit(value uint) {
	valueC := C.uint(value)

	C.frida_package_search_options_set_limit(p.p, valueC)
}

func (p *PackageSearchOptions) GetOffset() uint {
	rt := C.frida_package_search_options_get_offset(p.p)
	return uint(rt)
}

type PackageSearchResult struct {
	p *C.FridaPackageSearchResult
}

func (p *PackageSearchResult) GetPackages() *PackageList {
	rt := C.frida_package_search_result_get_packages(p.p)
	return &PackageList{rt}
}

func (p *PackageSearchResult) GetTotal() uint {
	rt := C.frida_package_search_result_get_total(p.p)
	return uint(rt)
}

type PackageInstallOptions struct {
	p *C.FridaPackageInstallOptions
}

func (p *PackageInstallOptions) GetProjectRoot() string {
	rt := C.frida_package_install_options_get_project_root(p.p)
	return C.GoString(rt)
}

func (p *PackageInstallOptions) SetProjectRoot(value string) {
	valueC := C.CString(value)
	defer C.free(unsafe.Pointer(valueC))

	C.frida_package_install_options_set_project_root(p.p, valueC)
}

func (p *PackageInstallOptions) GetRole() PackageRole {
	rt := C.frida_package_install_options_get_role(p.p)
	return PackageRole(rt)
}

func (p *PackageInstallOptions) SetRole(value PackageRole) {
	C.frida_package_install_options_set_role(p.p, C.FridaPackageRole(value))
}

func (p *PackageInstallOptions) ClearSpecs() {
	C.frida_package_install_options_clear_specs(p.p)
}

func (p *PackageInstallOptions) AddSpec(spec string) {
	specC := C.CString(spec)
	defer C.free(unsafe.Pointer(specC))

	C.frida_package_install_options_add_spec(p.p, specC)
}

func (p *PackageInstallOptions) ClearOmits() {
	C.frida_package_install_options_clear_omits(p.p)
}

func (p *PackageInstallOptions) AddOmit(role PackageRole) {
	C.frida_package_install_options_add_omit(p.p, C.FridaPackageRole(role))
}

type PackageInstallResult struct {
	p *C.FridaPackageInstallResult
}

func (p *PackageInstallResult) GetPackages() *PackageList {
	rt := C.frida_package_install_result_get_packages(p.p)
	return &PackageList{rt}
}
