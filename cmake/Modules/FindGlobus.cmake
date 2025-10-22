#[=======================================================================[.rst:
FindGlobus
-----------

Find Globus stuff

#]=======================================================================]

cmake_policy(PUSH)
cmake_minimum_required(VERSION 3.12...3.18 FATAL_ERROR)
if (POLICY CMP0121)
  # Detect invalid indices in list()
  cmake_policy(SET CMP0121 NEW)
endif()
if (POLICY CMP0125)
  # Consistent behavior for cache variables managed by find_*()
  cmake_policy(SET CMP0125 NEW)
endif()
if (POLICY CMP0144)
  # Allow for uppercased <PACKAGENAME>_ROOT variables.
  cmake_policy(SET CMP0144 NEW)
endif()

function(_fg_debug msg)
  if (FindGlobus_DEBUG)
    message(STATUS "${msg}")
  endif()
endfunction()

# check to see if lists are equivalent, ignoring ordering and duplicates
function(_fg_check_list_equivalence list1 list2 outvar)
  foreach(l1e IN LISTS "${list1}")
    if (NOT l1e IN_LIST "${list2}")
      set("${outvar}" FALSE PARENT_SCOPE)
      return()
    endif()
  endforeach()
  foreach(l2e IN LISTS "${list2}")
    if (NOT l2e IN_LIST "${list1}")
      set("${outvar}" FALSE PARENT_SCOPE)
      return()
    endif()
  endforeach()
  set("${outvar}" TRUE PARENT_SCOPE)
endfunction()

set(
  _Globus_FIND_COMPONENTS_known
  "common"
  "authz"
  "authz_callout_error"
  "callout"
  "dsi_rest"
  "ftp_control"
  "gfork"
  "gridftp_server"
  "gridftp_server_control"
  "gridmap_callout_error"
  "gsi_callback"
  "gsi_cert_utils"
  "gsi_credential"
  "gsi_openssl_error"
  "gsi_proxy_core"
  "gsi_proxy_ssl"
  "gsi_sysconfig"
  "gss_assist"
  "gssapi_error"
  "gssapi_gsi"
  "io"
  "openssl_module"
  "xio"
  "xio_gsi_driver"
  "xio_pipe_driver"
  "xio_unix_driver"
)

# xio drivers have no libs
set(_Globus_xio_gsi_driver_NOLIB TRUE)
set(_Globus_xio_pipe_driver_NOLIB TRUE)
set(_Globus_xio_unix_driver_NOLIB TRUE)

# some components have differently-named libs
set(_Globus_authz_callout_error_LIBNAME "globus_gsi_authz_callout_error")
set(_Globus_gsi_openssl_error_LIBNAME "globus_openssl_error")
set(_Globus_gsi_proxy_ssl_LIBNAME "globus_proxy_ssl")
set(_Globus_openssl_module_LIBNAME "globus_openssl")

# some components have differently-named headers
set(_Globus_authz_callout_error_HEADERNAME "globus_gsi_authz_callout_error.h")
set(_Globus_authz_HEADERNAME "globus_gsi_authz.h")
set(_Globus_gsi_openssl_error_HEADERNAME "globus_error_openssl.h")
set(_Globus_gsi_proxy_core_HEADERNAME "globus_gsi_proxy.h")
set(_Globus_gsi_proxy_ssl_HEADERNAME "proxycertinfo.h")
set(_Globus_gsi_sysconfig_HEADERNAME "globus_gsi_system_config.h")
set(_Globus_gssapi_error_HEADERNAME "globus_error_gssapi.h")
set(_Globus_gssapi_gsi_HEADERNAME "gssapi.h")
set(_Globus_openssl_module_HEADERNAME "globus_openssl.h")
set(_Globus_xio_gsi_driver_HEADERNAME "globus_xio_gsi.h")
set(_Globus_xio_unix_driver_HEADERNAME "globus_xio_unix.h")

find_package(PkgConfig QUIET)

function(_Globus_find_component component)
  _fg_debug("_Globus_find_component(${component})")
  string(REPLACE "_" "-" component_dash "${component}")
  set(pc_name "globus-${component_dash}")

  if (PKG_CONFIG_FOUND)
    pkg_check_modules(PC_Globus_${component} QUIET "${pc_name}")
  endif()

  set(include_dirs_docstring "${pc_name} include directories")
  if (Globus_${component}_INCLUDE_DIRS)
    set(Globus_${component}_INCLUDE_DIRS "${Globus_${component}_INCLUDE_DIRS}" CACHE STRING "${include_dirs_docstring}")
  else()
    _fg_debug("PC_Globus_${component}_INCLUDE_DIRS = ${PC_Globus_${component}_INCLUDE_DIRS}")
    _fg_debug("PC_Globus_${component}_INCLUDEDIR = ${PC_Globus_${component}_INCLUDEDIR}")
    if (_Globus_${component}_HEADERNAME)
      set(headername "${_Globus_${component}_HEADERNAME}")
    else()
      set(headername "globus_${component}.h")
    endif()
    _fg_debug("headername = ${headername}")
    find_path(
      Globus_${component}_INCLUDE_DIR "${headername}"
      HINTS "${PC_Globus_${component}_INCLUDE_DIRS}" "${PC_Globus_${component}_INCLUDEDIR}"
      DOC "${pc_name} main include directory"
    )
    mark_as_advanced(FORCE Globus_${component}_INCLUDE_DIR)
    _fg_debug("Globus_${component}_INCLUDE_DIR = ${Globus_${component}_INCLUDE_DIR}")
    set(include_dirs "${PC_Globus_${component}_INCLUDE_DIRS}")
    if (Globus_${component}_INCLUDE_DIR AND NOT Globus_${component}_INCLUDE_DIR IN_LIST include_dirs)
      list(INSERT include_dirs 0 "${Globus_${component}_INCLUDE_DIR}")
    endif()
    if (NOT include_dirs)
      set(include_dirs "Globus_${component}_INCLUDE_DIR-NOTFOUND")
    endif()
    set(Globus_${component}_INCLUDE_DIRS "${include_dirs}" CACHE STRING "${include_dirs_docstring}")
  endif()
  _fg_debug("Globus_${component}_INCLUDE_DIRS = ${Globus_${component}_INCLUDE_DIRS}")

  set(libs_docstring "${pc_name} libraries")
  if (DEFINED Globus_${component}_LIBRARIES)
    set(Globus_${component}_LIBRARIES "${Globus_${component}_LIBRARIES}" CACHE STRING "${libs_docstring}")
  else()
    if (_Globus_${component}_NOLIB)
      # At the time of writing, this component has no libraries.
      # On the off chance something has moved, let's take whatever pkgconf gives us.
      set(_Globus_${component}_LIBRARIES "${PC_Globus_${component}_LINK_LIBRARIES}")
    else()
      if (_Globus_${component}_LIBNAME)
        set(libname "${_Globus_${component}_LIBNAME}")
      else()
        set(libname "globus_${component}")
      endif()
      find_library(
        Globus_${component}_LIBRARY
        NAMES "${libname}" "lib${libname}"
        HINTS "${PC_Globus_${component}_LIBRARY_DIRS}" "${PC_Globus_${component}_LIBDIR}"
        DOC "${pc_name} main library"
      )
      mark_as_advanced(FORCE Globus_${component}_LIBRARY)
      set(_Globus_${component}_LIBRARIES "${PC_Globus_${component}_LINK_LIBRARIES}")
      if (Globus_${component}_LIBRARY AND NOT Globus_${component}_LIBRARY IN_LIST _Globus_${component}_LIBRARIES)
        list(INSERT _Globus_${component}_LIBRARIES 0 "${Globus_${component}_LIBRARY}")
      endif()
      if (NOT _Globus_${component}_LIBRARIES)
        set(_Globus_${component}_LIBRARIES "Globus_${component}_LIBRARIES-NOTFOUND")
      endif()
      set(Globus_${component}_LIBRARIES "${_Globus_${component}_LIBRARIES}" CACHE STRING "${libs_docstring}")
    endif()
  endif()
  _fg_debug("Globus_${component}_LIBRARIES = ${Globus_${component}_LIBRARIES}")

  set(compile_options_docstring "compile options for building with ${pc_name}")
  if (Globus_${component}_COMPILE_OPTIONS)
    set(Globus_${component}_COMPILE_OPTIONS "${Globus_${component}_COMPILE_OPTIONS}" CACHE STRING "${compile_options_docstring}")
  else()
    set(_Globus_${component}_COMPILE_OPTIONS "${PC_Globus_${component}_CFLAGS_OTHER}")
    if (NOT _Globus_${component}_COMPILE_OPTIONS)
      set(_Globus_${component}_COMPILE_OPTIONS "")
    endif()
    set(Globus_${component}_COMPILE_OPTIONS "${_Globus_${component}_COMPILE_OPTIONS}" CACHE STRING "${compile_options_docstring}")
  endif()
  mark_as_advanced(FORCE Globus_${component}_COMPILE_OPTIONS)

  set(link_options_docstring "link options for building with ${pc_name}")
  if (Globus_${component}_LINK_OPTIONS)
    set(Globus_${component}_LINK_OPTIONS "${Globus_${component}_LINK_OPTIONS}" CACHE STRING "${link_options_docstring}")
  else()
    set(_Globus_${component}_LINK_OPTIONS "${PC_Globus_${component}_LDFLAGS_OTHER}")
    if (NOT _Globus_${component}_LINK_OPTIONS)
      set(_Globus_${component}_LINK_OPTIONS "")
    endif()
    set(Globus_${component}_LINK_OPTIONS "${_Globus_${component}_LINK_OPTIONS}" CACHE STRING "${link_options_docstring}")
  endif()
  mark_as_advanced(FORCE Globus_${component}_LINK_OPTIONS)

  if (PC_Globus_${component}_VERSION)
    set(likely_version "${PC_Globus_${component}_VERSION}")

    # try to confirm that we're actually using the systemd pkgconf points us to
    set(pc_version_reasonably_certain FALSE)
    if (Globus_${component}_INCLUDE_DIRS)
      _fg_check_list_equivalence(Globus_${component}_INCLUDE_DIRS PC_Globus_${component}_INCLUDE_DIRS include_dirs_pc_equiv)
      if (include_dirs_pc_equiv)
        if (Globus_${component}_LIBRARIES)
          _fg_check_list_equivalence(Globus_${component}_LIBRARIES PC_Globus_${component}_LINK_LIBRARIES libs_pc_equiv)
          if (libs_pc_equiv)
            set(pc_version_reasonably_certain TRUE)
          endif()
        elseif (_Globus_${component}_NOLIB)
          set(pc_version_reasonably_certain TRUE)
        endif()
      endif()
    endif()
    if (pc_version_reasonably_certain)
      set(Globus_${component}_VERSION "${PC_Globus_${component}_VERSION}" PARENT_SCOPE)
      set(_Globus_last_version_found "${Globus_${component}_VERSION}" PARENT_SCOPE)
    endif()
  endif()

  if (Globus_${component}_INCLUDE_DIRS AND (Globus_${component}_LIBRARIES OR _Globus_${component}_NOLIB))
    set(Globus_${component}_FOUND TRUE PARENT_SCOPE)

    add_library(Globus::${component} INTERFACE IMPORTED)
    set_target_properties(
      Globus::${component}
      PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${Globus_${component}_INCLUDE_DIRS}"
      INTERFACE_COMPILE_OPTIONS "${Globus_${component}_COMPILE_OPTIONS}"
      INTERFACE_LINK_OPTIONS "${Globus_${component}_LINK_OPTIONS}"
    )
    if (Globus_${component}_LIBRARIES)
      set_target_properties(
        Globus::${component}
        PROPERTIES
        INTERFACE_LINK_LIBRARIES "${Globus_${component}_LIBRARIES}"
      )
    endif()
    if (Globus_${component}_VERSION)
      set_target_properties(
        Globus::${component}
        PROPERTIES
        VERSION "${Globus_${component}_VERSION}"
      )
    endif()
  else()
    set(Globus_${component}_FOUND FALSE PARENT_SCOPE)
  endif()
  _fg_debug("Globus_${component}_FOUND = ${Globus_${component}_FOUND}")
endfunction()

if (Globus_FIND_COMPONENTS)
  set(_Globus_FIND_COMPONENTS "${Globus_FIND_COMPONENTS}")
else()
  set(_Globus_FIND_COMPONENTS "${_Globus_FIND_COMPONENTS_known}")
endif()

list(REMOVE_DUPLICATES _Globus_FIND_COMPONENTS)

foreach (_component IN LISTS _Globus_FIND_COMPONENTS)
  _Globus_find_component(${_component})
  list(APPEND Globus_INCLUDE_DIRS "${Globus_${_component}_INCLUDE_DIRS}")
  list(APPEND Globus_LIBRARIES "${Globus_${_component}_LIBRARIES}")
endforeach()
# Not cache variables as components list could change
list(REMOVE_DUPLICATES Globus_INCLUDE_DIRS)
list(REMOVE_DUPLICATES Globus_LIBRARIES)

if (_Globus_last_version_found)
  set(_Globus_knowversion TRUE)
  foreach (_component IN LISTS _Globus_FIND_COMPONENTS)
    if (NOT Globus_${_component}_VERSION STREQUAL _Globus_last_version_found)
      set(_Globus_knowversion FALSE)
    endif()
  endforeach()
  if (_Globus_knowversion)
    set(Globus_VERSION "${_Globus_last_version_found}")
  endif()
endif()

include(FindPackageHandleStandardArgs)
# CMake >= 3.18 does not require REQUIRED_VARS when HANDLE_COMPONENTS is specified
if(CMAKE_VERSION VERSION_LESS "3.18")
  set(_fphsa_vv1 "REQUIRED_VARS")
  set(_fphsa_vv2 "Globus_INCLUDE_DIRS")
else()
  unset(_fphsa_vv1)
  unset(_fphsa_vv2)
endif()
if (Globus_VERSION)
  set(_fphsa_vv3 "VERSION_VAR")
  set(_fphsa_vv4 "Globus_VERSION")
else()
  unset(_fphsa_vv3)
  unset(_fphsa_vv4)
endif()
find_package_handle_standard_args(
  Globus
  ${_fphsa_vv1} ${_fphsa_vv2}
  ${_fphsa_vv3} ${_fphsa_vv4}
  HANDLE_COMPONENTS
)

cmake_policy(POP)
