cmake_minimum_required(VERSION 3.12...3.18 FATAL_ERROR)
if (POLICY CMP0121)
	# Detect invalid indices in list()
	cmake_policy(SET CMP0121 NEW)
endif()
if (POLICY CMP0125)
	# Consistent behavior for cache variables managed by find_*()
	cmake_policy(SET CMP0125 NEW)
endif()
if (POLICY CMP0132)
	# Consistent handling of compiler environment variables
	cmake_policy(SET CMP0132 NEW)
endif()
if (POLICY CMP0144)
	# Allow for uppercased <PACKAGENAME>_ROOT variables.
	cmake_policy(SET CMP0144 NEW)
endif()

list(INSERT CMAKE_MODULE_PATH 0 "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

set(IRODS_MINIMUM_VERSION "4.90.0")
set(IRODS_MAXIMUM_VERSION "6.0.0")
find_package(IRODS "${IRODS_MINIMUM_VERSION}...<${IRODS_MAXIMUM_VERSION}" REQUIRED)

include(RequireOutOfSourceBuild)

set(IRODS_CLIENT_NAME "irods-gridftp-client")
set(IRODS_CLIENT_VERSION "5.0.1")
set(IRODS_PACKAGE_REVISION "1")

include(IrodsExternals)
include(IrodsCXXCompiler)

set(CMAKE_CXX_STANDARD ${IRODS_CXX_STANDARD})
set(CMAKE_CXX_EXTENSIONS OFF)

# export-dynamic so stacktrace entries from executables have function names.
set(CMAKE_EXE_LINKER_FLAGS_INIT "-Wl,--export-dynamic -Wl,--enable-new-dtags -Wl,--as-needed -Wl,-z,defs")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "-Wl,--enable-new-dtags -Wl,--as-needed -Wl,-z,defs")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-Wl,--enable-new-dtags -Wl,--as-needed -Wl,-z,defs")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")
set(CMAKE_MODULE_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE_INIT "-Wl,--gc-sections -Wl,-z,combreloc")

include(IrodsRunpathDefaults)

project(${IRODS_CLIENT_NAME} VERSION "${IRODS_CLIENT_VERSION}" LANGUAGES C CXX)

include("${IRODS_TARGETS_PATH}")
include(GNUInstallDirs)

if (NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build {Debug, Release}." FORCE)
	message(STATUS "Setting unspecified CMAKE_BUILD_TYPE to '${CMAKE_BUILD_TYPE}'. This is the correct setting for normal builds.")
endif()

set(IRODS_BUILD_WITH_WERROR OFF CACHE BOOL "Choose whether to compile with -Werror.")

if (IRODS_BUILD_WITH_WERROR)
	add_compile_options(-Werror)
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-fpermissive>)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

include(ObjectTargetHelpers)

find_package(CURL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto SSL)
find_package(
	Globus
	REQUIRED
	COMPONENTS
	common
	gridftp_server
	gridmap_callout_error
	gsi_credential
	gss_assist
	gssapi_error
	gssapi_gsi
)

add_subdirectory(third-party)
add_subdirectory(lib)

include(IrodsCPackCommon)

set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENT_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENTS_GROUPING IGNORE)
set(CPACK_PACKAGE_VERSION ${IRODS_CLIENT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "The integrated Rule-Oriented Data System")

set(CPACK_DEB_COMPONENT_INSTALL OFF)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION ON)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

set(CPACK_RPM_COMPONENT_INSTALL OFF)
set(CPACK_RPM_PACKAGE_LICENSE "Apache-2.0")
set(CPACK_RPM_PACKAGE_AUTOREQ 0)
set(CPACK_RPM_PACKAGE_AUTOPROV 0)
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)

set(CPACK_ARCHIVE_COMPONENT_INSTALL OFF)

# The Globus packages for Debian and Ubuntu have soversions in the package
# names. We cannot currently discern these reliably without making dangerous
# assumptions about the build environment. Therefore, we do not currently
# declare dependencies on Globus packages. We do the same for EL for the sake of
# consistency, despite the fact that the EL pacakge names are not versioned.

set(CPACK_DEBIAN_PACKAGE_NAME "${IRODS_CLIENT_NAME}")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-runtime (= ${IRODS_VERSION}), libc6")

get_filename_component(CURL_LIBRARY_REALPATH ${CURL_LIBRARY} REALPATH)
get_filename_component(CURL_LIBRARY_REALNAME ${CURL_LIBRARY_REALPATH} NAME_WE)
if (CURL_LIBRARY_REALNAME STREQUAL "libcurl-gnutls")
	set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libcurl3-gnutls")
elseif (CURL_LIBRARY_REALNAME STREQUAL "libcurl-nss")
	set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libcurl3-nss")
elseif (CURL_LIBRARY_REALNAME STREQUAL "libcurl")
	set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libcurl4")
endif()
if (OPENSSL_VERSION VERSION_LESS "3.0.0")
	set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libssl1.1")
else()
	set(CPACK_DEBIAN_PACKAGE_DEPENDS "${CPACK_DEBIAN_PACKAGE_DEPENDS}, libssl3")
endif()

set(CPACK_RPM_PACKAGE_NAME ${IRODS_CLIENT_NAME})
set(CPACK_RPM_PACKAGE_REQUIRES "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-runtime = ${IRODS_VERSION}, (libcurl or libcurl-minimum), openssl")

if (NOT CPACK_GENERATOR)
	set(CPACK_GENERATOR ${IRODS_CPACK_GENERATOR} CACHE STRING "CPack generator to use, e.g. {DEB, RPM, TGZ}." FORCE)
	message(STATUS "Setting unspecified CPACK_GENERATOR to ${CPACK_GENERATOR}. This is the correct setting for normal builds.")
endif()

if (CPACK_GENERATOR STREQUAL "DEB")
	install(
		FILES
		"${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
		DESTINATION "${CMAKE_INSTALL_DOCDIR}/${CPACK_DEBIAN_PACKAGE_NAME}"
		RENAME copyright
	)
endif()

include(CPack)
