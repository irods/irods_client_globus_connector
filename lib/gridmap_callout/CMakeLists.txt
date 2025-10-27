set(IRODS_CALLOUT_LIBRARY_NAME "globus_gridmap_iRODS_callout")

if (NOT DEFINED IRODS_CALLOUT_FLAVOR AND Globus_FLAVOR)
	set(IRODS_CALLOUT_FLAVOR "${Globus_FLAVOR}")
endif()
set(IRODS_CALLOUT_FLAVOR "${IRODS_CALLOUT_FLAVOR}" CACHE STRING "Compliation flavor of gridmap iRODS callout library")
if (IRODS_CALLOUT_FLAVOR)
	set(IRODS_CALLOUT_LIBRARY_NAME "${IRODS_CALLOUT_LIBRARY_NAME}_${IRODS_CALLOUT_FLAVOR}")
endif()

set(IRODS_CALLOUT_INSTALL_CONFDIR "${CMAKE_INSTALL_SYSCONFDIR}/grid-security" CACHE STRING "Installation directory for iRODS callout authorization configuration")

add_library(
	gridmap_iRODS_callout
	MODULE
	"${CMAKE_CURRENT_SOURCE_DIR}/src/gridmap_iRODS_callout.c"
)
target_link_libraries(
	gridmap_iRODS_callout
	PRIVATE
	Globus::common
	Globus::gridftp_server
	Globus::gridmap_callout_error
	Globus::gsi_credential
	Globus::gss_assist
	Globus::gssapi_error
	Globus::gssapi_gsi
)
target_link_objects(
	gridmap_iRODS_callout
	PRIVATE
	irods_globus_irodsmap
)
set_target_properties(
	gridmap_iRODS_callout
	PROPERTIES
	POSITION_INDEPENDENT_CODE TRUE
	VERSION "${IRODS_CLIENT_VERSION}"
)

set_target_properties(
	gridmap_iRODS_callout
	PROPERTIES
	LIBRARY_OUTPUT_NAME "${IRODS_CALLOUT_LIBRARY_NAME}"
)

install(
	TARGETS gridmap_iRODS_callout
	LIBRARY
	DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)

configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/gridmap_iRODS_callout.conf.in"
	"${CMAKE_CURRENT_BINARY_DIR}/gridmap_iRODS_callout.conf"
)

install(
	FILES
	"${CMAKE_CURRENT_BINARY_DIR}/gridmap_iRODS_callout.conf"
	DESTINATION "${IRODS_CALLOUT_INSTALL_CONFDIR}"
)
