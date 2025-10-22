add_library(
	gridmap_iRODS_callout
	SHARED
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
	OpenSSL::SSL
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

install(
	TARGETS gridmap_iRODS_callout
	DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)

install(
	FILES
	"${CMAKE_CURRENT_SOURCE_DIR}/gridmap_iRODS_callout.conf"
	DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/grid-security"
)
