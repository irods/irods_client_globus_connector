add_library(
	globus_gridftp_server_iRODS
	SHARED
	"${CMAKE_CURRENT_SOURCE_DIR}/src/globus_gridftp_server_iRODS.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/include/circular_buffer.hpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/include/lock_and_wait_strategy.hpp"
)
target_link_libraries(
	globus_gridftp_server_iRODS
	PRIVATE
	irods_client
	Globus::common
)
target_link_objects(
	globus_gridftp_server_iRODS
	PRIVATE
	irods_globus_pid_manager
	irods_globus_hasher
)
target_include_directories(
	globus_gridftp_server_iRODS
	PRIVATE
	"${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
	"$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
)
set_target_properties(
	globus_gridftp_server_iRODS
	PROPERTIES
	POSITION_INDEPENDENT_CODE TRUE
	VERSION "${IRODS_CLIENT_VERSION}"
)

install(
	TARGETS globus_gridftp_server_iRODS
	DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)
