set(IRODS_DSI_LIBRARY_NAME "globus_gridftp_server_iRODS")

if (NOT DEFINED IRODS_DSI_FLAVOR AND Globus_FLAVOR)
	set(IRODS_DSI_FLAVOR "${Globus_FLAVOR}")
endif()
set(IRODS_DSI_FLAVOR "${IRODS_DSI_FLAVOR}" CACHE STRING "Compliation flavor of GridFTP iRODS DSI library")
if (IRODS_DSI_FLAVOR)
	set(IRODS_DSI_LIBRARY_NAME "${IRODS_DSI_LIBRARY_NAME}_${IRODS_DSI_FLAVOR}")
endif()

add_library(
	globus_gridftp_server_iRODS
	MODULE
	"${CMAKE_CURRENT_SOURCE_DIR}/src/globus_gridftp_server_iRODS.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/include/circular_buffer.hpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/include/lock_and_wait_strategy.hpp"
)
target_link_libraries(
	globus_gridftp_server_iRODS
	PRIVATE
	irods_client
	fmt::fmt
	Globus::common
	Globus::gridftp_server
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
set_target_properties(
	globus_gridftp_server_iRODS
	PROPERTIES
	LIBRARY_OUTPUT_NAME "${IRODS_DSI_LIBRARY_NAME}"
)

install(
	TARGETS globus_gridftp_server_iRODS
	LIBRARY
	DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)
