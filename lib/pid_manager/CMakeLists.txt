add_library(
	irods_globus_pid_manager
	OBJECT
	"${CMAKE_CURRENT_SOURCE_DIR}/src/pid_manager.cpp"
	"${CMAKE_CURRENT_SOURCE_DIR}/include/pid_manager.h"
)
objects_link_libraries(
	irods_globus_pid_manager
	PUBLIC
	Globus::gridftp_server
	CURL::libcurl
	nlohmann_json::nlohmann_json
)
target_include_directories(
	irods_globus_pid_manager
	PUBLIC
	"$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
)
target_compile_definitions(
	irods_globus_pid_manager
	PRIVATE
	${IRODS_COMPILE_DEFINITIONS}
	${IRODS_COMPILE_DEFINITIONS_PRIVATE}
)
set_target_properties(
	irods_globus_pid_manager
	PROPERTIES
	INTERFACE_POSITION_INDEPENDENT_CODE TRUE
	POSITION_INDEPENDENT_CODE TRUE
)

if (IRODS_BUILD_TESTS)
	add_executable(
		testpidmanager
		"${CMAKE_CURRENT_SOURCE_DIR}/test/pid_manager_test.cpp"
	)
	target_link_objects(
		testpidmanager
		PRIVATE
		irods_globus_pid_manager
	)
	set_target_properties(
		testpidmanager
		PROPERTIES
		BUILD_WITH_INSTALL_RPATH "${IRODS_TESTS_BUILD_WITH_INSTALL_RPATH}"
	)

	install(
		TARGETS testpidmanager
		RUNTIME
		DESTINATION "${CMAKE_INSTALL_BINDIR}"
	)
endif()
