add_library(
	irods_globus_irodsmap
	OBJECT
	"${CMAKE_CURRENT_SOURCE_DIR}/src/libirodsmap.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/include/libirodsmap.h"
)
objects_link_libraries(
	irods_globus_irodsmap
	PUBLIC
	irods_client
)
target_include_directories(
	irods_globus_irodsmap
	PUBLIC
	"$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
)
target_compile_definitions(
	irods_globus_irodsmap
	PRIVATE
	${IRODS_COMPILE_DEFINITIONS}
	${IRODS_COMPILE_DEFINITIONS_PRIVATE}
)
set_target_properties(
	irods_globus_irodsmap
	PROPERTIES
	INTERFACE_POSITION_INDEPENDENT_CODE TRUE
	POSITION_INDEPENDENT_CODE TRUE
)

if (IRODS_BUILD_TESTS)
	add_executable(
		testirodsmap
		"${CMAKE_CURRENT_SOURCE_DIR}/test/testirodsmap.c"
	)
	target_link_objects(
		testirodsmap
		PRIVATE
		irods_globus_irodsmap
	)
	set_target_properties(
		testirodsmap
		PROPERTIES
		BUILD_WITH_INSTALL_RPATH "${IRODS_TESTS_BUILD_WITH_INSTALL_RPATH}"
	)

	install(
		TARGETS testirodsmap
		RUNTIME
		DESTINATION "${CMAKE_INSTALL_BINDIR}"
	)
endif()
