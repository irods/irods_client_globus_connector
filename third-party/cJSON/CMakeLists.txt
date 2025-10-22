add_library(
	irods_globus_cJSON
	OBJECT
	"${CMAKE_CURRENT_SOURCE_DIR}/cJSON.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/cJSON.h"
)
objects_link_libraries(
	irods_globus_cJSON
	PUBLIC
	m
)
target_include_directories(
	irods_globus_cJSON
	PUBLIC
	"$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
)
target_compile_definitions(
	irods_globus_cJSON
	PRIVATE
	${IRODS_COMPILE_DEFINITIONS}
	${IRODS_COMPILE_DEFINITIONS_PRIVATE}
)
set_target_properties(
	irods_globus_cJSON
	PROPERTIES
	INTERFACE_POSITION_INDEPENDENT_CODE TRUE
	POSITION_INDEPENDENT_CODE TRUE
)
