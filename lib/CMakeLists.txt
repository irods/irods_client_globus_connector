add_subdirectory(pid_manager)
add_subdirectory(irodsmap)

# The iRODS-provided hasher for sha512 is broken in iRODS 5.0.2.
# Only use the iRODS hashers for releases greater than 5.0.2.
# Otherwise, use the locally provided hashers.
if (USE_LOCAL_HASHERS)
	add_subdirectory(globus_hasher)
endif()
add_subdirectory(gridmap_callout)
add_subdirectory(irods_dsi)
