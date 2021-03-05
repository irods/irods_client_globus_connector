##############################################################################
# Copyright (c) 2013 CINECA (www.hpc.cineca.it)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#
# Globus DSI to manage data on iRODS.
#
# Author: Roberto Mucci - SCAI - CINECA
# Email:  hpc-service@cineca.it
#
###############################################################################

cmake_minimum_required (VERSION 3.11 FATAL_ERROR)

find_package(IRODS 4.2.8 EXACT REQUIRED CONFIG)
include(RequireOutOfSourceBuild)

set(CMAKE_C_COMPILER ${IRODS_EXTERNALS_FULLPATH_CLANG}/bin/clang)
set(CMAKE_CXX_COMPILER ${IRODS_EXTERNALS_FULLPATH_CLANG}/bin/clang++)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(GNUInstallDirs)
if (NOT DEFINED ENV{DEST_LIB_DIR})
    set(ENV{DEST_LIB_DIR} "/${CMAKE_INSTALL_LIBDIR}")
    #set(ENV{DEST_LIB_DIR} "/usr/lib64")
    # Note: this may have to be lib64 on 64-bit platforms.
endif()
message("DEST_LIB_DIR is defined as $ENV{DEST_LIB_DIR}")
message("CMAKE_INSTALL_LIBDIR is defined as ${CMAKE_INSTALL_LIBDIR}")
message("CMAKE_INSTALL_FULL_LIBDIR is defined as ${CMAKE_INSTALL_FULL_LIBDIR}")

project (iRODS_DSI C CXX)
include(UseLibCXX)
set(GENERIC_LIB_VERSION "1.8")

##### Check ENV variables ######
if (DEFINED ENV{GLOBUS_LOCATION})
    message("GLOBUS_LOCATION is defined as $ENV{GLOBUS_LOCATION}")
else()
    set(ENV{GLOBUS_LOCATION} "/usr")
endif()

##### iRODS #####
set(IRODS_PLUGIN_REVISION "0")

if (NOT IRODS_EXTERNALS_PACKAGE_ROOT)
  set(IRODS_EXTERNALS_PACKAGE_ROOT "/opt/irods-externals" CACHE STRING "Choose the location of iRODS external packages." FORCE)
  message(STATUS "Setting unspecified IRODS_EXTERNALS_PACKAGE_ROOT to '${IRODS_EXTERNALS_PACKAGE_ROOT}'. This is the correct setting for normal builds.")
endif()

macro(IRODS_MACRO_CHECK_DEPENDENCY_SET_FULLPATH DEPENDENCY_NAME DEPENDENCY_SUBDIRECTORY)
  if (IS_DIRECTORY ${IRODS_EXTERNALS_FULLPATH_${DEPENDENCY_NAME}})
    message(STATUS "Using user-specified value for IRODS_EXTERNALS_FULLPATH_${DEPENDENCY_NAME}: ${IRODS_EXTERNALS_FULLPATH_${DEPENDENCY_NAME}}")
  else()
    if (NOT IS_DIRECTORY ${IRODS_EXTERNALS_PACKAGE_ROOT}/${DEPENDENCY_SUBDIRECTORY})
      message(FATAL_ERROR "${DEPENDENCY_NAME} not found at ${IRODS_EXTERNALS_PACKAGE_ROOT}/${DEPENDENCY_SUBDIRECTORY}")
    endif()
    set(IRODS_EXTERNALS_FULLPATH_${DEPENDENCY_NAME} ${IRODS_EXTERNALS_PACKAGE_ROOT}/${DEPENDENCY_SUBDIRECTORY})
  endif()
endmacro()

macro(IRODS_MACRO_CHECK_DEPENDENCY_SET_FULLPATH_ADD_TO_IRODS_PACKAGE_DEPENDENCIES_LIST DEPENDENCY_NAME DEPENDENCY_SUBDIRECTORY)
  IRODS_MACRO_CHECK_DEPENDENCY_SET_FULLPATH(${DEPENDENCY_NAME} ${DEPENDENCY_SUBDIRECTORY})
  list(APPEND IRODS_PACKAGE_DEPENDENCIES_LIST irods-externals-${DEPENDENCY_SUBDIRECTORY})
endmacro()
string(REPLACE ";" ", " IRODS_PACKAGE_DEPENDENCIES_STRING "${IRODS_PACKAGE_DEPENDENCIES_LIST}")
#################


FIND_PACKAGE(CURL)
IF(CURL_FOUND)
    INCLUDE_DIRECTORIES(${CURL_INCLUDE_DIR})
    SET(requiredlibs ${requiredlibs} ${CURL_LIBRARIES} )
ELSE(CURL_FOUND)
    MESSAGE(FATAL_ERROR "Could not find the CURL library and development files.")
ENDIF(CURL_FOUND)

set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
add_definitions(-DIRODS_HEADER_HPP)

add_compile_options(-Wall -Wextra -Werror -Wno-unused-parameter)

remove_definitions(-DIRODS_HEADER_HPP)
add_definitions(-DIRODS_42)
set(irods_include_path_list
    "${IRODS_INCLUDE_DIRS}"
    "${IRODS_EXTERNALS_FULLPATH_BOOST}/include"
    "${IRODS_EXTERNALS_FULLPATH_JSON}/include"
    )

set(irods_link_obj_path
    PRIVATE
    irods_client
    irods_common
    irods_plugin_dependencies
    "-lrt"
    "${IRODS_EXTERNALS_FULLPATH_AVRO}/lib/libavrocpp.so"
    "${IRODS_EXTERNALS_PACKAGE_ROOT}/jansson2.7-0/lib/libjansson.so"
    "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_system.so"
    "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_regex.so"
    "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_thread.so"
    "${IRODS_EXTERNALS_FULLPATH_BOOST}/lib/libboost_filesystem.so"
    "/${IRODS_PLUGINS_DIRECTORY}/network/libtcp_client.so"
    "/${IRODS_PLUGINS_DIRECTORY}/network/libssl_client.so"
    "/${IRODS_PLUGINS_DIRECTORY}/auth/libnative_client.so"
    )

if (NOT CPACK_DEBIAN_PACKAGE_VERSION)
    set(CPACK_DEBIAN_PACKAGE_VERSION ${IRODS_CPACK_DEBIAN_PACKAGE_VERSION})
endif()

set(CPACK_PACKAGE_FILE_NAME "irods-gridftp-client${IRODS_PACKAGE_FILE_NAME_SUFFIX}")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENT_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_COMPONENTS_GROUPING IGNORE)
set(CPACK_PACKAGE_VERSION ${IRODS_VERSION})
set(CPACK_PACKAGE_VERSION_MAJOR ${IRODS_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${IRODS_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${IRODS_VERSION_PATCH})
set(CPACK_PACKAGE_CONTACT "Renaissance Computing Institute <info@irods.org>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "The integrated Rule-Oriented Data System")
set(CPACK_PACKAGE_VENDOR "Renaissance Computing Institute <info@irods.org>")

set(CPACK_DEB_COMPONENT_INSTALL OFF)
set(CPACK_DEBIAN_PACKAGE_SECTION "contrib/science")
set(CPACK_DEBIAN_COMPRESSION_TYPE "gzip")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "extra")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://irods.org")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS OFF)
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION ON)

set(CPACK_RPM_COMPONENT_INSTALL OFF)
set(CPACK_RPM_PACKAGE_RELEASE "1")
set(CPACK_RPM_PACKAGE_LICENSE "BSD-3-Clause")
set(CPACK_RPM_PACKAGE_VENDOR "iRODS Consortium")
set(CPACK_RPM_PACKAGE_URL "https://irods.org")
set(CPACK_RPM_PACKAGE_AUTOREQ 0)
set(CPACK_RPM_PACKAGE_AUTOPROV 0)

set(CPACK_ARCHIVE_COMPONENT_INSTALL OFF)

set(CPACK_DEBIAN_PACKAGE_NAME "irods-gridftp-client")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-runtime (= ${CPACK_DEBIAN_PACKAGE_VERSION}), libc6, libssl1.0.0")
#set(CPACK_DEBIAN_PACKAGE_REPLACES "irods-icat, irods-resource")

set(CPACK_RPM_PACKAGE_NAME "irods-gridftp-client")
#set(CPACK_RPM_PACKAGE_OBSOLETES "irods-icat, irods-resource")
if (IRODS_LINUX_DISTRIBUTION_NAME STREQUAL "centos" OR IRODS_LINUX_DISTRIBUTION_NAME STREQUAL "centos linux")
    set(CPACK_RPM_PACKAGE_REQUIRES "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-runtime = ${IRODS_VERSION}, openssl")
elseif (IRODS_LINUX_DISTRIBUTION_NAME STREQUAL "opensuse")
    set(CPACK_RPM_PACKAGE_REQUIRES "${IRODS_PACKAGE_DEPENDENCIES_STRING}, irods-runtime = ${IRODS_VERSION}, libopenssl1_0_0")
endif()

if (NOT CPACK_GENERATOR)
  set(CPACK_GENERATOR ${IRODS_CPACK_GENERATOR} CACHE STRING "CPack generator to use, e.g. {DEB, RPM, TGZ}." FORCE)
  message(STATUS "Setting unspecified CPACK_GENERATOR to ${CPACK_GENERATOR}. This is the correct setting for normal builds.")
endif()

include(CPack)


if (DEFINED ENV{RESOURCE_MAP_PATH})
    message("RESOURCE_MAP_PATH is defined as $ENV{RESOURCE_MAP_PATH}")
else()
    message( WARNING "RESOURCE_MAP_PATH is NOT defined!" )
endif()

if (DEFINED ENV{FLAVOR})
    message("FLAVOR is defined as $ENV{FLAVOR}")
    set(dsi_library_name globus_gridftp_server_iRODS_$ENV{FLAVOR})
    set(gridmap_callout_library_name gridmap_iRODS_callout_$ENV{FLAVOR})
    set(gridmap_callout_library_LINK_FLAGS "-lglobus_gridmap_callout_error")
else()
    set(dsi_library_name globus_gridftp_server_iRODS)
    set(gridmap_callout_library_name gridmap_iRODS_callout)
    set(gridmap_callout_library_LINK_FLAGS "-lglobus_gridmap_callout_error")
endif()

if (NOT DEFINED ENV{DEST_ETC_DIR})
    if ($ENV{GLOBUS_LOCATION} STREQUAL "/usr")
        set(ENV{DEST_ETC_DIR} "/etc/grid-security")
    else()
        set(ENV{DEST_ETC_DIR} "$ENV{GLOBUS_LOCATION}/etc")
    endif()
endif()
message("DEST_ETC_DIR is defined as $ENV{DEST_ETC_DIR}")

if (NOT DEFINED ENV{DEST_BIN_DIR})
    set(ENV{DEST_BIN_DIR} "$ENV{GLOBUS_LOCATION}/bin")
endif()
message("DEST_BIN_DIR is defined as $ENV{DEST_BIN_DIR}")
#################################

message("DSI library name will be: ${dsi_library_name}")
message("Gridmap callout library name will be: ${gridmap_callout_library_name}")

add_library(${dsi_library_name} SHARED DSI/globus_gridftp_server_iRODS.cpp DSI/pid_manager.c external/cJSON.c)
add_library(${gridmap_callout_library_name} SHARED DSI/gridmap_iRODS_callout.c DSI/libirodsmap.c)

set_target_properties(${dsi_library_name} PROPERTIES VERSION ${GENERIC_LIB_VERSION})
set_target_properties(${dsi_library_name} PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(${dsi_library_name} ${irods_link_obj_path} ${CURL_LIBRARIES})

set_target_properties(${gridmap_callout_library_name} PROPERTIES LINK_FLAGS ${gridmap_callout_library_LINK_FLAGS} VERSION ${GENERIC_LIB_VERSION})
set_target_properties(${gridmap_callout_library_name} PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(${gridmap_callout_library_name} ${irods_link_obj_path} ${CURL_LIBRARIES})

set(gridmap_callout_conf_name gridmap_iRODS_callout.conf)

set(testirodsmap_exe "testirodsmap")
set(testirodsmap_exe_LINK_FLAGS "-ldl -lglobus_gss_assist -lstdc++")
add_executable(${testirodsmap_exe} DSI/testirodsmap.c DSI/libirodsmap.c)
set_target_properties(${testirodsmap_exe} PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(${testirodsmap_exe} PROPERTIES LINK_FLAGS ${testirodsmap_exe_LINK_FLAGS})
target_link_libraries(${testirodsmap_exe} ${irods_link_obj_path} ${CURL_LIBRARIES})

set(testpidmanager_exe "testpidmanager")
add_executable(${testpidmanager_exe} DSI/pid_manager_test.c DSI/pid_manager.c external/cJSON.c)
target_link_libraries(${testpidmanager_exe} ${irods_link_obj_path} "-lm -lglobus_gridftp_server" ${CURL_LIBRARIES})

include_directories(${irods_include_path_list})
include_directories(
        $ENV{GLOBUS_LOCATION}/include/globus
        $ENV{GLOBUS_LOCATION}/lib/globus/include
        $ENV{GLOBUS_LOCATION}/lib64/globus/include
        ${CURL_INCLUDE_DIR}
        DSI
        external)
if (DEFINED ENV{FLAVOR})
    include_directories($ENV{GLOBUS_LOCATION}/include/ENV{FLAVOR})
endif()

message(STATUS "PROJECT_BINARY_DIR is ${PROJECT_BINARY_DIR}")

install(TARGETS ${dsi_library_name} ${gridmap_callout_library_name} DESTINATION $ENV{DEST_LIB_DIR})
install(TARGETS ${testirodsmap_exe} DESTINATION $ENV{DEST_BIN_DIR})
install(TARGETS ${testpidmanager_exe} DESTINATION $ENV{DEST_BIN_DIR})
configure_file(DSI/${gridmap_callout_conf_name}.in ${gridmap_callout_conf_name})
install(FILES ${PROJECT_BINARY_DIR}/${gridmap_callout_conf_name} DESTINATION $ENV{DEST_ETC_DIR})

