project(opi-backend)
cmake_minimum_required(VERSION 2.8)

include( FindPkgConfig )
pkg_check_modules ( LIBOPI REQUIRED libopi>=1.6.44 )
pkg_check_modules  ( LIBKINGUARD REQUIRED libkinguard )
pkg_check_modules ( LIBNOTIFY REQUIRED libkgpnotify )

set (OPIB_VERSION_MAJOR 1)
set (OPIB_VERSION_MINOR 0)
set (OPIB_APP_NAME "opi-backend")

set (APP_PATH "${PROJECT_BINARY_DIR}")
set (SRC_PATH "${PROJECT_SOURCE_DIR}")

if(APP_BUILD MATCHES deb)
		set ( APP_BUILD_PACKAGE 1 )
else()
		set ( APP_BUILD_LOCAL 1 )
endif()

configure_file (
	"${PROJECT_SOURCE_DIR}/Config.h.in"
	"${PROJECT_BINARY_DIR}/Config.h"
)

include_directories("${PROJECT_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/src")

add_subdirectory( src )
add_subdirectory( test )

aux_source_directory(. SRC_LIST)

include_directories (
		"${LIBOPI_INCLUDE_DIRS}"
		${LIBKINGUARD_INCLUDE_DIRS}
	)

add_definitions( -std=c++11 )
add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries( ${PROJECT_NAME} applib -ljsoncpp ${LIBOPI_LDFLAGS} ${LIBNOTIFY_LDFLAGS} ${LIBKINGUARD_LDFLAGS} -lkgpnotify)

enable_testing()
add_test( NAME TestApp COMMAND testapp )

install( TARGETS opi-backend DESTINATION sbin )

