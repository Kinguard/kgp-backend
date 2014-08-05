pkg_check_modules( CPPUNIT cppunit>=1.12.1 )

set( testapp_src
	test.cpp
	TestMailConfig.cpp
	)

include_directories(
    "${PROJECT_SOURCE_DIR}/src"
    "${LIBJSONCPP_INCLUDE_DIRS}"
)

add_definitions( -std=c++11 )
add_executable( testapp ${testapp_src} )

target_link_libraries( testapp applib ${CPPUNIT_LDFLAGS} ${LIBCRYPTO++_LDFLAGS} ${LIBUTILS_LDFLAGS})

