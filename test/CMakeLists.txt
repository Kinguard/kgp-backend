pkg_check_modules( CPPUNIT cppunit>=1.12.1 )

set( testapp_src
	test.cpp
	TestMailConfig.cpp
	TestFetchmailConfig.cpp
	TestSmtpClient.cpp
	)

include_directories(
    "${PROJECT_SOURCE_DIR}/src"
)

add_definitions( -std=c++11 )
add_executable( testapp ${testapp_src} )

target_link_libraries( testapp applib ${CPPUNIT_LDFLAGS} ${LIBOPI_LDFLAGS} )

