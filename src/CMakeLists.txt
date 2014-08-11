set( applib_src
	OpiBackendApp.cpp
	OpiBackendServer.cpp
	FetchmailConfig.cpp
	SmtpClientConfig.cpp
	MailConfig.cpp
	Secop.cpp
	)

include_directories ( "${LIBJSONCPP_INCLUDE_DIRS}" )
add_definitions( -std=c++11 )
add_library(applib ${applib_src})

target_link_libraries( applib jsoncpp ${LIBCRYPTO++_LDFLAGS})
