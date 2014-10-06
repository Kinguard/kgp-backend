set( applib_src
	FetchmailConfig.cpp
	MailConfig.cpp
	NetworkConfig.cpp
	OpiBackendApp.cpp
	OpiBackendServer.cpp
	SmtpClientConfig.cpp
	WebClient.cpp
	)

include_directories ( "${LIBOPI_INCLUDE_DIRS}" )
add_definitions( -std=c++11 )
add_library(applib ${applib_src})
