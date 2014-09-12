set( applib_src
	OpiBackendApp.cpp
	OpiBackendServer.cpp
	FetchmailConfig.cpp
	SmtpClientConfig.cpp
	MailConfig.cpp
	WebClient.cpp
	)

include_directories ( "${LIBOPI_INCLUDE_DIRS}" )
add_definitions( -std=c++11 )
add_library(applib ${applib_src})
