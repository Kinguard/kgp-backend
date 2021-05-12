set( applib_src
	OpiBackendApp.cpp
	OpiBackendServer.cpp
	WebClient.cpp
	)

include_directories ( "${LIBOPI_INCLUDE_DIRS}" )
add_library(applib ${applib_src})
