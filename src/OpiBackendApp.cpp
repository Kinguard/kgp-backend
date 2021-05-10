#include "OpiBackendApp.h"

#include "Config.h"

#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>


#include <functional>
#include <memory>

#include <libutils/Logger.h>
#include <libutils/FileUtils.h>
using namespace std::placeholders;


OpiBackendApp::OpiBackendApp():DaemonApplication(OPIB_APP_NAME,"/run", "root", "root")
{

}

void OpiBackendApp::Startup()
{
	// Divert logger to syslog
	openlog( OPIB_APP_NAME, LOG_PERROR, LOG_DAEMON);
	logg.SetOutputter( [](const string& msg){ syslog(LOG_INFO, "%s",msg.c_str());});
	logg.SetLogName("");

	logg << Logger::Info << "Starting"<<lend;

	this->options.AddOption( Option('D', "debug", Option::ArgNone,"0","Debug logging") );

	Utils::SigHandler::Instance().AddHandler(SIGTERM, std::bind(&OpiBackendApp::SigTerm, this, _1) );
	Utils::SigHandler::Instance().AddHandler(SIGINT, std::bind(&OpiBackendApp::SigTerm, this, _1) );
	Utils::SigHandler::Instance().AddHandler(SIGHUP, std::bind(&OpiBackendApp::SigHup, this, _1) );
	Utils::SigHandler::Instance().AddHandler(SIGPIPE, std::bind(&OpiBackendApp::SigPipe, this, _1) );

	unlink(SOCKPATH);
}

void OpiBackendApp::Main()
{
	if( this->options["debug"] == "1" )
	{
		logg << Logger::Info << "Increase logging to debug level "<<lend;
		logg.SetLevel(Logger::Debug);
	}

	this->server = std::make_shared<OpiBackendServer>( SOCKPATH );

	chmod( SOCKPATH, File::UserRW | File::GroupRW | File::OtherRW);

	this->server->Run();

}

void OpiBackendApp::ShutDown()
{
	unlink(SOCKPATH);
	logg << Logger::Debug << "Shutting down"<<lend;
}

OpiBackendApp::~OpiBackendApp() = default;

void OpiBackendApp::SigTerm(int)
{
	logg << Logger::Info << "Got sigterm initiate shutdown"<<lend;
	this->server->ShutDown();
}

void OpiBackendApp::SigHup(int)
{

}

void OpiBackendApp::SigPipe(int)
{
	logg << Logger::Info << "Got SIGPIPE, ignoring"<<lend;
}
