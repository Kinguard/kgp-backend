#include "OpiBackendApp.h"

#include "Config.h"

#include <sys/stat.h>
#include <unistd.h>


#include <functional>

#include <libutils/Logger.h>

using namespace std::placeholders;


OpiBackendApp::OpiBackendApp():DaemonApplication(OPIB_APP_NAME,"/var/run", "root", "root")
{

}

void OpiBackendApp::Startup()
{
	//logg << Logger::Debug << "Starting up"<<lend;

	Utils::SigHandler::Instance().AddHandler(SIGTERM, std::bind(&OpiBackendApp::SigTerm, this, _1) );
	Utils::SigHandler::Instance().AddHandler(SIGINT, std::bind(&OpiBackendApp::SigTerm, this, _1) );
	Utils::SigHandler::Instance().AddHandler(SIGHUP, std::bind(&OpiBackendApp::SigHup, this, _1) );
	Utils::SigHandler::Instance().AddHandler(SIGPIPE, std::bind(&OpiBackendApp::SigPipe, this, _1) );

	unlink(SOCKPATH);
}

void OpiBackendApp::Main()
{
	this->server = OpiBackendServerPtr( new OpiBackendServer( SOCKPATH) );

	chmod( SOCKPATH, 0666);

	this->server->Run();

}

void OpiBackendApp::ShutDown()
{
	unlink(SOCKPATH);
	logg << Logger::Debug << "Shutting down"<<lend;
}

OpiBackendApp::~OpiBackendApp()
{

}

void OpiBackendApp::SigTerm(int signo)
{
	logg << Logger::Info << "Got sigterm initiate shutdown"<<lend;
	this->server->ShutDown();
}

void OpiBackendApp::SigHup(int signo)
{

}

void OpiBackendApp::SigPipe(int signo)
{
	logg << Logger::Info << "Got SIGPIPE, ignoring"<<lend;
}
