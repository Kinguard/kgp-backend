#include <libutils/Logger.h>

#include "OpiBackendApp.h"

int main(int argc, char** argv)
{
	logg.SetLevel(Logger::Info);

	int ret;
	try
	{
		OpiBackendApp app;

		ret = app.Start( argc, argv);
	}
	catch(std::runtime_error& err)
	{
		logg << Logger::Error << "Caught runtime exception " << err.what() << lend;
	}

	return ret;
}
