#include <libutils/Application.h>

#include "OpiBackendServer.h"

using namespace Utils;


class OpiBackendApp: public DaemonApplication
{
public:

	OpiBackendApp();

	virtual void Startup();
	virtual void Main();
	virtual void ShutDown();

	virtual ~OpiBackendApp();

protected:
	void SigTerm(int);
	void SigHup(int);
	void SigPipe(int);

private:
	OpiBackendServerPtr server;

};
