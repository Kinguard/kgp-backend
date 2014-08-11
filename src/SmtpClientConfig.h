#ifndef SMTPCLIENTCONFIG_H
#define SMTPCLIENTCONFIG_H

#include <string>
#include <map>
#include <memory>

#include <libutils/Regex.h>

using namespace std;
using namespace Utils;

typedef struct
{
	bool enabled;
	string host;
	string port;
	string user;
	string pass;
} passwdline;

class PostConfInterface
{
public:

	virtual void ReadConfig() = 0;
	virtual void WriteConfig() = 0;

	string getRelayhost() const;
	void setRelayhost(const string &value);

	bool getEnable() const;
	void setEnable(bool value);

protected:
	string relayhost;
	bool enable;
};

typedef shared_ptr<PostConfInterface> PostConfInterfacePtr;

/*
 * Default implementation of interface
 */
class Postconf: public PostConfInterface
{
	virtual void ReadConfig();
	virtual void WriteConfig();
};

class SmtpClientConfig
{
public:
	SmtpClientConfig( const string& path, PostConfInterfacePtr pi = PostConfInterfacePtr(new Postconf) );

	void ReadConfig();
	void WriteConfig();

	passwdline GetConfig();
	void SetConfig( const passwdline& cfg);

	void dump();

	virtual ~SmtpClientConfig();
private:

	PostConfInterfacePtr postconf;
	void _parsesasl();
	void _writesasal();
	string path;
	Regex lreg;

	string user;
	string password;
	map<string, passwdline> passwd;
};

#endif // SMTPCLIENTCONFIG_H
