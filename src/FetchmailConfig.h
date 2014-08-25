#ifndef FETCHMAILCONFIG_H
#define FETCHMAILCONFIG_H

#include <map>
#include <list>
#include <string>

#include <libutils/Regex.h>
#include <libutils/ConfigFile.h>

using namespace std;
using namespace Utils;

struct userinfo
{
	string password;
	string user;
	bool use_ssl;
};

class FetchmailConfig
{
public:
	FetchmailConfig(const string& cfgpath);

	void AddAccount(const string& email, const string& host, const string& identity, const string& password, const string& user, bool use_ssl=false);
	void UpdateAccount(const string& email, const string& host, const string& identity, const string& password, const string& user, bool use_ssl=false);

	list<string> GetHosts();

	map<string,string> GetAccount( const string& host, const string& identity );
	list<map<string,string>> GetAccounts( const string& user="");

	void DeleteAccount( const string& host, const string& identity );

	void ReadConfig();
	void WriteConfig();

	virtual ~FetchmailConfig();
private:
	bool _hasuser( const string& host, const string& identity);
	string configfile;
	// <host < identity < password, user > > >
	//map<string, map<string, pair<string,string> > > config;
	map<string, map<string, struct userinfo > > config;
	Regex host, user;
	ConfigFile cfgfile;
};

#endif // FETCHMAILCONFIG_H
