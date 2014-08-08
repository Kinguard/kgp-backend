#ifndef FETCHMAILCONFIG_H
#define FETCHMAILCONFIG_H

#include <map>
#include <list>
#include <string>

#include <libutils/Regex.h>

using namespace std;
using namespace Utils;

class FetchmailConfig
{
public:
	FetchmailConfig(const string& cfgpath);

	void AddAccount(const string& host, const string& identity, const string& password, const string& user);
	void UpdateAccount(const string& host, const string& identity, const string& password, const string& user);

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
	map<string, map<string, pair<string,string> > > config;
	Regex host, user;
};

#endif // FETCHMAILCONFIG_H
