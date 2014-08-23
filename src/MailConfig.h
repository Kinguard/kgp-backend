#ifndef MAILCONFIG_H
#define MAILCONFIG_H

#include <libutils/FileUtils.h>
#include <libutils/String.h>
#include <libutils/Logger.h>
#include <map>
#include <string>
#include <tuple>

using namespace std;
using namespace Utils;

#include "Config.h"

class MailMapFile
{
public:
	MailMapFile(const string& aliasfile);

	virtual void ReadConfig();
	virtual void WriteConfig();

	virtual void ChangeDomain(const string& from, const string& to);

	void SetAddress(const string& domain, const string& address, const string& user);
	void DeleteAddress(const string& domain, const string& address);
	list<tuple<string,string>> GetAddresses(const string& domain);

	virtual ~MailMapFile();
protected:
	inline bool hasDomain(const string& domain);
	inline bool hasAddress(const string& domain, const string& address);

	// <Domain, <remote user, local user>>
	map<string, map<string,string> > config;

	string aliasesfile;
};

class MailConfig: public MailMapFile
{
public:
	MailConfig(const string& aliasfile=ALIASES,const string& domainfile=DOMAINFILE);

	virtual void ReadConfig();
	virtual void WriteConfig();

	void AddDomain(const string& domain);
	void DeleteDomain(const string& domain);
	list<string> GetDomains();


	virtual ~MailConfig();
private:
	string domainfile;
};

#endif // MAILCONFIG_H
