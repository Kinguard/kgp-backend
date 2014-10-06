#ifndef NETWORKCONFIG_H
#define NETWORKCONFIG_H

#include <json/json.h>

#include <string>
#include <list>

namespace NetUtils
{

using namespace std;

class NetworkConfig
{
public:
	NetworkConfig(const string& path = "/etc/network/interfaces");


	Json::Value GetInterfaces();
	Json::Value GetInterface(const string& iface);

	void SetInterface(const string &iface, const Json::Value& v);
	void SetDHCP( const string& iface);
	void SetStatic(const string& iface,
					const string& ip,
					const string& nm,
					const string& gw = "");
	void Dump();

	void WriteConfig();

	virtual ~NetworkConfig();
private:
	string path;

	void parse();
	Json::Value cfg;
};

class ResolverConfig
{
public:
	ResolverConfig( const string& path = "/etc/resolv.conf");

	virtual ~ResolverConfig();

	string getDomain() const;
	void setDomain(const string &value);

	string getSearch() const;
	void setSearch(const string &value);

	list<string> getNameservers() const;
	void setNameservers(const list<string> &value);

	void WriteConfig();

	void Dump();
private:
	string path;
	string domain;
	string search;
	list<string> nss;
	void parse();
};

string GetAddress(const string& ifname);
string GetNetmask(const string& ifname);
string GetDefaultRoute();

bool RestartInterface(const string& ifname);

}

#endif // NETWORKCONFIG_H
