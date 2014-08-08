
#include <sstream>

#include "FetchmailConfig.h"

#include <libutils/FileUtils.h>
#include <libutils/String.h>

using namespace Utils;

FetchmailConfig::FetchmailConfig(const string &cfgpath):
	configfile(cfgpath),
	host("^poll\\s+(\\S+)\\s+with proto"),
	user("\\s+user\\s+(\\S+)\\s+there with password\\s+(.+)\\s+is\\s+(\\S+)\\s+here")
{
	this->ReadConfig();
}

void FetchmailConfig::AddAccount(const string &host, const string &identity, const string &password, const string &user)
{
	if( this->_hasuser( host, identity ) )
	{
		throw runtime_error("User already exists");
	}

	this->config[host][identity] = make_pair(password, user);

}

void FetchmailConfig::UpdateAccount(const string &host, const string &identity, const string &password, const string &user)
{
	if( ! this->_hasuser( host, identity ) )
	{
		throw runtime_error("User doesnt exists");
	}

	this->config[host][identity] = make_pair(password, user);
}

list<string> FetchmailConfig::GetHosts()
{
	list<string> hosts;
	for( const auto& host: this->config )
	{
		hosts.push_back( host.first );
	}
	return hosts;
}

map<string, string> FetchmailConfig::GetAccount(const string &host, const string &identity)
{
	if( ! this->_hasuser( host, identity ) )
	{
		throw runtime_error("User doesnt exists");
	}

	return {
		{"host",		host},
		{"identity",	identity},
		{"password",	this->config[host][identity].first},
		{"username",	this->config[host][identity].second},
	};

}

list<map<string, string> > FetchmailConfig::GetAccounts(const string &user)
{
	list<map<string, string> > ret;
	bool fetchall = user == "";
	for( const auto& domain: this->config )
	{
		for( const auto& identity: domain.second )
		{
			map<string,string> userline = this->GetAccount(domain.first, identity.first);
			if( fetchall || user == userline["username"] )
			{
				ret.push_back( userline );
			}
		}
	}

	return ret;
}

void FetchmailConfig::DeleteAccount(const string &host, const string &identity)
{
	if( ! this->_hasuser( host, identity ) )
	{
		throw runtime_error("User doesnt exists");
	}

	this->config[host].erase(identity);

	// Last identity at host?
	if( this->config[host].size() == 0 )
	{
		this->config.erase( host );
	}
}

static inline string getmatchstring(const string& line, Regex::Match m)
{
	return line.substr(m.rm_so, m.rm_eo - m.rm_so);
}

void FetchmailConfig::ReadConfig()
{
	this->config.empty();
	list<string> lines = File::GetContent( this->configfile );

	string lasthost="";
	for( const string& line: lines)
	{
		vector<Regex::Match> m;
		if( (m = host.DoMatch(line)).size() > 1)
		{
			lasthost = line.substr( m[1].rm_so, m[1].rm_eo-m[1].rm_so );
		}
		else if( (m = user.DoMatch(line)).size() == 4 )
		{
			if( lasthost ==  "")
			{
				continue;
			}
			string identity =	String::Trimmed(getmatchstring( line, m[1]), "'\"" );
			string password =	String::Trimmed( getmatchstring( line, m[2]), "'\"" );
			string user =		String::Trimmed( getmatchstring( line, m[3]), "'\"" );
			this->config[lasthost][identity] =
					make_pair( password,user);
		}
	}
}

void FetchmailConfig::WriteConfig()
{
	stringstream out;

	out << "set postmaster \"postmaster\"\n"
		<< "set bouncemail\n"
		<< "set no spambounce\n"
		<< "set properties \"\"\n"
		<< "set daemon 300\n"
		<< "set syslog";

	for( const auto& cfgline: config)
	{
		string host = cfgline.first;

		out << "\npoll "<<host<<" with proto POP3\n";

		map< string, pair<string,string> > users = cfgline.second;
		for( const auto& user: users )
		{
			out << "\tuser '"<<user.first <<"' there with password '"<<user.second.first << "' is '"<<user.second.second<< "' here\n";
		}
	}

	File::Write( this->configfile, out.str(), 0600);
}

FetchmailConfig::~FetchmailConfig()
{

}

bool FetchmailConfig::_hasuser(const string &host, const string &identity)
{
	return ( this->config.find(host) != this->config.end() ) &&
			( this->config[host].find(identity) != this->config[host].end() );
}
