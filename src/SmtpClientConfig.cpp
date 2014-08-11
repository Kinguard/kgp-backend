#include <iostream>
#include <stdexcept>
#include <sstream>
#include <list>

#include <libutils/String.h>
#include <libutils/FileUtils.h>

#include "SmtpClientConfig.h"

// Forwards for helpers

static inline string getmatchstring(const string& line, Regex::Match m);
static string gethost(const string & host);
static string getport(const string &host);
static string exec(const string &cmd);


SmtpClientConfig::SmtpClientConfig(const string &path, PostConfInterfacePtr pi):
	postconf(pi),
	path(path),
	lreg("^(\\S+)\\s+(.*):(.*)")
{
	this->ReadConfig();
}

void SmtpClientConfig::ReadConfig()
{
	this->postconf->ReadConfig();
	this->_parsesasl();

	//return;
	if( ! this->postconf->getEnable() )
	{
		return;
	}

	if( this->passwd.find(this->postconf->getRelayhost() ) != this->passwd.end() )
	{
		this->user = this->passwd[this->postconf->getRelayhost() ].user;
		this->password = this->passwd[this->postconf->getRelayhost()].pass;
	}
	else
	{
		throw runtime_error(string("Failed to find user credentials for ")+this->postconf->getRelayhost() );
	}

}

void SmtpClientConfig::WriteConfig()
{
	this->postconf->WriteConfig();
	this->_writesasal();
}

passwdline SmtpClientConfig::GetConfig()
{
	passwdline cfg;

	cfg.host = gethost( this->postconf->getRelayhost() );
	cfg.port = getport( this->postconf->getRelayhost() );
	cfg.enabled = this->postconf->getEnable();
	cfg.user = this->user;
	cfg.pass = this->password;

	return cfg;
}

void SmtpClientConfig::SetConfig(const passwdline &cfg)
{

	stringstream host;
	host << "["<<cfg.host<<"]";
	if( cfg.port != "" )
	{
		host << ":" << cfg.port;
	}

	this->postconf->setEnable( cfg.enabled );
	this->postconf->setRelayhost( host.str() );

	this->passwd[host.str()]=cfg;
}

void SmtpClientConfig::dump()
{
	cout << "Sasl config\n";
	cout << "-----------\n";
	cout << "Enabled   : "<< this->postconf->getEnable() <<endl;
	cout << "Relayhost : "<< this->postconf->getRelayhost() <<endl;
	cout << "-----------\n";
	cout << "Username  : "<< this->user<<endl;
	cout << "Password  : "<< this->password<<endl;
#if 0
	for( const auto& p : this->passwd )
	{
		cout << "-----------\n";
		const passwdline line = p.second;
		cout << "Host : "<< line.host << endl;
		cout << "Port : "<< line.port << endl;
		cout << "User : "<< line.user << endl;
		cout << "Pass : "<< line.pass << endl;
	}
#endif
}

SmtpClientConfig::~SmtpClientConfig()
{

}

void SmtpClientConfig::_parsesasl()
{
	list<string> plines = File::GetContent( this->path );
	for( auto line: plines )
	{
		vector<Regex::Match> m = this->lreg.DoMatch(line);
		if( m.size() == 4 )
		{
			string host = getmatchstring( line, m[1]);

			passwdline pwline(
			{
				true, /* Hack since we reuse this for getters/setters */
				gethost( getmatchstring( line, m[1]) ),
				getport( getmatchstring( line, m[1]) ),
				getmatchstring( line, m[2]),
				getmatchstring( line, m[3])
			});

			this->passwd[host] = pwline;
			//this->passwd[host] = "["+user + "] [" + pass+"] ["+port+"]";
		}
	}

}

void SmtpClientConfig::_writesasal()
{
	stringstream out;

	for( auto& line: this->passwd )
	{
		out << line.first <<"\t"<<line.second.user<<":"<<line.second.pass<<endl;
	}
	//cout << endl << "--------------"<<endl << out.str()<<endl;
	File::Write(this->path, out.str(), 0600 );

	exec("/usr/sbin/postmap "+ this->path );
}

static inline string getmatchstring(const string& line, Regex::Match m)
{
	return line.substr(m.rm_so, m.rm_eo - m.rm_so);
}


static string gethost(const string & host)
{
	list<string> parts = String::Split(host,":");
	if( parts.size() == 2  )
	{
		return String::Trimmed( parts.front(),"[]");
	}
	if( parts.size() == 1 )
	{
		return String::Trimmed( host,"[]");
	}
	return "";
}

static string getport(const string &host)
{
	list<string> parts = String::Split(host,":");
	if( parts.size() == 2  )
	{
		return parts.back();
	}
	return "";
}

static string exec(const string& cmd)
{
	FILE* pipe = popen(cmd.c_str(), "r");
	if (!pipe) return "ERROR";
	char buffer[128];
	std::string result = "";
	while(!feof(pipe))
	{
		if(fgets(buffer, 128, pipe) != NULL)
			result += buffer;
	}
	pclose(pipe);
	return result;
}

/*
 *
 * PostConf interface implementation.
 *
 */

string PostConfInterface::getRelayhost() const
{
	return relayhost;
}

void PostConfInterface::setRelayhost(const string &value)
{
	relayhost = value;
}
bool PostConfInterface::getEnable() const
{
	return enable;
}

void PostConfInterface::setEnable(bool value)
{
	enable = value;
}

/*
 *
 * Postconf implementation
 *
 */

void Postconf::ReadConfig()
{
	const char* cmd = "postconf  relayhost smtp_sasl_auth_enable";
	string ret = exec( cmd );

	list<string> lines = String::Split(ret,"\n");

	if( lines.size() != 2 )
	{
		throw runtime_error("Unable to parse postconf output");
	}

	this->relayhost = String::Trimmed( String::Split( lines.front(),"=").back()," \t");
	this->enable = String::Trimmed( String::Split( lines.back(),"=").back()," \t") == "yes";

#if 0
	for( const auto& line: lines)
	{
		cout << "Line {"<<line<<"}"<<endl;
	}
#endif
}

void Postconf::WriteConfig()
{
	stringstream cmd;

	cmd << "/usr/sbin/postconf -e "
		<<"relayhost=\""<<this->relayhost<<"\" "
	   << "smtp_sasl_auth_enable=\"";
	if ( this->enable )
	{
		cmd << "yes";
	}
	else
	{
		cmd << "no";
	}

	cmd <<"\"";

	exec(cmd.str() );

	// cout << cmd.str()<<endl;
}
