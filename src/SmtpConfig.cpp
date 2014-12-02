#include <iostream>
#include <stdexcept>
#include <sstream>
#include <list>

#include <libutils/String.h>
#include <libutils/FileUtils.h>
#include <libutils/ConfigFile.h>

#include <resolv.h>
#include <libopi/DnsHelper.h>
#include <libopi/AuthServer.h>

#include "SmtpConfig.h"
#include "Config.h"

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

	// Bugfix for #204 "Sätta relay host funkar inte" when relayhost left empty but sasl enabled
	if ( this->postconf->getRelayhost() == "" )
	{
		this->postconf->setEnable(false);
		return;
	}

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
	// Make sure we have no reminder config
	this->passwd.clear();

	if( cfg.host != "")
	{
		host << "["<<cfg.host<<"]";
		if( cfg.port != "" )
		{
			host << ":" << cfg.port;
		}

		this->passwd[host.str()]=cfg;
	}

	this->postconf->setEnable( cfg.enabled );
	this->postconf->setRelayhost( host.str() );
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
	const char* cmd = "/usr/sbin/postconf  relayhost smtp_sasl_auth_enable";
	string ret = exec( cmd );

	list<string> lines = String::Split(ret,"\n");

	if( lines.size() != 2 )
	{
		throw runtime_error("Unable to parse postconf output");
	}

	list<string> words = String::Split( lines.front(),"=");
	if( words.size() == 2 )
	{
		this->relayhost = String::Trimmed( words.back()," \t");
	}

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


SmtpConfig::SmtpConfig(const string &path): cfg(path)
{
	this->getConfig();
}

SmtpConfig::SmtpMode SmtpConfig::GetMode()
{
	return this->mode;
}

void SmtpConfig::SetStandAloneMode()
{

	if( this->mode == SmtpMode::OPI )
	{
		// No change
		return;
	}

	// Else custom or relay, reset
	passwdline pw;
	pw.enabled = false;

	SmtpClientConfig scli( SASLPASSWD );
	scli.SetConfig( pw );

	scli.WriteConfig();

	this->opconf = { false, false};
	this->customconf = {"","","",""};

	if( this->mode == SmtpMode::OPRelay && this->opconf.receive )
	{
		// We used OP relay and OP configed to handle our mail, change
		this->setMX( false );
	}

	this->mode = SmtpMode::OPI;
}

void SmtpConfig::SetOPRelayMode(OPRelayConf &conf)
{

	if( !conf.send && ! conf.receive )
	{
		throw runtime_error("Missing argument for relay settings");
	}

	// Should we use OP server as outgoing relay server?
	if( conf.send )
	{

		stringstream cmd;

		cmd << "/usr/sbin/postconf -e "
			   << "smtp_tls_cert_file = /etc/opi/opi.cert "
			   << "smtp_tls_key_file = /etc/opi/dnspriv.pem ";
		exec(cmd.str());

		passwdline pw;
		pw.enabled = false;
		pw.host = "op-mail.openproducts.com";
		pw.port="587";

		SmtpClientConfig scli( SASLPASSWD );
		scli.SetConfig( pw );

		scli.WriteConfig();
	}
	else
	{
		// Make sure we have no leftover config
		passwdline pw;
		pw.enabled = false;

		SmtpClientConfig scli( SASLPASSWD );
		scli.SetConfig( pw );

		scli.WriteConfig();
	}

	// Tell OP server to forward mail to us!
	if( conf.receive )
	{
		this->setMX( true );
	}
	else if( this->mode == SmtpMode::OPRelay && this->opconf.receive )
	{
		// We used relaymode earlier disable
		this->setMX( false );
	}

	this->opconf = conf;
	this->mode == SmtpMode::OPRelay;
}

OPRelayConf SmtpConfig::GetOPRelayConfig()
{
	if( this->mode != SmtpMode::OPRelay )
	{
		throw runtime_error("Not in OP relay mode");
	}
	return this->opconf;
}

void SmtpConfig::SetCustomMode(OPCustomConf &conf)
{
	passwdline cf;

	cf.host = conf.host;
	cf.port = conf.port;
	cf.enabled = (conf.user != "") && ( conf.pass != "" );

	if( cf.enabled )
	{
		cf.user = conf.user;
		cf.pass = conf.pass;
	}
	this->cfg.SetConfig( cf );
	this->cfg.WriteConfig();

	if( this->mode == SmtpMode::OPRelay && this->opconf.receive )
	{
		this->setMX( false );
	}

	this->customconf = conf;
	this->mode = SmtpMode::Custom;
}

OPCustomConf SmtpConfig::GetOPCustomConfig()
{
	if( this->mode != SmtpMode::Custom )
	{
		throw runtime_error("Not in custom mode");
	}
	return this->customconf;
}

SmtpConfig::~SmtpConfig()
{

}

void SmtpConfig::getConfig()
{
	ConfigFile opicfg(SYS_INFO);
	passwdline pass = cfg.GetConfig();

	string name = opicfg.ValueOrDefault("opi_name");
	if( name == "")
	{
		throw runtime_error("Opiname not found");
	}

	this->opiname = name+".op-i.me";


	this->unit_id = opicfg.ValueOrDefault("unit_id");
	if( this->unit_id == "")
	{
		throw runtime_error("Unit id not found");
	}

	// OP relay?
	if( this->checkMX( ) )
	{
		this->mode = SmtpMode::OPRelay;
		this->opconf.receive = true;

		if( pass.host == OP_RELAYSERVER )
		{
			this->opconf.send = true;
		}

		return;
	}

	// OP relay send only?
	if( pass.host == OP_RELAYSERVER )
	{
		this->mode = SmtpMode::OPRelay;
		this->opconf.receive = false;
		this->opconf.send = true;
		return;
	}

	// OPI stand alone?
	if( pass.host == "" )
	{
		this->mode = SmtpMode::OPI;
		return;
	}

	// Must be custom mode
	this->mode = SmtpMode::Custom;
	this->customconf.host = pass.host;
	this->customconf.pass = pass.pass;
	this->customconf.port = pass.port;
	this->customconf.user = pass.user;
}

bool SmtpConfig::checkMX()
{
	OPI::Dns::DnsHelper dns;

	dns.Query(this->opiname.c_str(), ns_t_mx );

	list<OPI::Dns::rr> answers = dns.getAnswers();

	if( answers.size() == 0 )
	{
		return false;
	}

	for( const OPI::Dns::rr& r: answers )
	{
		if( r.type == ns_t_mx )
		{
			if( dynamic_cast<OPI::Dns::MXData*>( r.data.get() )->exchange == OP_RELAYSERVER )
			{
				return true;
			}
		}
	}

	return false;
}

void SmtpConfig::setMX(bool mxmode)
{
	int resultcode;
	Json::Value ret;

	OPI::AuthServer s( this->unit_id );

	tie(resultcode, ret) = s.Login();

	if( resultcode != 200 )
	{
		throw runtime_error("Unable to authenticate with backend server");
	}
	string token = ret["token"].asString();

	tie(resultcode, ret) = s.UpdateMXPointer(mxmode, token);
	if( resultcode != 200 )
	{
		throw runtime_error("Unable to update MX settings");
	}
}
