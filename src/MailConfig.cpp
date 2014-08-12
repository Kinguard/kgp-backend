#include "MailConfig.h"
#include <sstream>

#include <stdexcept>

MailConfig::MailConfig(const string &aliasfile, const string &domainfile)
	: MailMapFile(aliasfile), domainfile(domainfile)
{
	this->ReadConfig();
}

void MailConfig::ReadConfig()
{

	MailMapFile::ReadConfig();

	// Read domains since it could be that we have domains without users(??)
	list<string> dm = File::GetContent( this->domainfile);

	for( string line: dm)
	{
		if( this->config.find( line ) == this->config.end() )
		{
			this->config[line] = map<string,string>();
		}
	}
}

void MailConfig::AddDomain(const string &domain)
{
	if( ! this->hasDomain(domain) )
	{
		this->config[domain] = map<string,string>();
	}
}

void MailConfig::DeleteDomain(const string &domain)
{
	if( ! this->hasDomain( domain ) )
	{
		throw runtime_error("Domain not found");
	}

	this->config.erase(domain);
}

list<string> MailConfig::GetDomains()
{
	list<string> domains;
	for(auto dom: this->config)
	{
		domains.push_back(dom.first);
	}
	return domains;
}

void MailConfig::WriteConfig()
{
	MailMapFile::WriteConfig();

	stringstream domains;

	for(auto entries: this->config )
	{
		domains << entries.first << endl;
	}

	if( this->domainfile != "" )
	{
		File::Write(this->domainfile, domains.str(), 0640 );
	}
}

MailConfig::~MailConfig()
{

}

/*
 * Implementation of mailmapfile
 */

MailMapFile::MailMapFile(const string &aliasfile): aliasesfile(aliasfile)
{

}

void MailMapFile::ReadConfig()
{
	this->config.clear();

	// Read aliases
	list<string> al = File::GetContent( this->aliasesfile);

	for( string line: al)
	{
		line = String::Trimmed(line," ");

		// Skip empty lines and comments
		if( line.size() == 0 || line[0]=='#' )
		{
			continue;
		}

		list<string> parts = String::Split(line, "\t");
		if( parts.size() == 2 )
		{
			string email=parts.front();
			string path =parts.back();
			list<string> mailparts = String::Split(email, "@");
			list<string> pathparts = String::Split(path,"/",2);
			if( mailparts.size() == 2 && pathparts.size() == 2 )
			{
				this->config[mailparts.back()][mailparts.front()] = pathparts.front();
			}
			else
			{
				throw runtime_error("Malformed syntax entry in alias file");
			}
		}
		else
		{
			throw runtime_error("Malformed syntax entry in alias file");
		}
	}

}

void MailMapFile::WriteConfig()
{
	stringstream aliases;

	for(auto entries: this->config )
	{
		for(auto users: entries.second)
		{
			aliases << users.first<<"@"<<entries.first<<"\t"<<users.second<<"/mail/"<<endl;
		}
	}

	if( this->aliasesfile != "" )
	{
		File::Write(this->aliasesfile, aliases.str(), 0640 );
	}
}

bool MailMapFile::hasAddress(const string &domain, const string &address)
{
	return this->hasDomain(domain) && ( this->config[domain].find(address) != this->config[domain].end() );
}

bool MailMapFile::hasDomain(const string &domain)
{
	return this->config.find(domain) != this->config.end();
}


void MailMapFile::SetAddress(const string &domain, const string &address, const string &user)
{
	this->config[domain][address]=user;
}

void MailMapFile::DeleteAddress(const string &domain, const string &address)
{
	if( ! this->hasAddress(domain, address) )
	{
		throw runtime_error("Address not found");
	}

	this->config[domain].erase(address);
}

list<tuple<string, string> > MailMapFile::GetAddresses(const string &domain)
{

	if( ! this->hasDomain(domain) )
	{
		throw runtime_error("No such domain");
	}

	list<tuple<string, string> > adresses;
	for(auto address: this->config[domain] )
	{
		adresses.push_back( make_tuple(address.first, address.second));
	}

	return adresses;
}

MailMapFile::~MailMapFile()
{

}
