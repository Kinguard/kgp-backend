#include "MailConfig.h"
#include <sstream>

#include <stdexcept>
#include <algorithm>

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

void MailMapFile::ChangeDomain(const string &from, const string &to)
{
	if( from =="" || to == "" )
	{
		throw runtime_error("Missing argumet");
	}

	if( this->config.find(from) == this->config.end() )
	{
		throw runtime_error("Domain not found");
	}

	if( this->config.find( to ) != this->config.end() )
	{
		throw runtime_error("Target domain exists");
	}

	map<string,string> domusers = this->config[from];

	this->config.erase(from);
	this->config[to] = domusers;
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

	// Last address?
	if( this->config[domain].empty() )
	{
		this->config.erase(domain);
	}

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

tuple<string, string> MailMapFile::GetAddress(const string &domain, const string &address)
{
	return make_tuple(address,this->config[domain][address]);
}

MailMapFile::~MailMapFile()
{

}


MailAliasFile::MailAliasFile(const string &file): filename(file)
{
	this->ReadConfig();
}

void MailAliasFile::ReadConfig()
{
	this->config.clear();

	// Read aliases
	list<string> lines = File::GetContent( this->filename);

	for( string line: lines)
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
			string users =parts.back();

			list<string> userparts = String::Split(users,",");
			for( auto user: userparts)
			{
				this->config[email].push_back(user);
			}
		}
		else
		{
			throw runtime_error("Malformed syntax entry in alias file");
		}
	}
}

void MailAliasFile::WriteConfig()
{
	stringstream aliases;

	for(auto entries: this->config )
	{
		aliases << entries.first << "\t";
		bool first = true;
		for(auto user: entries.second)
		{
			if( ! first )
			{
				aliases << ",";
			}
			first = false;
			aliases << user;
		}
		aliases<<endl;
	}

	if( this->filename != "" )
	{
		File::Write(this->filename, aliases.str(), 0640 );
	}
}

list<string> MailAliasFile::GetUsers(const string &alias)
{
	if( this->config.find( alias ) == this->config.end() )
	{
		throw runtime_error( "No such alias" );
	}
	return this->config[alias];
}

list<string> MailAliasFile::GetAliases()
{
	list<string> ret;
	for( auto alias: this->config )
	{
		ret.push_back( alias.first );
	}
	return ret;
}

void MailAliasFile::AddUser(const string &alias, const string &user)
{
	if( this->config.find(alias) != this->config.end() )
	{
		if( find( this->config[alias].begin(), this->config[alias].end(), user) != this->config[alias].end() )
		{
			// User exists, nothing needs to be done
			return;
		}
	}
	this->config[alias].push_back(user);
}

void MailAliasFile::RemoveUser(const string &alias, const string &user)
{
	if( this->config.find(alias) == this->config.end() )
	{
		throw runtime_error("No such alias");
	}

	if( find( this->config[alias].begin(), this->config[alias].end(), user) == this->config[alias].end() )
	{
		throw runtime_error("No such user");
	}

	list<string> newlist;
	for( const string& auser: this->config[alias] )
	{
		if( user != auser)
		{
			newlist.push_back( auser );
		}
	}
	if( newlist.size() == 0)
	{
		this->config.erase(alias);
	}
	else
	{
		this->config[alias] = newlist;
	}
}

void MailAliasFile::Dump()
{
	for( auto alias: this->config )
	{
		cout << alias.first << ":";
		for( auto user: alias.second )
		{
			cout  << " "<< user;
		}
		cout << endl;
	}
}

MailAliasFile::~MailAliasFile()
{

}
