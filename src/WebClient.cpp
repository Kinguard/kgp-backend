
#include <algorithm>

#include "WebClient.h"
#include "Config.h"

#include <libutils/Logger.h>
#include <libutils/String.h>

using namespace Utils;

WebClient::WebClient(const string &username, SecopPtr secop) : username(username), secop(secop)
{
	logg << Logger::Debug << "Creating new connection for "<<username<<lend;

	vector<string> members = secop->GetGroupMembers( "admin" );
	this->isadmin = find(members.begin(), members.end(), username ) != members.end();

	this->token = String::UUID();
	this->lastaccess = time(nullptr);
}

bool WebClient::Timedout()
{
	return this->lastaccess + SESSION_TIMEOUT < time(nullptr);
}

void WebClient::Touch()
{
	this->lastaccess = time(nullptr);
}

string WebClient::Username()
{
	return this->username;
}

string WebClient::Token()
{
	return this->token;
}

SecopPtr WebClient::Secop()
{
	return this->secop;
}

bool WebClient::IsAdmin()
{
	return this->isadmin;
}

WebClient::~WebClient()
{
	logg << Logger::Debug << "Terminating connection for "<<this->username << lend;
}

/*
 *
 * Implementation of clients class
 *
 */

Clients::Clients()
{

}

WebClientPtr Clients::CreateNewClient(const string &username, SecopPtr secop)
{
	if( this->IsUsernameLoggedin( username ) )
	{
		logg << Logger::Crit << "User "<< username << " already exists in clients" << lend;
		return this->GetClientByUsername( username );
	}

	WebClientPtr client(new WebClient(username, secop) );
	this->clients.push_back(client);

	return client;
}

bool Clients::IsUsernameLoggedin(const string &username)
{
	return find_if(
				this->clients.begin(),
				this->clients.end(),
				[username](WebClientPtr c) { return c->Username() == username; } ) != this->clients.end();

}

bool Clients::IsTokenLoggedin(const string &token)
{
	return find_if(
				this->clients.begin(),
				this->clients.end(),
				[token](WebClientPtr c) { return c->Token() == token; } ) != this->clients.end();
}

void Clients::ReapClient(WebClientPtr wc)
{
	logg << Logger::Debug << "Reap " << wc->Username() << " token " << wc->Token() << lend;

	auto it = find( this->clients.begin(), this->clients.end(), wc );

	if( it == this->clients.end() )
	{
		logg << Logger::Crit << "Client " << wc->Username() << " not found!"<<lend;
		return;
	}
	this->clients.erase( it );
}

void Clients::Reap(bool purgeall)
{
	list<WebClientPtr> toReap;

	for( WebClientPtr client: this->clients )
	{
		if( purgeall || client->Timedout() )
		{
			toReap.push_back( client );
		}
	}

	logg << Logger::Debug << "About to reap "<<toReap.size() << " clients of "<< this->clients.size() << " active"<<lend;

	for( WebClientPtr client: toReap )
	{
		this->ReapClient( client );
	}
}

void Clients::Purge()
{
	logg << Logger::Notice << "About to purge all web clients" << lend;

	this->Reap(true);
}

WebClientPtr Clients::GetClientByUsername(const string &username)
{
	for( WebClientPtr client: this->clients )
	{
		if( client->Username() == username )
		{
			client->Touch();
			return client;
		}
	}
	return nullptr;
}

WebClientPtr Clients::GetClientByToken(const string &token)
{
	for( WebClientPtr client: this->clients )
	{
		if( client->Token() == token )
		{
			client->Touch();
			return client;
		}
	}
	return nullptr;

}

Clients::~Clients()
{

}

