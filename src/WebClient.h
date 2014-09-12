#ifndef WEBCLIENT_H
#define WEBCLIENT_H

#include <string>
#include <memory>
#include <list>

#include <libopi/Secop.h>

using namespace std;
using namespace OPI;

class WebClient
{
public:
	WebClient(const string& username, SecopPtr secop);

	bool Timedout();
	void Touch();

	string Username();
	string Token();
	SecopPtr Secop();
	bool IsAdmin();


	virtual ~WebClient();
private:
	string username;
	SecopPtr secop;
	string	token;
	bool isadmin;
	time_t	lastaccess;
};

typedef shared_ptr<WebClient> WebClientPtr;


class Clients
{
public:
	Clients();

	WebClientPtr CreateNewClient( const string& username, SecopPtr secop);

	bool IsUsernameLoggedin( const string& username);
	bool IsTokenLoggedin( const string& token);

	void Reap();

	WebClientPtr GetClientByUsername( const string& username);
	WebClientPtr GetClientByToken( const string& token);

	virtual ~Clients();
private:
	void ReapClient( WebClientPtr wc);
	list<WebClientPtr> clients;
};

#endif // WEBCLIENT_H
