#ifndef OPIBACKENDSERVER_H
#define OPIBACKENDSERVER_H

#include <memory>
#include <string>
#include <map>

#include <json/json.h>

#include <libutils/NetServer.h>

#include "Secop.h"
#include "Config.h"

using namespace Utils;
using namespace Utils::Net;
using namespace std;

class OpiBackendServer: public Utils::Net::NetServer
{
public:
	OpiBackendServer(const string& socketpath);

	virtual void Dispatch(SocketPtr con);

	virtual	~OpiBackendServer ();
private:
	// Commands
	void DoLogin(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoCreateUser(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoDeleteUser(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoGetUser(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoUpdateUser(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoGetUsers(UnixStreamClientSocketPtr& client, Json::Value& cmd);

	// Helper functions
	bool CheckArguments(UnixStreamClientSocketPtr& client, int what,const Json::Value& cmd);
	bool CheckLoggedIn(const string& username);
	bool CheckLoggedIn(UnixStreamClientSocketPtr &client, Json::Value& req);
	void TouchCLient(const string& token);

	Json::Value GetUser(const string& token, const string& user);

	void ProcessOneCommand(UnixStreamClientSocketPtr& client, Json::Value& cmd);


	void SendReply(UnixStreamClientSocketPtr& client, Json::Value& val);
	void SendErrorMessage(UnixStreamClientSocketPtr& client, const Json::Value& cmd, int errcode, const string& msg);
	void SendOK(UnixStreamClientSocketPtr& client, const Json::Value& cmd, const Json::Value& val = Json::nullValue);

	typedef void (OpiBackendServer::*Action)(UnixStreamClientSocketPtr&, Json::Value&);
	map<string,Action> actions;


	string AddUser(const string& username, SecopPtr secop);
	// <token, last access>
	map<string, time_t> clientaccess;
	// <token, pointer to secopconnection>
	map<string, SecopPtr> clients;
	// <Username, token>
	map<string, string> users;

	Json::FastWriter writer;
	Json::Reader reader;
};

typedef std::shared_ptr<OpiBackendServer> OpiBackendServerPtr;


#endif // OPIBACKENDSERVER_H
