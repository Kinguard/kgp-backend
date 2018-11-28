#ifndef OPIBACKENDSERVER_H
#define OPIBACKENDSERVER_H

#include <memory>
#include <string>
#include <map>

#include <json/json.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libutils/NetServer.h>

#include <libopi/Secop.h>
#include <libopi/JsonHelper.h>

#include <libkgpnotify/kgpNotify.h>

#include <kinguard/UserManager.h>

#include "Config.h"

#include "WebClient.h"

using namespace Utils;
using namespace Utils::Net;
using namespace std;
using namespace OPI;

class OpiBackendServer: public Utils::Net::NetServer
{
public:
	OpiBackendServer(const string& socketpath);

	virtual void Dispatch(SocketPtr con);

	virtual	~OpiBackendServer ();
private:
	// Commands
	void DoLogin(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoAuthenticate(UnixStreamClientSocketPtr& client, Json::Value& cmd);

	void DoCreateUser(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoDeleteUser(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoGetUser(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoGetUserIdentities(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoUserExists(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoUpdateUser(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoGetUsers(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoGetUserGroups(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoUpdateUserPassword(UnixStreamClientSocketPtr& client, Json::Value& cmd);

	void DoGetGroups(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoAddGroup(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoAddGroupMember(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoGetGroupMembers(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoRemoveGroup(UnixStreamClientSocketPtr& client, Json::Value& cmd);
	void DoRemoveGroupMember(UnixStreamClientSocketPtr& client, Json::Value& cmd);

	void DoShutdown(UnixStreamClientSocketPtr& client, Json::Value& cmd);

	void DoUpdateGetstate(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoUpdateSetstate(UnixStreamClientSocketPtr &client, Json::Value &cmd);

	void DoBackupGetSettings(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoBackupSetSettings(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoBackupGetQuota(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoBackupGetStatus(UnixStreamClientSocketPtr &client, Json::Value &cmd);

	void DoSmtpGetDomains(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoSmtpAddDomain(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoSmtpDeleteDomain(UnixStreamClientSocketPtr &client, Json::Value &cmd);

	void DoSmtpGetAddresses(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoSmtpAddAddress(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoSmtpDeleteAddress(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoSmtpGetSettings(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoSmtpSetSettings(UnixStreamClientSocketPtr &client, Json::Value &cmd);

	void DoFetchmailGetAccounts(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoFetchmailGetAccount(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoFetchmailAddAccount(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoFetchmailUpdateAccount(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoFetchmailDeleteAccount(UnixStreamClientSocketPtr &client, Json::Value &cmd);

	void DoNetworkGetPortStatus(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoNetworkSetPortStatus(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoNetworkGetOpiName(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoNetworkSetOpiName(UnixStreamClientSocketPtr &client, Json::Value &cmd);
    void DoNetworkGetDomains(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoNetworkGetSettings(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoNetworkSetSettings(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoNetworkGetCert(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoNetworkCheckCert(UnixStreamClientSocketPtr &client, Json::Value &cmd);

	void DoShellGetSettings(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoShellEnable(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoShellDisable(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	
	void DoSystemGetMessages(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoSystemAckMessage(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoSystemGetStatus(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoSystemGetStorage(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoSystemGetPackages(UnixStreamClientSocketPtr &client, Json::Value &cmd);
    void DoSystemGetType(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoSystemGetUnitid(UnixStreamClientSocketPtr &client, Json::Value &cmd);
	void DoSystemSetUnitid(UnixStreamClientSocketPtr &client, Json::Value &cmd);


	// Key management
	bool RegisterKeys();
	tuple<bool,string> UploadKeys(string unitid, string mpwd);


	// Helper functions
	bool CheckArguments(UnixStreamClientSocketPtr& client, int what,const Json::Value& cmd);
	bool CheckLoggedIn(UnixStreamClientSocketPtr &client, Json::Value& req);

	bool CheckIsAdmin(UnixStreamClientSocketPtr &client, Json::Value& req);
	bool CheckIsAdminOrUser(UnixStreamClientSocketPtr &client, Json::Value& req);

	bool isAdmin( const string& token);
	bool isAdminOrUser( const string& token, const string& user);

	bool verifyCertificate( string certificate, string type );
	string getTmpFile(string path, string suffix);
	string BackendLogin(const string& unit_id);

	string getSysconfigString(string scope, string key);
	bool getSysconfigBool(string scope, string key);

	// Lifecycle management
	time_t lastreap;
	// ONLY call this when not processing a request!
	void ReapClients();

	Json::Value UserToJson(const KGP::UserPtr user);

	void ProcessOneCommand(UnixStreamClientSocketPtr& client, Json::Value& cmd);

	void SendReply(UnixStreamClientSocketPtr& client, Json::Value& val);
	void SendErrorMessage(UnixStreamClientSocketPtr& client, const Json::Value& cmd, int errcode, const string& msg);
	void SendOK(UnixStreamClientSocketPtr& client, const Json::Value& cmd, const Json::Value& val = Json::nullValue);

	typedef void (OpiBackendServer::*Action)(UnixStreamClientSocketPtr&, Json::Value&);
	map<string,Action> actions;

	Clients clients;

	// Argumnen checking functionality
	string typecheckerror;
	static void typecheckcallback(const string& msg, void* data);
	JsonHelper::TypeChecker typechecker;

	Json::FastWriter writer;
	Json::Reader reader;
};

typedef std::shared_ptr<OpiBackendServer> OpiBackendServerPtr;


#endif // OPIBACKENDSERVER_H
