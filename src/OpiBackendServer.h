#ifndef OPIBACKENDSERVER_H
#define OPIBACKENDSERVER_H

#include <memory>
#include <string>
#include <map>

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
	void DoLogin(UnixStreamClientSocketPtr& client, json& cmd);
	void DoAuthenticate(UnixStreamClientSocketPtr& client, json& cmd);

	void DoCreateUser(UnixStreamClientSocketPtr& client, json& cmd);
	void DoDeleteUser(UnixStreamClientSocketPtr& client, json& cmd);
	void DoGetUser(UnixStreamClientSocketPtr& client, json& cmd);
	void DoGetUserIdentities(UnixStreamClientSocketPtr& client, json& cmd);
	void DoUserExists(UnixStreamClientSocketPtr& client, json& cmd);
	void DoUpdateUser(UnixStreamClientSocketPtr& client, json& cmd);
	void DoGetUsers(UnixStreamClientSocketPtr& client, json& cmd);
	void DoGetUserGroups(UnixStreamClientSocketPtr& client, json& cmd);
	void DoUpdateUserPassword(UnixStreamClientSocketPtr& client, json& cmd);

	void DoGetGroups(UnixStreamClientSocketPtr& client, json& cmd);
	void DoAddGroup(UnixStreamClientSocketPtr& client, json& cmd);
	void DoAddGroupMember(UnixStreamClientSocketPtr& client, json& cmd);
	void DoGetGroupMembers(UnixStreamClientSocketPtr& client, json& cmd);
	void DoRemoveGroup(UnixStreamClientSocketPtr& client, json& cmd);
	void DoRemoveGroupMember(UnixStreamClientSocketPtr& client, json& cmd);

	void DoShutdown(UnixStreamClientSocketPtr& client, json& cmd);

	/*
	 * Settings for automatic updates
	 */
	void DoUpdateGetstate(UnixStreamClientSocketPtr &client, json &cmd);
	void DoUpdateSetstate(UnixStreamClientSocketPtr &client, json &cmd);

	void DoBackupGetSettings(UnixStreamClientSocketPtr &client, json &cmd);
	void DoBackupSetSettings(UnixStreamClientSocketPtr &client, json &cmd);
	void DoBackupGetQuota(UnixStreamClientSocketPtr &client, json &cmd);
	void DoBackupGetStatus(UnixStreamClientSocketPtr &client, json &cmd);
	void DoBackupStartBackup(UnixStreamClientSocketPtr &client, json &cmd);

	void DoSmtpGetDomains(UnixStreamClientSocketPtr &client, json &cmd);
	void DoSmtpAddDomain(UnixStreamClientSocketPtr &client, json &cmd);
	void DoSmtpDeleteDomain(UnixStreamClientSocketPtr &client, json &cmd);

	void DoSmtpGetAddresses(UnixStreamClientSocketPtr &client, json &cmd);
	void DoSmtpAddAddress(UnixStreamClientSocketPtr &client, json &cmd);
	void DoSmtpDeleteAddress(UnixStreamClientSocketPtr &client, json &cmd);
	void DoSmtpGetSettings(UnixStreamClientSocketPtr &client, json &cmd);
	void DoSmtpSetSettings(UnixStreamClientSocketPtr &client, json &cmd);

	void DoFetchmailGetAccounts(UnixStreamClientSocketPtr &client, json &cmd);
	void DoFetchmailGetAccount(UnixStreamClientSocketPtr &client, json &cmd);
	void DoFetchmailAddAccount(UnixStreamClientSocketPtr &client, json &cmd);
	void DoFetchmailUpdateAccount(UnixStreamClientSocketPtr &client, json &cmd);
	void DoFetchmailDeleteAccount(UnixStreamClientSocketPtr &client, json &cmd);

	void DoNetworkGetPortStatus(UnixStreamClientSocketPtr &client, json &cmd);
	void DoNetworkSetPortStatus(UnixStreamClientSocketPtr &client, json &cmd);
	void DoNetworkGetOpiName(UnixStreamClientSocketPtr &client, json &cmd);
	void DoNetworkSetOpiName(UnixStreamClientSocketPtr &client, json &cmd);
	void DoNetworkGetDomains(UnixStreamClientSocketPtr &client, json &cmd);
	void DoNetworkGetSettings(UnixStreamClientSocketPtr &client, json &cmd);
	void DoNetworkSetSettings(UnixStreamClientSocketPtr &client, json &cmd);
	void DoNetworkGetCert(UnixStreamClientSocketPtr &client, json &cmd);
	void DoNetworkCheckCert(UnixStreamClientSocketPtr &client, json &cmd);

	void DoShellGetSettings(UnixStreamClientSocketPtr &client, json &cmd);
	void DoShellEnable(UnixStreamClientSocketPtr &client, json &cmd);
	void DoShellDisable(UnixStreamClientSocketPtr &client, json &cmd);
	
	void DoSystemGetMessages(UnixStreamClientSocketPtr &client, json &cmd);
	void DoSystemAckMessage(UnixStreamClientSocketPtr &client, json &cmd);
	void DoSystemGetStatus(UnixStreamClientSocketPtr &client, json &cmd);
	void DoSystemGetStorage(UnixStreamClientSocketPtr &client, json &cmd);
	void DoSystemGetPackages(UnixStreamClientSocketPtr &client, json &cmd);
	void DoSystemGetType(UnixStreamClientSocketPtr &client, json &cmd);
	void DoSystemGetUnitid(UnixStreamClientSocketPtr &client, json &cmd);
	void DoSystemSetUnitid(UnixStreamClientSocketPtr &client, json &cmd);

	void DoSystemStartUpdate(UnixStreamClientSocketPtr &client, json &cmd);
	void DoSystemGetUpgrade(UnixStreamClientSocketPtr &client, json &cmd);
	void DoSystemStartUpgrade(UnixStreamClientSocketPtr &client, json &cmd);


	// Key management
	bool RegisterKeys();
	tuple<bool,string> UploadKeys(string unitid, string mpwd);


	// Helper functions
	bool CheckArguments(UnixStreamClientSocketPtr& client, int what,const json& cmd);
	bool CheckLoggedIn(UnixStreamClientSocketPtr &client, json& req);

	bool CheckIsAdmin(UnixStreamClientSocketPtr &client, json& req);
	bool CheckIsAdminOrUser(UnixStreamClientSocketPtr &client, json& req);

	bool isAdmin( const string& token);
	bool isAdminOrUser( const string& token, const string& user);

	bool verifyCertificate(string certificate, const string& type );
	string getTmpFile(const string &path, const string &suffix);
	string BackendLogin(const string& unit_id);

	string getSysconfigString(const string& scope, const string& key);
	bool getSysconfigBool(const std::string &scope, const std::string &key);

	// Lifecycle management
	void LockBackend();
	void UnlockBackend();
	bool islocked; // Used to indicate if backend is locked
	time_t lastreap;
	// ONLY call this when not processing a request!
	void ReapClients();

	json UserToJson(const KGP::UserPtr& user);

	void ProcessOneCommand(UnixStreamClientSocketPtr& client, json& cmd);

	void SendReply(UnixStreamClientSocketPtr& client, json& val);
	void SendErrorMessage(UnixStreamClientSocketPtr& client, const json& cmd, int errcode, const string& msg);
	void SendOK(UnixStreamClientSocketPtr& client, const json& cmd, const json& val = json());

	typedef void (OpiBackendServer::*Action)(UnixStreamClientSocketPtr&, json&);
	map<string,Action> actions;

	Clients clients;

	// Argument checking functionality
	string typecheckerror;
	static void typecheckcallback(const string& msg, void* data);
	JsonHelper::TypeChecker typechecker;
};

typedef std::shared_ptr<OpiBackendServer> OpiBackendServerPtr;


#endif // OPIBACKENDSERVER_H
