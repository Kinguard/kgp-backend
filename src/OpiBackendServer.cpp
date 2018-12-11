#include "OpiBackendServer.h"
#include "Config.h"

#include <libutils/Logger.h>
#include <libutils/String.h>
#include <libutils/FileUtils.h>
#include <libutils/ConfigFile.h>
#include <libutils/UserGroups.h>
#include <libutils/Regex.h>

#include <libopi/AuthServer.h>
#include <libopi/ServiceHelper.h>
#include <libopi/NetworkConfig.h>
#include <libopi/SmtpConfig.h>
#include <libopi/SysInfo.h>
#include <libopi/ExtCert.h>
#include <libopi/SysConfig.h>
#include <libopi/BackupHelper.h>

#include <libopi/JsonHelper.h>

#include <kinguard/IdentityManager.h>
#include <kinguard/UserManager.h>
#include <kinguard/MailManager.h>

#include <algorithm>

#include <unistd.h>
#include <linux/limits.h>

using namespace OPI;
using namespace OPI::JsonHelper;
using namespace KGP;

// Convenience defines
#define SCFG	(OPI::SysConfig())

/*
 * Bit patterns for argument checks
 * (A bit uggly but effective)
 */
#define CHK_USR	0x00000001	// Check username
#define CHK_PWD	0x00000002	// Check password
#define CHK_DSP	0x00000004	// Check displayname
#define CHK_NPW 0x00000008	// Check new password
#define CHK_GRP 0x00000010	// Check group
#define CHK_DMN 0x00000020	// Check domain
#define CHK_ADR 0x00000040	// Check address
#define CHK_HST 0x00000080  // Check hostname
#define CHK_IDN 0x00000100  // Check identity
#define CHK_PRT 0x00000200  // Check port
#define CHK_EML 0x00000400  // Check email
#define CHK_SSL 0x00000800  // Check ssl
#define CHK_TYP 0x00001000  // Check type
#define CHK_SND 0x00002000  // Check send
#define CHK_RCV 0x00004000  // Check receive
#define CHK_DEM 0x00008000  // Check default email

#define CHK_ORIGID	0x00010000  // Check original identity
#define CHK_ORIGHST 0x00020000  // Check original hostname

static vector<TypeChecker::Check> argchecks(
	{
			{ CHK_USR, "username",		TypeChecker::Type::STRING },
			{ CHK_PWD, "password",		TypeChecker::STRING },
			{ CHK_NPW, "newpassword",	TypeChecker::STRING },
			{ CHK_DSP, "displayname",	TypeChecker::STRING },
			{ CHK_DEM, "defaultemail",	TypeChecker::STRING },
			{ CHK_DMN, "domain",		TypeChecker::STRING },
			{ CHK_GRP, "group",			TypeChecker::STRING },
			{ CHK_ADR, "address",		TypeChecker::STRING },
			{ CHK_HST, "hostname",		TypeChecker::STRING },
			{ CHK_IDN, "identity",		TypeChecker::STRING },
			{ CHK_PRT, "port",			TypeChecker::STRING },
			{ CHK_EML, "email",			TypeChecker::STRING },
			{ CHK_SSL, "ssl",			TypeChecker::STRING },
			{ CHK_TYP, "type",			TypeChecker::STRING },
			{ CHK_SND, "send",			TypeChecker::BOOL },
			{ CHK_RCV, "receive",		TypeChecker::BOOL },

			{ CHK_ORIGID, "origidentity",			TypeChecker::STRING },
			{ CHK_ORIGID, "orighostname",			TypeChecker::STRING },
	});

// Utility function forwards
static void postfix_fixpaths();

OpiBackendServer::OpiBackendServer(const string &socketpath):
	Utils::Net::NetServer(UnixStreamServerSocketPtr( new UnixStreamServerSocket(socketpath)), 0),
	typechecker(argchecks, OpiBackendServer::typecheckcallback)
{
	this->actions["login"]=&OpiBackendServer::DoLogin;
	this->actions["authenticate"]=&OpiBackendServer::DoAuthenticate;

	this->actions["createuser"]=&OpiBackendServer::DoCreateUser;
	this->actions["updateuserpassword"]=&OpiBackendServer::DoUpdateUserPassword;
	this->actions["updateuser"]=&OpiBackendServer::DoUpdateUser;
	this->actions["deleteuser"]=&OpiBackendServer::DoDeleteUser;
	this->actions["getuser"]=&OpiBackendServer::DoGetUser;
	this->actions["getuseridentities"]=&OpiBackendServer::DoGetUserIdentities;
	this->actions["getuserexists"]=&OpiBackendServer::DoUserExists;
	this->actions["getusers"]=&OpiBackendServer::DoGetUsers;
	this->actions["getusergroups"]=&OpiBackendServer::DoGetUserGroups;

	this->actions["groupsget"]=&OpiBackendServer::DoGetGroups;
	this->actions["groupadd"]=&OpiBackendServer::DoAddGroup;
	this->actions["groupaddmember"]=&OpiBackendServer::DoAddGroupMember;
	this->actions["groupgetmembers"]=&OpiBackendServer::DoGetGroupMembers;
	this->actions["groupremove"]=&OpiBackendServer::DoRemoveGroup;
	this->actions["groupremovemember"]=&OpiBackendServer::DoRemoveGroupMember;

	this->actions["shutdown"]=&OpiBackendServer::DoShutdown;

	this->actions["updategetstate"]=&OpiBackendServer::DoUpdateGetstate;
    this->actions["updatesetstate"]=&OpiBackendServer::DoUpdateSetstate;

	this->actions["backupgetsettings"]=&OpiBackendServer::DoBackupGetSettings;
	this->actions["backupsetsettings"]=&OpiBackendServer::DoBackupSetSettings;
	this->actions["backupgetQuota"]=&OpiBackendServer::DoBackupGetQuota;
	this->actions["backupgetstatus"]=&OpiBackendServer::DoBackupGetStatus;

	this->actions["smtpgetdomains"]=&OpiBackendServer::DoSmtpGetDomains;
	this->actions["smtpadddomain"]=&OpiBackendServer::DoSmtpAddDomain;
	this->actions["smtpdeletedomain"]=&OpiBackendServer::DoSmtpDeleteDomain;

	this->actions["smtpgetaddresses"]=&OpiBackendServer::DoSmtpGetAddresses;
	this->actions["smtpaddaddress"]=&OpiBackendServer::DoSmtpAddAddress;
	this->actions["smtpdeleteaddress"]=&OpiBackendServer::DoSmtpDeleteAddress;

	this->actions["smtpgetsettings"]=&OpiBackendServer::DoSmtpGetSettings;
	this->actions["smtpsetsettings"]=&OpiBackendServer::DoSmtpSetSettings;

	this->actions["fetchmailgetaccounts"]=&OpiBackendServer::DoFetchmailGetAccounts;
	this->actions["fetchmailgetaccount"]=&OpiBackendServer::DoFetchmailGetAccount;
	this->actions["fetchmailaddaccount"]=&OpiBackendServer::DoFetchmailAddAccount;
	this->actions["fetchmailupdateaccount"]=&OpiBackendServer::DoFetchmailUpdateAccount;
	this->actions["fetchmaildeleteaccount"]=&OpiBackendServer::DoFetchmailDeleteAccount;

	this->actions["networkgetportstatus"]=&OpiBackendServer::DoNetworkGetPortStatus;
	this->actions["networksetportstatus"]=&OpiBackendServer::DoNetworkSetPortStatus;
	this->actions["networkgetopiname"]=&OpiBackendServer::DoNetworkGetOpiName;
	this->actions["networksetopiname"]=&OpiBackendServer::DoNetworkSetOpiName;
    this->actions["networkgetdomains"]=&OpiBackendServer::DoNetworkGetDomains;
	this->actions["networkgetcert"]=&OpiBackendServer::DoNetworkGetCert;
//	this->actions["networksetcert"]=&OpiBackendServer::DoNetworkSetCert;
	this->actions["networkcheckcert"]=&OpiBackendServer::DoNetworkCheckCert;

	this->actions["setnetworksettings"]=&OpiBackendServer::DoNetworkSetSettings;
	this->actions["getnetworksettings"]=&OpiBackendServer::DoNetworkGetSettings;

	this->actions["getshellsettings"]=&OpiBackendServer::DoShellGetSettings;
	this->actions["doshellenable"]=&OpiBackendServer::DoShellEnable;
	this->actions["doshelldisable"]=&OpiBackendServer::DoShellDisable;


	this->actions["dosystemgetmessages"]=&OpiBackendServer::DoSystemGetMessages;
	this->actions["dosystemackmessage"]=&OpiBackendServer::DoSystemAckMessage;
	this->actions["dosystemgetstatus"]=&OpiBackendServer::DoSystemGetStatus;
	this->actions["dosystemgetstorage"]=&OpiBackendServer::DoSystemGetStorage;
	this->actions["dosystemgetpackages"]=&OpiBackendServer::DoSystemGetPackages;
    this->actions["dosystemgettype"]=&OpiBackendServer::DoSystemGetType;
	this->actions["dosystemgetunitid"]=&OpiBackendServer::DoSystemGetUnitid;
	this->actions["dosystemsetunitid"]=&OpiBackendServer::DoSystemSetUnitid;


	// Setup mail paths etc
	postfix_fixpaths();

	// Initialize time for last reap
	this->lastreap = time(nullptr);
}

#define BUFSIZE (64*1024)

void OpiBackendServer::Dispatch(SocketPtr con)
{
	ScopedLog l("Dispatch");

	// Convert into unixsocket
	UnixStreamClientSocketPtr sock = static_pointer_cast<UnixStreamClientSocket>(con);

	char buf[BUFSIZE];
	size_t rd, rd_total=0;
	int retries = 5;

	try
	{
		while( (rd = sock->Read(&buf[rd_total], BUFSIZE - rd_total )) > 0 )
		{
			rd_total += rd;

			logg << "Read request of socket (" <<rd << "/"<<rd_total << ") bytes"<<lend;
			Json::Value req;
			if( reader.parse(buf, buf+rd_total, req) )
			{
				if( req.isMember("cmd") && req["cmd"].isString() )
				{
					this->ProcessOneCommand(sock, req);
					retries = 5;
					rd_total = 0;
				}
				else
				{
					this->SendErrorMessage(sock, Json::Value::null, 4, "Missing command in request");
					break;
				}
			}
			else
			{
				if( retries-- == 0 )
				{
					this->SendErrorMessage(sock, Json::Value::null, 4, "Unable to parse request");
					break;
				}
			}
		}
	}
	catch(Utils::ErrnoException& e)
	{
		logg << Logger::Debug << "Caught exception on socket read ("<<e.what()<<")"<<lend;
	}

	// Check and possibly remove clients not active
	// This is ok since we are guaranteed not to process any client now
	this->ReapClients();

	this->decreq();

}

OpiBackendServer::~OpiBackendServer()
{

}

void OpiBackendServer::DoLogin(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("DoLogin");

	if( ! this->CheckArguments(client, CHK_USR|CHK_PWD, cmd) )
	{
		return;
	}

	string username = cmd["username"].asString();
	string password = cmd["password"].asString();

	if( this->clients.IsUsernameLoggedin( username ))
	{
		logg << Logger::Debug << "User seems already logged in, validating anyway"<<lend;

		try {
			WebClientPtr wc = this->clients.GetClientByUsername( username );
			SecopPtr secop = wc->Secop();

			if( ! secop )
			{
				logg << Logger::Error << "Missing connection to secop"<<lend;
				this->SendErrorMessage(client, cmd, 500, "Failed connecting to backing store");
				return;
			}

			if( ! secop->PlainAuth(username, password)  )
			{
				this->SendErrorMessage(client, cmd, 400, "Failed");
				return;
			}

			// User reauthorized?? Return same token
			Json::Value ret;
			ret["token"] = wc->Token();

			this->SendOK(client, cmd, ret);
		}
		catch (std::runtime_error& err)
		{
			logg << Logger::Notice << "Failed to (re)authenticate user. Stale connection?"
				 << " (" << err.what() << ")"
				 << lend;

			// Todo, fix generic cleanup.

			this->SendErrorMessage(client, cmd, 400, "Failed");
		}

		return;
	}
	else
	{
		SecopPtr secop(new Secop() );
		if( ! secop->PlainAuth(username,password) )
		{
			this->SendErrorMessage(client, cmd, 400, "Failed");
			return;
		}

		// we have a new login
		WebClientPtr wc = this->clients.CreateNewClient( username, secop );

		Json::Value ret;
		ret["token"] = wc->Token();

		this->SendOK(client, cmd, ret);
	}
}

void OpiBackendServer::DoAuthenticate(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do Authenticate");

	// TODO: Should one have to be logged in to do this?

	if( ! this->CheckArguments(client, CHK_USR|CHK_PWD, cmd) )
	{
		return;
	}

	string username = cmd["username"].asString();
	string password = cmd["password"].asString();

	// We do this on a new temporary connection
	SecopPtr secop(new Secop() );
	if( ! secop->PlainAuth(username,password) )
	{
		this->SendErrorMessage(client, cmd, 400, "Failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoCreateUser(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do Create user");

	if( !this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_USR|CHK_PWD|CHK_DSP, cmd) )
	{
		return;
	}

	string token =		cmd["token"].asString();
	string user =		cmd["username"].asString();
	string pass =		cmd["password"].asString();
	string display =	cmd["displayname"].asString();

	SecopPtr secop = this->clients.GetClientByToken(token)->Secop();


	UserManagerPtr umgr = UserManager::Instance(secop);

	if( ! umgr->AddUser(user,pass, display, false) )
	{
		this->SendErrorMessage(client, cmd, 400, "Failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoDeleteUser(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do Delete user");
    SysConfig sysconfig;

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

    if( ! this->CheckArguments(client, CHK_USR, cmd) )
	{
		return;
	}

	string token =		cmd["token"].asString();
	string user =		cmd["username"].asString();

	WebClientPtr wc = this->clients.GetClientByToken( token );

	if( user == wc->Username() )
	{
		// Not allowed to comit suicide
		this->SendErrorMessage(client, cmd, 403, "Not allowed");
		return;
	}

	UserManagerPtr umgr = UserManager::Instance( wc->Secop() );

	if( ! umgr->DeleteUser(user) )
	{
		logg << Logger::Notice << "Failed to remove user: "<< umgr->StrError()<<lend;
		this->SendErrorMessage(client, cmd, 400, "Failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoGetUser(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do get user");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_USR, cmd) )
	{
		return;
	}

	string token =		cmd["token"].asString();
	string user =		cmd["username"].asString();

	SecopPtr secop = this->clients.GetClientByToken( token )->Secop();

	UserManagerPtr umgr = UserManager::Instance( secop );

	KGP::UserPtr usr = umgr->GetUser(user);

	if( ! usr )
	{
		logg << Logger::Notice << "User not found: " << umgr->StrError() << lend;
		this->SendErrorMessage(client, cmd, 400, "Not found");
		return;
	}

	Json::Value ret = this->UserToJson(usr);

	this->SendOK(client, cmd,ret);
}

void OpiBackendServer::DoGetUserIdentities(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do get user identities");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_USR, cmd) )
	{
		return;
	}

	if( ! this->CheckIsAdminOrUser( client, cmd) )
	{
		return;
	}

	string user = cmd["username"].asString();

	// TODO: Validate that user exists!

	MailManager& mmgr = MailManager::Instance();

	// Get all remote addresses
	list<map<string,string>> accounts = mmgr.GetRemoteAccounts(user);

	Json::Value ids(Json::arrayValue);
	for( auto& account: accounts )
	{
		ids.append(account["email"]);
	}

	// Get all smtp addresses
	list<string> domains = mmgr.GetDomains();
	for( const string& domain: domains)
	{
		list<tuple<string, string> > addresses = mmgr.GetAddresses( domain );
		for( auto address: addresses )
		{
			if( user == get<1>(address) )
			{
				ids.append(get<0>(address)+"@"+domain);
			}
		}
	}

	Json::Value ret;
	ret["identities"] = ids;

	this->SendOK(client, cmd,ret);
}

void OpiBackendServer::DoUserExists(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do user exists");

	if( ! this->CheckArguments(client, CHK_USR, cmd) )
	{
		return;
	}

	string user =		cmd["username"].asString();

	UserManagerPtr umgr = UserManager::Instance();

	bool exists = umgr->UserExists( user );

	Json::Value ret;
	ret["username"] = user;
	ret["exists"] = exists;

	this->SendOK(client, cmd,ret);
}

void OpiBackendServer::DoUpdateUser(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do update user");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_USR|CHK_DSP|CHK_DEM, cmd) )
	{
		return;
	}

	if( ! this->CheckIsAdminOrUser( client, cmd) )
	{
		return;
	}

	string token =			cmd["token"].asString();
	string user =			cmd["username"].asString();
	string disp =			cmd["displayname"].asString();
	string defaultemail =	cmd["defaultemail"].asString();

	SecopPtr secop = this->clients.GetClientByToken( token )->Secop();

	UserManagerPtr umgr = UserManager::Instance(secop);

	UserPtr usr = umgr->GetUser(user);

	if( ! usr )
	{
		logg <<  Logger::Notice << "Retrieve user failed: " << umgr->StrError() << lend;
		this->SendErrorMessage(client, cmd, 400, "Operation failed");
		return;
	}

	usr->AddAttribute("displayname", disp);
	usr->AddAttribute("defaultemail", defaultemail);

	if( ! umgr->UpdateUser( usr ) )
	{
		logg <<  Logger::Notice << "Update user failed: " << umgr->StrError() << lend;
		this->SendErrorMessage(client, cmd, 400, "Operation failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoGetUsers(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do get users");

	if( ! this->CheckLoggedIn(client,cmd)  )
	{
		return;
	}

	string token = cmd["token"].asString();

	SecopPtr secop = this->clients.GetClientByToken( token )->Secop();

	UserManagerPtr umgr = UserManager::Instance(secop);

	list<UserPtr> users = umgr->GetUsers();

	Json::Value ret;
	ret["users"]=Json::arrayValue;
	for(auto user: users)
	{
		ret["users"].append( this->UserToJson( user) );
	}

	this->SendOK(client, cmd, ret);
}

void OpiBackendServer::DoGetUserGroups(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do get user groups");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_USR, cmd) )
	{
		return;
	}

	string user =		cmd["username"].asString();
	string token =		cmd["token"].asString();

	SecopPtr secop = this->clients.GetClientByToken( token )->Secop();

	UserManagerPtr umgr = UserManager::Instance(secop);

	list<string> groups = umgr->GetUserGroups( user );

	Json::Value ret;
	ret["groups"]=Json::arrayValue;
	for(auto group: groups)
	{
		ret["groups"].append( group );
	}

	this->SendOK(client, cmd, ret);
}

void OpiBackendServer::DoUpdateUserPassword(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do update password");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_USR|CHK_PWD|CHK_NPW, cmd) )
	{
		return;
	}

	if( ! this->CheckIsAdminOrUser( client, cmd ) )
	{
		return;
	}

	string token =		cmd["token"].asString();
	string user =		cmd["username"].asString();
	string passw =		cmd["password"].asString();
	string newps =		cmd["newpassword"].asString();

	WebClientPtr wc = this->clients.GetClientByToken( token );

	SecopPtr secop = wc->Secop();

	UserManagerPtr umgr = UserManager::Instance(secop);

	if( ! umgr->UpdateUserPassword( user, newps, passw ) )
	{
		logg << Logger::Notice << "Failed to update user password: " << umgr->StrError() << lend;
		this->SendErrorMessage(client, cmd, 400, "Operation failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoGetGroups(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do get groups");

	UserManagerPtr umgr = UserManager::Instance();

	list<string> groups = umgr->GetGroups();

	Json::Value ret;
	ret["groups"]=Json::arrayValue;
	for(auto group: groups)
	{
		ret["groups"].append( group );
	}

	this->SendOK(client, cmd, ret);
}

void OpiBackendServer::DoAddGroup(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do add group");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_GRP, cmd) )
	{
		return;
	}

	string token =	cmd["token"].asString();
	string group =	cmd["group"].asString();

	SecopPtr secop = this->clients.GetClientByToken( token )->Secop();
	UserManagerPtr umgr = UserManager::Instance(secop);


	if( !umgr->AddGroup(group) )
	{
		logg << Logger::Notice << "Failed to add group: " << umgr->StrError() << lend;
		this->SendErrorMessage(client, cmd, 400, "Operation failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoAddGroupMember(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do add group member");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_GRP, cmd) )
	{
		return;
	}

	string token =	cmd["token"].asString();
	string group =	cmd["group"].asString();
	string member =	cmd["member"].asString();

	SecopPtr secop = this->clients.GetClientByToken( token )->Secop();
	UserManagerPtr umgr = UserManager::Instance(secop);

	if( !umgr->AddGroupMember(group, member) )
	{
		logg << Logger::Notice << "Failed to add member to group: " << umgr->StrError() << lend;
		this->SendErrorMessage(client, cmd, 400, "Operation failed");
		return;
	}

	if( group == "admin" )
	{
		MailManager& mmgr = MailManager::Instance();

		if( ! mmgr.AddToAdmin( member ) )
		{
			logg << Logger::Error << "Failed to add user to admin mail: "<< mmgr.StrError() << lend;
			this->SendErrorMessage(client, cmd, 400, "Operation failed");
			return;
		}

		if( ! mmgr.Synchronize() )
		{
			logg << Logger::Error << "Failed to synchronize mail settings: "<< mmgr.StrError() << lend;
			this->SendErrorMessage(client, cmd, 500, "Operation failed");
			return;
		}
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoGetGroupMembers(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do get group members");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_GRP, cmd) )
	{
		return;
	}

	string token =	cmd["token"].asString();
	string group =	cmd["group"].asString();

	SecopPtr secop = this->clients.GetClientByToken( token )->Secop();
	UserManagerPtr umgr = UserManager::Instance(secop);

	list<string> members = umgr->GetGroupMembers( group );

	Json::Value ret;
	ret["members"]=Json::arrayValue;

	for( auto member: members)
	{
		ret["members"].append(member);
	}

	this->SendOK(client, cmd, ret);
}

void OpiBackendServer::DoRemoveGroup(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do remove group");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_GRP, cmd) )
	{
		return;
	}

	string token =	cmd["token"].asString();
	string group =	cmd["group"].asString();

	SecopPtr secop = this->clients.GetClientByToken( token )->Secop();
	UserManagerPtr umgr = UserManager::Instance(secop);

	if( !umgr->DeleteGroup(group) )
	{
		logg << Logger::Notice << "Failed to delete group: " << umgr->StrError() << lend;
		this->SendErrorMessage(client, cmd, 400, "Operation failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoRemoveGroupMember(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do group remove member");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_GRP, cmd) )
	{
		return;
	}

	string token =	cmd["token"].asString();
	string group =	cmd["group"].asString();
	string member =	cmd["member"].asString();

	WebClientPtr wc = this->clients.GetClientByToken( token );

	if( ( group == "admin" ) && ( member == wc->Username() ) )
	{
		this->SendErrorMessage(client, cmd, 403, "Not allowed");
		return;
	}

	SecopPtr secop = wc->Secop();
	UserManagerPtr umgr = UserManager::Instance(secop);

	if( !umgr->DeleteGroupMember(group, member) )
	{
		this->SendErrorMessage(client, cmd, 400, "Operation failed");
		return;
	}

	if( group == "admin" )
	{
		MailManager& mmgr = MailManager::Instance();

		if( ! mmgr.RemoveFromAdmin( member ) )
		{
			logg << Logger::Error << "Failed to add user to admin mail: "<< mmgr.StrError() << lend;
			this->SendErrorMessage(client, cmd, 400, "Operation failed");
			return;
		}

		if( ! mmgr.Synchronize() )
		{
			logg << Logger::Error << "Failed to synchronize mail settings: "<< mmgr.StrError() << lend;
			this->SendErrorMessage(client, cmd, 500, "Operation failed");
			return;
		}
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoShutdown(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do shutdown");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	string action =	cmd["action"].asString();

	if( action == "shutdown")
	{
		system("/sbin/poweroff");
	}
	else if( action == "reboot" )
	{
		system("/sbin/reboot");
	}
	else
	{
		this->SendErrorMessage(client, cmd, 400, "Bad request");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoUpdateGetstate(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	Json::Value res(Json::objectValue);

	ScopedLog l("Get update state");
    SysConfig sysconfig;

	if( ! this->CheckLoggedIn(client,cmd)  || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

    try
    {
        res["update"] = sysconfig.GetKeyAsBool("autoupdate","enabled");
        this->SendOK(client, cmd, res);
    }
    catch (std::runtime_error& e)
    {
        this->SendErrorMessage( client, cmd, 500, "Failed to read config parameters");
        logg << Logger::Error << "Failed to read sysconfig" << e.what() << lend;
        return;
    }

}

void OpiBackendServer::DoUpdateSetstate(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	Json::Value res(Json::objectValue);

	ScopedLog l("Set update state");
	string doupdates = cmd["state"].asString();
    SysConfig sysconfig(true);

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}


    try
    {
        bool enabled = false;
        if(doupdates == "1")
        {
            enabled = true;
        }
        sysconfig.PutKey("autoupdate","enabled",enabled);
    }
    catch (std::runtime_error& e)
    {
        this->SendErrorMessage( client, cmd, 500, "Failed to read config parameters");
        logg << Logger::Error << "Failed to read sysconfig" << e.what() << lend;
        return;
    }

	this->SendOK(client, cmd);

}

// TODO: Refactor and modularize, opi/s3 specifics
void OpiBackendServer::DoBackupGetSettings(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	Json::Value res(Json::objectValue);
	string backend,key;
    bool enabled;
    string type, bucket;
    SysConfig sysconfig;

	ScopedLog l("Get backup settings");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

    try
    {
        backend = sysconfig.GetKeyAsString("backup","backend");
        enabled = sysconfig.GetKeyAsBool("backup","enabled");
        if ( sysconfig.HasKey("backup","type") )
        {
            type = sysconfig.GetKeyAsString("backup","type");
        }
        if ( sysconfig.HasKey("backup","bucket") )
        {
            bucket = sysconfig.GetKeyAsString("backup","bucket");
        }
    }
    catch (std::runtime_error& e)
    {
        this->SendErrorMessage( client, cmd, 500, "Failed to read config parameters");
        logg << Logger::Error << "Failed to read sysconfig" << e.what() << lend;
        return;
    }


    logg << Logger::Error << "Backend: " << backend <<lend;
    res["enabled"] = enabled;

    if(backend == "s3op://")
    {
        res["location"] = "op";
    }
    else if (backend == "local://")
    {
        res["location"] = "local";
    }
    else if (backend == "s3://")
    {
        res["location"] = "amazon";
    }
    else
    {
		res["location"] = "op";  // Show as default target in UI
    }
    res["type"] = type;
    res["AWSbucket"] = bucket;


    IniFile aws(BACKUP_AUTH,":");
    aws.UseSection("s3");
    res["AWSkey"] = aws.ValueOrDefault("backend-login");

    this->SendOK(client, cmd, res);
}

// TODO: Refactor and modularize, opi/s3 specifics
void OpiBackendServer::DoBackupSetSettings(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	Json::Value res(Json::objectValue);

	ScopedLog l("Set backup settings");
	string type = cmd["type"].asString();
	string backend = cmd["location"].asString();
	string AWSkey = cmd["AWSkey"].asString();
	string AWSseckey = cmd["AWSseckey"].asString();
	string AWSbucket = cmd["AWSbucket"].asString();
    SysConfig sysconfig(true);

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

    try
    {
        bool enabled=true;
        logg << Logger::Debug << "Set backend to " << backend << lend;
        if(backend == "local")
        {
            sysconfig.PutKey("backup","backend", string("local://"));
        }
        else if (backend == "op")
        {
            sysconfig.PutKey("backup","backend", string("s3op://"));
        }
        else if (backend == "amazon")
        {
            sysconfig.PutKey("backup","backend", string("s3://"));
			if(sysconfig.HasKey("backup","bucket") && (sysconfig.GetKeyAsString("backup","bucket") != AWSbucket) )
            {
                // bucket has changed, umount the backend to trigger new mount on next backup
                Process::Exec( BACKUP_UMOUNT_FS);
            }
            sysconfig.PutKey("backup","bucket", AWSbucket);

            IniFile aws(BACKUP_AUTH,":");
            aws.UseSection("s3");

            if ( AWSseckey.length()  > 0 )
            {
                // only write password if we get a new, it might already exist.
                aws["s3"]["backend-password"] = AWSseckey;
            }
            aws["s3"]["backend-login"] = AWSkey;
            aws.Save();


        }
        else
        {
            enabled = false;
        }

        sysconfig.PutKey("backup","type", type);
        sysconfig.PutKey("backup","enabled", enabled);
    }
    catch (std::runtime_error& e)
    {
        this->SendErrorMessage( client, cmd, 500, "Failed to set config parameters");
        logg << Logger::Error << "Failed to write sysconfig" << e.what() << lend;
        return;
    }

    this->SendOK(client, cmd);
	if(backend == "remote" || backend == "local" || backend == "amazon")
	{
		Process::Exec( BACKUP_MOUNT_FS);
		Process::Exec( BACKUP_LINK);
	}

}

void OpiBackendServer::DoBackupGetQuota(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Get Quota");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	string jsonMessage;
	Json::Reader reader;
	Json::Value parsedFromString;
	bool parsingSuccessful;

	tie(ignore,jsonMessage) = Process::Exec( BACKUP_GET_QUOTA );

	parsingSuccessful = reader.parse(jsonMessage, parsedFromString);
	this->SendOK(client, cmd, parsedFromString);
}

void OpiBackendServer::DoBackupGetStatus(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Get Backup Status");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	Json::Value res(Json::objectValue);
	struct stat filestatus;
	string log;

	if( File::FileExists( BACKUP_ALERT ))
	{
		res["backup_status"] = "Failed";
		res["info"] = File::GetContentAsString( BACKUP_ALERT ,true );
		if( File::DirExists( BACKUP_ERRORS ))
		{
			stat( BACKUP_ERRORS , &filestatus );
			res["date"] = to_string(filestatus.st_mtime);
		}
		if( File::FileExists( BACKUP_LOG )) 
		{
			res["log"] = File::GetContentAsString( BACKUP_LOG ,true );
			logg << Logger::Error << "Sending log file" <<lend;
		}
	}
	else
	{
		res["backup_status"] = "Successful";

		if( File::DirExists( BACKUP_COMPLETE ))
		{
			stat( BACKUP_COMPLETE , &filestatus );
			res["date"] = to_string(filestatus.st_mtime);
			log = File::GetContentAsString( BACKUP_LASTTARGET ,true );
			res["info"] = log;
			logg << Logger::Error << log <<lend;
		}
		else
		{
            res["backup_status"] = "NotAvailable";
            res["date"] = "";
			res["info"] = "";
		}
	}
	// TODO: Send error reply when fail
	this->SendOK(client, cmd, res);

}

void OpiBackendServer::DoSmtpGetDomains(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do smtp get domains");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	MailManager& mmgr = MailManager::Instance();

	list<string> domains = mmgr.GetDomains();

	Json::Value res(Json::objectValue);
	res["domains"]=Json::arrayValue;
	for( auto domain: domains )
	{
		res["domains"].append(domain);
	}

	this->SendOK(client, cmd, res);
}

void OpiBackendServer::DoSmtpAddDomain(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do smtp add domain");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_DMN, cmd) )
	{
		return;
	}

	string domain = cmd["domain"].asString();

	MailManager& mmgr = MailManager::Instance();
	mmgr.AddDomain( domain );

	if( ! mmgr.Synchronize() )
	{
		logg << Logger::Error << "Failed to synchronize mail manager: " << mmgr.StrError() << lend;
		this->SendErrorMessage( client, cmd, 500, "Failed to add domain");
		return;
	}

	this->SendOK(client, cmd);
}

// TODO: This should move into MailManager, libkinguard
static void postfix_fixpaths()
{
    SysConfig sysconfig;

    string aliases = sysconfig.GetKeyAsString("filesystem","storagemount") + sysconfig.GetKeyAsString("mail","vmailbox");
    if( ! File::FileExists( aliases ) )
	{
        File::Write( aliases, "", 0600);
    }

    string saslpwd = sysconfig.GetKeyAsString("filesystem","storagemount")  + sysconfig.GetKeyAsString("mail","saslpasswd");
    if( ! File::FileExists( saslpwd ) )
	{
        File::Write( saslpwd, "", 0600);
	}

    string domains = sysconfig.GetKeyAsString("filesystem","storagemount") + sysconfig.GetKeyAsString("mail","vdomains");
    if( ! File::FileExists( domains ) )
	{
        File::Write( domains, "", 0600);
	}

    string localmail = sysconfig.GetKeyAsString("filesystem","storagemount") + sysconfig.GetKeyAsString("mail","localmail");
    if( ! File::FileExists( localmail ) )
	{
        File::Write( localmail, "", 0600);
	}

	if( chown( aliases.c_str(), Utils::User::UserToUID("postfix"), Group::GroupToGID("postfix") ) != 0)
	{
		logg << Logger::Error << "Failed to change owner on aliases file"<<lend;
	}

	if( chown( saslpwd.c_str(), Utils::User::UserToUID("postfix"), Group::GroupToGID("postfix") ) != 0)
	{
		logg << Logger::Error << "Failed to change owner on saslpasswd file"<<lend;
	}

	if( chown( domains.c_str(), Utils::User::UserToUID("postfix"), Group::GroupToGID("postfix") ) != 0)
	{
		logg << Logger::Error << "Failed to change owner on domain file"<<lend;
	}

	if( chown( File::GetPath(domains).c_str(), Utils::User::UserToUID("postfix"), Group::GroupToGID("postfix") ) != 0)
	{
		logg << Logger::Error << "Failed to change owner on config directory"<<lend;
	}

    if( chmod( File::GetPath(domains).c_str(), 0700 ) != 0)
	{
		logg << Logger::Error << "Failed to change mode on config directory"<<lend;
	}
}

void OpiBackendServer::DoSmtpDeleteDomain(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do smtp delete domain");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_DMN, cmd) )
	{
		return;
	}

	string domain = cmd["domain"].asString();

	string token = cmd["token"].asString();
	bool admin = this->isAdmin( token );

	string user = this->clients.GetClientByToken( token )->Username();


	MailManager& mmgr = MailManager::Instance();

	// We only allow delete of domain if you are admin OR
	// is the only user of this domain
	if( ! admin )
	{
		list<tuple<string, string> > addresses = mmgr.GetAddresses(domain);

		for( auto address: addresses)
		{
			if( get<1>(address) != user )
			{
				this->SendErrorMessage( client, cmd, 403, "Not allowed");
				return;
			}
		}

	}

	mmgr.DeleteDomain( domain );

	if( !mmgr.Synchronize() )
	{
		logg << Logger::Error << "Failed to synchronize mailmanager: " << mmgr.StrError() << lend;
		this->SendErrorMessage( client, cmd, 500, "Failed to reload mailserver");
	}
	else
	{
		this->SendOK(client, cmd);
	}
}

void OpiBackendServer::DoSmtpGetAddresses(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do smtp get addresses");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_DMN, cmd) )
	{
		return;
	}

	string domain = cmd["domain"].asString();

	string token = cmd["token"].asString();
	bool admin = this->isAdmin( token );
	string user = this->clients.GetClientByToken( token )->Username();

	MailManager& mmgr = MailManager::Instance();

	list<tuple<string,string>> addresses = mmgr.GetAddresses(domain);

	Json::Value res(Json::objectValue);
	res["addresses"]=Json::arrayValue;
	for( auto address: addresses )
	{
		// Only return own adresses if not admin
		if( ! admin && user != get<1>(address) )
		{
			continue;
		}

		Json::Value adr;
		adr["address"] = get<0>(address);
		adr["username"] = get<1>(address);
		res["addresses"].append(adr);
	}

	this->SendOK(client, cmd, res);
}

void OpiBackendServer::DoSmtpAddAddress(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do smtp add address");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_DMN | CHK_USR | CHK_ADR , cmd) )
	{
		return;
	}

	string domain = cmd["domain"].asString();
	string username = cmd["username"].asString();
	string address = cmd["address"].asString();

	string token = cmd["token"].asString();
	bool admin = this->isAdmin( token );
	string user = this->clients.GetClientByToken( token )->Username();

	if( !admin && ( user != username ) )
	{
		// If not admin you only can add/update mail addressed to yourself
		this->SendErrorMessage( client, cmd, 403, "Not allowed");
		return;
	}

	MailManager& mmgr = MailManager::Instance();

	if( ! admin )
	{
		// Non admin users can only add not used addresses
		// or update their own addresses
		if( mmgr.hasAddress( domain, address) )
		{
			string adr, localuser;
			tie(adr, localuser) = mmgr.GetAddress(domain,address);

			if( user != localuser )
			{
				this->SendErrorMessage( client, cmd, 403, "Not allowed");
				return;

			}
		}
	}

	mmgr.SetAddress(domain, address, username);

	if( mmgr.Synchronize() )
	{
		this->SendOK(client, cmd);
	}
	else
	{
		this->SendErrorMessage( client, cmd, 500, "Failed to reload mailserver");
	}
}

void OpiBackendServer::DoSmtpDeleteAddress(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do smtp delete address");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_DMN | CHK_ADR , cmd) )
	{
		return;
	}

	string token = cmd["token"].asString();
	bool admin = this->isAdmin( token );
	string user = this->clients.GetClientByToken( token )->Username();

	string domain = cmd["domain"].asString();
	string address = cmd["address"].asString();

	MailManager& mmgr = MailManager::Instance();

	if( ! admin )
	{
		// None admins can only delete their own addresses
		if( mmgr.hasAddress(domain, address) )
		{
			string adr, localuser;
			tie(adr, localuser) = mmgr.GetAddress(domain,address);

			if( user != localuser )
			{
				this->SendErrorMessage( client, cmd, 403, "Not allowed");
				return;

			}
		}
	}

	mmgr.DeleteAddress( domain, address );

	if( mmgr.Synchronize() )
	{
		this->SendOK(client, cmd);
	}
	else
	{
		this->SendErrorMessage( client, cmd, 500, "Failed to reload mailserver");
	}
}

//TODO: Refactor this out, OPI specifics
void OpiBackendServer::DoSmtpGetSettings(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do smtp get settings");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

    string saslpasswd = SysConfig().GetKeyAsString("filesystem","storagemount") + "/" + SysConfig().GetKeyAsString("mail","saslpasswd");
    SmtpConfig cfg(saslpasswd);

	Json::Value ret;
	switch( cfg.GetMode() )
	{
	case SmtpConfig::OPI:
		ret["type"]="OPI";
		break;
	case SmtpConfig::OPRelay:
	{
		OPRelayConf conf = cfg.GetOPRelayConfig();
		ret["type"] = "EXTERNAL";
		ret["send"] = conf.send;
		ret["receive"] = conf.receive;
		break;
	}
	case SmtpConfig::Custom:
	{
		OPCustomConf conf = cfg.GetOPCustomConfig();
		ret["type"] = "CUSTOM";
		ret["hostname"] =	conf.host;
		ret["username"] =	conf.user;
		ret["password"] =	conf.pass;
		ret["port"] =		conf.port;
		break;
	}
	}

	this->SendOK(client, cmd,ret);
}

//TODO: Refactor this out, OPI specifics
void OpiBackendServer::DoSmtpSetSettings(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do smtp set settings");
    SysConfig sysconfig;
	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_TYP, cmd) )
	{
		return;
	}

	string type = cmd["type"].asString();
    string saslpwd = sysconfig.GetKeyAsString("filesystem","storagemount") + "/" + sysconfig.GetKeyAsString("mail","saslpasswd");

	if( type == "OPI")
	{
		logg << Logger::Debug << "Set opi mode"<<lend;
        SmtpConfig smtp( saslpwd );

		smtp.SetStandAloneMode();
	}
	else if( type == "EXTERNAL" )
	{
		logg << Logger::Debug << "Set external server mode"<<lend;
		if( ! this->CheckArguments(client, CHK_RCV | CHK_SND, cmd) )
		{
			return;
		}
        SmtpConfig smtp( saslpwd );
		OPRelayConf conf;

		conf.receive = cmd["receive"].asBool();
		conf.send = cmd["send"].asBool();

		smtp.SetOPRelayMode( conf );
	}
	else if( type == "CUSTOM" )
	{
		logg << Logger::Debug << "Set custom mode"<<lend;
		if( ! this->CheckArguments(client, CHK_USR | CHK_PWD | CHK_HST | CHK_PRT , cmd) )
		{
			return;
		}

		OPCustomConf conf;
		conf.user = cmd["username"].asString();
		conf.pass = cmd["password"].asString();
		conf.host = cmd["hostname"].asString();
		conf.port = cmd["port"].asString();

		if( conf.host == "" )
		{
			logg << Logger::Debug<< "No relay host specified"<<lend;
			this->SendErrorMessage(client, cmd, 400, "No relay host specified");
			return;
		}

        SmtpConfig smtp( saslpwd );

		smtp.SetCustomMode( conf );
	}
	else
	{
		logg << Logger::Debug << "Missing smtp type"<<lend;
		this->SendErrorMessage(client, cmd, 400, "Missing type argument");
		return;
	}

	MailManager& mmgr = MailManager::Instance();
	if( mmgr.Synchronize( true ) )
	{
		this->SendOK(client, cmd);
	}
	else
	{
		logg << Logger::Error << "Failed to update smtp settings: " << mmgr.StrError() << lend;
		this->SendErrorMessage(client, cmd, 500, "Operation failed");
	}
}

void OpiBackendServer::DoFetchmailGetAccounts(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do fetchmail get accounts");

	if( ! this->CheckLoggedIn(client,cmd) || ! this->CheckIsAdminOrUser(client, cmd) )
	{
		return;
	}

	// Username is optional here
	string user;
	if(cmd.isMember( "username" ) && cmd["username"].isString())
	{
		user = cmd["username"].asString();
	}

	MailManager& mmgr = MailManager::Instance();

	list<map<string,string>> accounts = mmgr.GetRemoteAccounts(user);

	Json::Value ret(Json::objectValue);
	ret["accounts"] = Json::arrayValue;

	for( auto& account: accounts )
	{
		Json::Value acc(Json::objectValue);
		acc["email"] = account["email"];
		acc["host"] = account["host"];
		acc["identity"] = account["identity"];
		acc["username"] = account["username"];
		acc["ssl"] = account["ssl"];
		ret["accounts"].append(acc);
	}

	this->SendOK(client, cmd,ret);

}

void OpiBackendServer::DoFetchmailGetAccount(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do fetchmail get account");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_HST | CHK_IDN , cmd) )
	{
		return;
	}

	string host = cmd["hostname"].asString();
	string id = cmd["identity"].asString();

	MailManager& mmgr = MailManager::Instance();
	map<string,string> account = mmgr.GetRemoteAccount(host,id);

	Json::Value ret(Json::objectValue);
	ret["email"] = account["email"];
	ret["host"] = account["host"];
	ret["identity"] = account["identity"];
	ret["username"] = account["username"];
	ret["ssl"] = account["ssl"];

	if( this->isAdminOrUser(cmd["token"].asString(), account["username"]) )
	{
		this->SendOK(client, cmd,ret);
	}
	else
	{
		this->SendErrorMessage(client, cmd, 401, "Not allowed");
	}
}

void OpiBackendServer::DoFetchmailAddAccount(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do fetchmail add account");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_HST | CHK_IDN | CHK_PWD | CHK_USR  | CHK_EML | CHK_SSL , cmd) )
	{
		return;
	}

	string email = cmd["email"].asString();
	string host = cmd["hostname"].asString();
	string id = cmd["identity"].asString();
	string pwd = cmd["password"].asString();
	string user = cmd["username"].asString();
	string ssl = cmd["ssl"].asString();

	if( ! this->isAdminOrUser(cmd["token"].asString(), user) )
	{
		this->SendErrorMessage(client, cmd, 401, "Not allowed");
		return;
	}

	MailManager& mmgr = MailManager::Instance();

	mmgr.AddRemoteAccount(email, host, id, pwd, user, ssl == "true" );

	if( mmgr.Synchronize() )
	{
		this->SendOK(client, cmd);
	}
	else
	{
		logg << Logger::Error << "Failed to add fetchmail account: "<< mmgr.StrError() << lend;
		this->SendErrorMessage(client, cmd, 500, "Operation failed");
	}
}

void OpiBackendServer::DoFetchmailUpdateAccount(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do fetchmail update account");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client,
							   CHK_HST | CHK_IDN | CHK_PWD | CHK_USR | CHK_EML | CHK_SSL |
							   CHK_ORIGHST | CHK_ORIGID
							   , cmd) )
	{
		return;
	}

	string email = cmd["email"].asString();
	string ohost = cmd["orighostname"].asString();
	string host = cmd["hostname"].asString();
	string oid = cmd["origidentity"].asString();
	string id = cmd["identity"].asString();
	string pwd = cmd["password"].asString();
	string user = cmd["username"].asString();
	string token = cmd["token"].asString();
	string ssl = cmd["ssl"].asString();

	if( ! this->isAdminOrUser( token, user) )
	{
		this->SendErrorMessage(client, cmd, 401, "Not allowed");
		return;
	}

	MailManager& mmgr = MailManager::Instance();

	if( (ohost != host) || (oid != id ) )
	{
		// We have updated id fields, need to re-add account
		map<string,string> acc = mmgr.GetRemoteAccount(ohost, oid);

		mmgr.DeleteRemoteAccount(ohost, oid);

		acc["email"] =		(email != "" ) ? email : acc["email"];
		acc["host"] =		host;
		acc["identity"]	=	id;
		acc["username"] =	(user != "") ? user : acc["username"];
		acc["password"] =	(pwd != "") ? pwd : acc["password"];
		acc["ssl"] =		(ssl != "") ? ssl : acc["ssl"];

		mmgr.AddRemoteAccount(acc["email"],acc["host"],acc["identity"],acc["password"],acc["username"],acc["ssl"]=="true");
	}
	else
	{
		mmgr.UpdateRemoteAccount(email, host, id, pwd, user, ssl == "true" );
	}

	if( mmgr.Synchronize() )
	{
		this->SendOK(client, cmd);
	}
	else
	{
		logg << Logger::Error << "Failed to add fetchmail account: "<< mmgr.StrError() << lend;
		this->SendErrorMessage(client, cmd, 500, "Operation failed");
	}
}

void OpiBackendServer::DoFetchmailDeleteAccount(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do fetchmail delete account");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_HST | CHK_IDN , cmd) )
	{
		return;
	}

	string host = cmd["hostname"].asString();
	string id = cmd["identity"].asString();
	string token = cmd["token"].asString();

	MailManager& mmgr = MailManager::Instance();

	map<string,string> account = mmgr.GetRemoteAccount(host, id);

	if( ! this->isAdminOrUser( token, account["username"] ) )
	{
		this->SendErrorMessage(client, cmd, 401, "Not allowed");
		return;
	}

	mmgr.DeleteRemoteAccount(host, id );

	if( mmgr.Synchronize() )
	{
		this->SendOK(client, cmd);
	}
	else
	{
		logg << Logger::Error << "Failed to delete fetchmail account: "<< mmgr.StrError() << lend;
		this->SendErrorMessage(client, cmd, 500, "Operation failed");
	}
}

void OpiBackendServer::DoNetworkGetPortStatus(UnixStreamClientSocketPtr &client, Json::Value &cmd) {
	Json::Value res(Json::objectValue);

	ScopedLog l("Get port state");
    SysConfig sysconfig;

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin( client, cmd ) )
	{
		return;
	}
    string port = cmd["port"].asString();
    string forwardports;

    try
    {
        forwardports = sysconfig.GetKeyAsString("upnp","forwardports");
    }
    catch (std::runtime_error& e)
    {
        this->SendErrorMessage( client, cmd, 500, "Failed to read config parameters");
        logg << Logger::Error << "Failed to read sysconfig" << e.what() << lend;
        return;
    }
    list<string> ports = Utils::String::Split(forwardports," ");
    if ( std::find(ports.begin(), ports.end(), port) != ports.end() )
    {
        res["is_open"] = "yes";
    }
    else
    {
        res["is_open"] = "no";
    }

    this->SendOK(client, cmd, res);
}

void OpiBackendServer::DoNetworkSetPortStatus(UnixStreamClientSocketPtr &client, Json::Value &cmd) {
	Json::Value res(Json::objectValue);

	ScopedLog l("Set port state");
    SysConfig sysconfig(true);


    string port = cmd["port"].asString();
    string forwardports;

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin( client, cmd ) )
	{
		return;
	}
    try
    {
        forwardports = sysconfig.GetKeyAsString("upnp","forwardports");
    }
    catch (std::runtime_error& e)
    {
        this->SendErrorMessage( client, cmd, 500, "Failed to read config parameters");
        logg << Logger::Error << "Failed to read sysconfig" << e.what() << lend;
    }
    list<string> ports = Utils::String::Split(forwardports," ");
    list<string>::iterator i;

    i = find(ports.begin(), ports.end(), port);
    if (i != ports.end()) {
        // found port in config
        if (! cmd["set_open"].asBool())
        {
            // remove port
            logg << Logger::Debug << "Remove port" << port << lend;
            ports.erase(i);
        }
    }
    else
    {
        // port is not in config
        if (cmd["set_open"].asBool())
        {
            // add port
            logg << Logger::Debug << "Add port" << port << lend;
            ports.push_back(port);
        }
    }

    forwardports = "";
    for (std::list<string>::iterator it=ports.begin(); it!=ports.end(); ++it)
    {
        if (it != ports.begin())
        {
            forwardports += " "; // add a space between ports
        }

        forwardports += *it;
    }
    try
    {
        sysconfig.PutKey("upnp","forwardports",forwardports);
    }
    catch (std::runtime_error& e)
    {
        this->SendErrorMessage( client, cmd, 500, "Failed to read config parameters");
        logg << Logger::Error << "Failed to read sysconfig" << e.what() << lend;
        return;
    }

    this->SendOK(client, cmd);
}

void OpiBackendServer::DoNetworkGetOpiName(UnixStreamClientSocketPtr &client, Json::Value &cmd) {
	Json::Value res(Json::objectValue);

    ScopedLog l("Get OPI name!");
    SysConfig sysconfig;

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

    try
	{
		res["opiname"] = this->getSysconfigString("hostinfo","hostname");
        res["dnsenabled"] = sysconfig.GetKeyAsBool("dns","enabled");
		res["provider"] = this->getSysconfigString("dns","provider");
		res["domain"] = this->getSysconfigString("hostinfo","domain");
		logg << Logger::Debug << "opiname: " << this->getSysconfigString("hostinfo","hostname").c_str() << " domain: " << this->getSysconfigString("hostinfo","domain").c_str() <<lend;

		this->SendOK(client, cmd, res);
	}
    catch (std::runtime_error& e)
	{
        this->SendErrorMessage( client, cmd, 500, "Failed to read config parameters");
        logg << Logger::Error << "Failed to read sysconfig" << e.what() << lend;
        return;
	}
}

void OpiBackendServer::DoNetworkSetOpiName(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{

	ScopedLog l("Set OPI name");
	Json::Value response(Json::objectValue);
	KGP::IdentityManager& idmgr = KGP::IdentityManager::Instance();

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin( client, cmd ) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_HST , cmd) )
	{
		return;
	}

	string oldcerttype;

	string oldopiname = idmgr.GetHostname();
	string olddomain = idmgr.GetDomain();

	string hostname = cmd["hostname"].asString();
	string domain = cmd["domain"].asString();
	bool   enableDns = cmd["dnsenabled"].asBool();
	string certtype = cmd["CertType"].asString();
	string certificate = cmd["CustomCertVal"].asString();
	string key = cmd["CustomKeyVal"].asString();

	if (SCFG.HasKey("webcertificate","backend"))
	{
		oldcerttype = SCFG.GetKeyAsString("webcertificate","backend");
	}

	bool managedDomain = idmgr.DnsDomainAvailable(domain);
	/* If the domain is in the list of available domains, check with provider.
		*  if the domain is "custom", there is no DNS provider to check with...
		*/
	if ( managedDomain )
	{
		logg << Logger::Debug << "Domain is 'managed'"<<lend;
		// if the domain is in the available domains, check that the full FQDN is available
		if ( ! idmgr.DnsNameAvailable(hostname,domain) )
		{
			this->SendErrorMessage( client, cmd, 401, "FQDN not available");
			logg << Logger::Error << "FQDN not available: " << hostname << "@" << domain << lend;
			return;
		}
		if ( enableDns )
		{
			idmgr.EnableDNS();
		}
		else
		{
			idmgr.DisableDNS();
		}

	} else {
		logg << Logger::Debug << "Domain '"<< domain << "' is not 'managed', disable DNS"<<lend;
		idmgr.DisableDNS();
	}

	bool updatename;
	if( (hostname == oldopiname) && (olddomain == domain) ) {
		// if we use a custom cert, always generate make sure the cert is written
		updatename = false;
		if ( (oldcerttype == certtype) && ( key == "" ) )
		{
			// no need to do any updates on server side
			logg << Logger::Debug << "No name update"<<lend;

			this->SendOK(client, cmd);
			return;
		}
	} else {
		logg << Logger::Debug << "Update sysconfig with new name"<<lend;
		// Update sysconfig with new name
		updatename = true;
		if ( !idmgr.SetFqdn(hostname,domain) )
		{
			this->SendErrorMessage( client, cmd, 500, "Failed to set hostname/domain config parameters");
			logg << Logger::Error << "Failed to set hostname/domain config parameters" << lend;
			return;
		}
	}

	if ( managedDomain ) {
		/* Try update DNS, i.e. reserve name */
		logg << Logger::Info << "Update DNS" << lend;
		if( ! idmgr.AddDnsName(hostname,domain) )
		{
			this->SendErrorMessage( client, cmd, 400, "Failed to register new name/domain");
			return;
		}
	}


	/* Generate certificates */
	/* Certificate backend will not do anything for custom certs, just immediately terminate */
	logg << Logger::Info << "Generate certificates" << lend;
	if ( !idmgr.CreateCertificate(updatename,certtype) )
	{
		this->SendErrorMessage( client, cmd, 400, "Failed to generate certificate(s)");
		return;
	}

	if (certtype == "CUSTOMCERT")
	{

		logg << Logger::Debug << "Supplied key: '" << key << "'" << lend;
		bool valid_cert = this->verifyCertificate(certificate,"cert");
		bool valid_key =  this->verifyCertificate(key,"key");

		if ( ! (  valid_cert && valid_key ) )
		{
			logg << Logger::Debug << "Combination of certs not valid" << lend;
			if ( valid_cert )
			{
				this->SendErrorMessage( client, cmd, 400, "Failed to verify Private Key, possibly missing file or uploaded data.");
			}
			else if ( valid_key )
			{
				this->SendErrorMessage( client, cmd, 400, "Failed to verify Certificate");
			}
			else
			{
				this->SendErrorMessage( client, cmd, 400, "Failed to verify certificate and key");
			}
			return;
		}

		// INPUT VALIDATED, WRITE FILES
		logg << Logger::Debug << "Certificates seem to be Valid" << lend;

		string retmsg;
		bool retval;
		tie(retval,retmsg) = idmgr.WriteCustomCertificate(key,certificate);
		if ( retval )
		{
			this->SendOK( client, cmd);
			// nginx config is correct, restart webserver
			logg << Logger::Debug << "Reloading Nginx config" << lend;
			ServiceHelper::Reload("nginx");
		}
		else
		{
			this->SendErrorMessage( client, cmd, 500, retmsg);
		}


	}

	this->SendOK(client, cmd, response);

	idmgr.CleanUp();

}

void OpiBackendServer::DoNetworkGetDomains(UnixStreamClientSocketPtr &client, Json::Value &cmd) {

    ScopedLog l("Get Domains!");
	KGP::IdentityManager& idmgr = KGP::IdentityManager::Instance();

    if( ! this->CheckLoggedIn(client,cmd) )
    {
        return;
    }

	Json::Value res(Json::objectValue);
	Json::Value d(Json::arrayValue);
	list<string> domains = idmgr.DnsAvailableDomains();

	for(const auto& val: domains)
	{
		d.append(val);
	}
	res["availabledomains"] = d;

	this->SendOK(client, cmd, res);
}

void OpiBackendServer::DoNetworkGetCert(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Get Webserver Certificates");
	Json::Value cfg;

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin( client, cmd ) )
	{
		return;
	}


	if (SCFG.HasKey("webcertificate","backend") )
	{
		cfg["CertType"] = SCFG.GetKeyAsString("webcertificate","backend");
	}
	else
	{
		this->SendErrorMessage( client, cmd, 400, "Failed to read certificate type from sysconfig");
	}


	if ( cfg["CertType"] == "CUSTOMCERT" )
	{
		try
		{
			cfg["CustomCertVal"] = File::GetContentAsString(SCFG.GetKeyAsString("webcertificate","activecert"), true);
		}
		catch (runtime_error& err)
		{
			logg << Logger::Warning << "Failed to read certificate: " << err.what() <<lend;
			cfg["CustomCertVal"] = "";
		}
	}

	if ( cfg["CertType"] == "LETSENCRYPT" )
	{
		string webcert = SCFG.GetKeyAsString("webcertificate","activecert");
		// test to see if signed cert is used, if it could not be generated there is a fallback to default self singed certificate
        logg << Logger::Debug << "Testing for used certificate."<<lend;
	    char buff[PATH_MAX];
	    string certpath;
        ssize_t len = ::readlink(webcert.c_str(), buff, sizeof(buff)-1);
	    if (len != -1)
	    {
	    	buff[len] = '\0';
	    	certpath=std::string(buff);
            logg << Logger::Debug << "CertPath used:" << certpath <<lend;

			if ( File::GetFileName(File::RealPath(certpath)) == File::GetFileName(SCFG.GetKeyAsString("webcertificate","defaultcert")) )
	    	{
	    		cfg["CertStatus"] = "ERROR";
	    		logg << Logger::Debug << "Lets Encrypt cert asked for, but not used."<<lend;		      
	    	}
	    }
	}


	this->SendOK( client, cmd, cfg);
}

void OpiBackendServer::DoNetworkCheckCert(UnixStreamClientSocketPtr &client, Json::Value &cmd) {
	ScopedLog l("Check Webserver Certificates");

	string type = cmd["type"].asString();
	string certificate = cmd["CertVal"].asString();
	
	bool res;

	res = this->verifyCertificate(certificate,type);
	if ( res )
	{
		this->SendOK( client, cmd);
	}
	else
	{
		this->SendErrorMessage( client, cmd, 400, "Failed to verify certificate/key");
	}

}


void OpiBackendServer::DoNetworkGetSettings(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Get network settings");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin( client, cmd ) )
	{
		return;
	}
    string netif = sysinfo.NetworkDevice();
    Json::Value cfg = NetUtils::NetworkConfig().GetInterface( netif );
	Json::Value ret;
	if( cfg["addressing"].asString() == "static" )
	{
		ret["type"] = "static";
		ret["ipnumber"] = cfg["options"]["address"][static_cast<uint>(0)].asString();
		ret["netmask"] = cfg["options"]["netmask"][static_cast<uint>(0)].asString();
		ret["gateway"] = cfg["options"]["gateway"][static_cast<uint>(0)].asString();
	}
	else if( cfg["addressing"].asString() == "dhcp" )
	{
		ret["type"] = "dhcp";
        ret["ipnumber"] = NetUtils::GetAddress( netif );
        ret["netmask"] = NetUtils::GetNetmask( netif );
		ret["gateway"] = NetUtils::GetDefaultRoute();
	}
	else
	{
		this->SendErrorMessage(client, cmd, 500, "Unknown addressing of network interface");
		return;
	}

	NetUtils::ResolverConfig rc;

	list<string> nss = rc.getNameservers();

	ret["dns"]=Json::arrayValue;
	for( auto ns: nss)
	{
		ret["dns"].append(ns);
	}

	this->SendOK( client, cmd, ret);
}

void OpiBackendServer::DoNetworkSetSettings(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Set network settings");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin( client, cmd ) )
	{
		return;
	}

	// Manually verify
	if( !cmd.isMember("type") && !cmd["type"].isString() )
	{
		this->SendErrorMessage(client, cmd, 400, "Missing argument");
		return;
	}

	string type = cmd["type"].asString();
	if( type != "dhcp" && type != "static")
	{
		this->SendErrorMessage(client, cmd, 400, "Missing argument");
		return;
	}

    string netif = sysinfo.NetworkDevice();

	if( type == "dhcp" )
	{
		NetUtils::NetworkConfig nc;
        nc.SetDHCP( netif );
		nc.WriteConfig();
	}
	else
	{
		if( !cmd.isMember("ipnumber") && !cmd["ipnumber"].isString() )
		{
			this->SendErrorMessage(client, cmd, 400, "Missing argument");
			return;
		}
		if( !cmd.isMember("netmask") && !cmd["netmask"].isString() )
		{
			this->SendErrorMessage(client, cmd, 400, "Missing argument");
			return;
		}
		if( !cmd.isMember("gateway") && !cmd["gateway"].isString() )
		{
			this->SendErrorMessage(client, cmd, 400, "Missing argument");
			return;
		}
		if( !cmd.isMember("dns") && !cmd["dns"].isArray() )
		{
			this->SendErrorMessage(client, cmd, 400, "Missing argument");
			return;
		}

		NetUtils::NetworkConfig nc;
        nc.SetStatic( netif, cmd["ipnumber"].asString(), cmd["netmask"].asString(), cmd["gateway"].asString() );
		nc.WriteConfig();

		NetUtils::ResolverConfig rc;
		rc.setDomain("localdomain");
		rc.setSearch("");

		list<string> nss;

		for(unsigned int i = 0; i < cmd["dns"].size(); i++ )
		{
			if( cmd["dns"][i].isString() )
			{
				nss.push_back(cmd["dns"][i].asString());
			}
		}

		rc.setNameservers( nss );
		rc.WriteConfig();
	}

    if( ! NetUtils::RestartInterface( netif ) )
	{
		this->SendErrorMessage( client, cmd, 500, "Failed to restart network");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoShellGetSettings(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do shell get settings");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	Json::Value ret;
	ret["enabled"] = File::FileExists("/usr/sbin/dropbear");

	this->SendOK(client, cmd, ret);
}

void OpiBackendServer::DoShellEnable(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do shell enabled");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	int res = system( "/usr/share/opi-backend/enable_shell.sh" );

	if( ( res < 0) || WEXITSTATUS(res) != 0 )
	{
		this->SendErrorMessage( client, cmd, 500, "Failed to enable shell");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoShellDisable(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do shell disabled");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	int res = system( "/usr/share/opi-backend/disable_shell.sh" );

	if( ( res < 0) || WEXITSTATUS(res) != 0 )
	{
		this->SendErrorMessage( client, cmd, 500, "Failed to disable shell");
		return;
	}

	this->SendOK(client, cmd);
}


void OpiBackendServer::DoSystemGetMessages(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do System Get Messages");
	if( ! this->CheckLoggedIn(client,cmd)  )
	{
		return;
	}

	Json::Value messages(Json::arrayValue);
	// return array of json encoded messages

	// for each file in /var/spool/notify
	if( File::DirExists(NOTIFY_DIR) ) {
		list<string> files = File::Glob(NOTIFY_DIR "*");
		for( const string& file: files)
		{
            if( File::FileExists(file) )
            {
                messages.append(File::GetContentAsString(file, true));
            }
		}
	}
	else
	{
		logg << Logger::Debug << "Spool dir does not exist"<<lend;
		this->SendErrorMessage(client, cmd, 405, "Method not Allowed");
		return;
	}
	Json::Value ret;
	ret["messages"] = messages;
	this->SendOK(client, cmd, ret);
}

void OpiBackendServer::DoSystemAckMessage(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
    ScopedLog l("Do System Ack Message");
	Json::Value ret;
	
	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		this->SendErrorMessage(client, cmd, 404, "Forbidden");
		return;
	}
	// Manually verify
	if( !cmd.isMember("id") && !cmd["id"].isString() )
	{
		this->SendErrorMessage(client, cmd, 400, "Missing argument");
		return;
	}
	logg << Logger::Debug << "Ack message with id: " << cmd["id"].asString() <<lend;
    Notify::ExistingMessage msg(cmd["id"].asString());
    msg.Ack();

	ret["deleted"] = cmd["id"];
	this->SendOK(client, cmd, ret);
}

void OpiBackendServer::DoSystemGetStatus(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do System Get Status");
	Json::Value ret;
	string Message, uptimescript, tempscript;
	int retval;

	uptimescript ="/usr/bin/uptime -p";
	tie(retval,Message)=Process::Exec( uptimescript );
	if ( retval )
	{
		ret["uptime"]=Message.substr(3,string::npos);
	}
	else
	{
		ret["uptime"]=0;
	}
	tempscript = "/sys/class/thermal/thermal_zone0/temp"; // works on XU4...
	if ( File::FileExists(tempscript) )
	{
		tie(retval,Message)=Process::Exec( "cat " + tempscript );
		ret["temperature"]=Message;
	} else {
		ret["temperature"]=0;
	}
	this->SendOK(client, cmd, ret);
}

void OpiBackendServer::DoSystemGetStorage(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do System Get Storage");
	Json::Value ret;
	string ExecOutput, storagescript;
	vector<string> storage;
	
	int retval;
	
	// prints only the line with the data partition and in the order of "total, used, available" in 1k blocks

    storagescript ="df -l | grep \""+String::Trimmed(SysConfig().GetKeyAsString("filesystem","storagemount"),"/")+"\" | awk '{print $2 \" \" $3 \" \" $4}'";
	tie(retval,ExecOutput)=Process::Exec( storagescript );
	if ( retval )
	{
		String::Split(ExecOutput,storage," ");

        ret["storage"]["total"]=storage[0];
		ret["storage"]["used"]=storage[1];
		ret["storage"]["available"]=storage[2];
		
		this->SendOK(client, cmd, ret);
	}
	else
	{
		this->SendErrorMessage(client, cmd, 500, "Internal Error");
	}
		
}

//TODO: Refactor
void OpiBackendServer::DoSystemGetUnitid(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do System Get Unitid");
	Json::Value ret;
	string scope;
	string key;

	if( !this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	scope = "hostinfo";
	key = "unitid";
	ret[key] = this->getSysconfigString(scope,key);

	key = "unitidbak";
	ret[key] = this->getSysconfigString(scope,key);

	scope = "dns";
	key = "provider";
	ret[key] = this->getSysconfigString(scope,key);
	key = "enabled";
	ret[key] = this->getSysconfigBool(scope,key);

	this->SendOK(client, cmd, ret);

}

//TODO: Refactor
void OpiBackendServer::DoSystemSetUnitid(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do System Set Unitid");
	Json::Value ret;

	string passphrase;
	bool passphrasefound = false;

	if( !this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	// Manually verify passed parameters
	if( !cmd.isMember("unitid") && !cmd["unitid"].isString() )
	{
		this->SendErrorMessage(client, cmd, 400, "Missing argument");
		return;
	}
	if( !cmd.isMember("mpwd") && !cmd["mpwd"].isString() )
	{
		this->SendErrorMessage(client, cmd, 400, "Missing argument");
		return;
	}
	if( !cmd.isMember("enabled") && !cmd["enabled"].isBool() )
	{
		this->SendErrorMessage(client, cmd, 400, "Missing argument");
		return;
	}

	string mpwd = cmd["mpwd"].asString();
	string unitid = cmd["unitid"].asString();
	bool enabled = cmd["enabled"].asBool();

	// Read fs-passphrase from backup config.
	string authfile = this->getSysconfigString("backup","authfile");
	list<string> authdata = File::GetContent(authfile);
	if ( authfile == "" ){
		logg << Logger::Info<< "No backup authfile found, unable to verify MPWD: " <<lend;
		this->SendErrorMessage(client, cmd, 400, "Unable to verify Master Password");
		return;
	}

	// Find the passphrase
	for( auto authline: authdata )
	{
		list<string> data = String::Split(authline,":");
		if ( data.front() == "fs-passphrase")
		{
			passphrase = data.back();
			passphrasefound = true;
			// Don't write sensitive data to logfile
			//logg << Logger::Debug << "Read passphrase: " << passphrase <<lend;
			break;
		}
	}
	if( ! passphrasefound )
	{
		logg << Logger::Info<< "No backup passphrase found, unable to verify MPWD: " <<lend;
		this->SendErrorMessage(client, cmd, 400, "Unable to verify Master Password");
		return;
	}

	// Input data confirmed, move on to verify password.

	string calc_passphrase;
	SecString spass(mpwd.c_str(), mpwd.size() );
	SecVector<byte> key = PBKDF2( spass, 20);
	vector<byte> ukey(key.begin(), key.end());

	calc_passphrase = Base64Encode( ukey );
	// Don't write sensitive data to logfile
	//logg << Logger::Debug<< "Calculated passphrase: " << calc_passphrase <<lend;

	if ( passphrase != calc_passphrase)
	{
		logg << Logger::Info<< "Incorrect Master Password" <<lend;
		this->SendErrorMessage(client, cmd, 403, "Incorrect Master Password");
		return;
	}

	SysConfig sysconfig(true);
	KGP::IdentityManager& idmgr = KGP::IdentityManager::Instance();

	if ( enabled )
	{
		// Try to login and set system keys
		bool status;
		string token;

		tie(status,token) = idmgr.UploadKeys(unitid,mpwd);

		if (! status) {
			logg << Logger::Error<< "Failed to upload keys" <<lend;
			this->SendErrorMessage(client, cmd, 500, "Failed to upload keys");
			return;
		}
		try
		{
			sysconfig.PutKey("hostinfo","unitid",unitid);
			if (sysconfig.HasKey("hostinfo","unitidbak"))
			{
				sysconfig.RemoveKey("hostinfo","unitidbak");
			}
		}
		catch ( std::runtime_error& err )
		{
			logg << Logger::Error<< "Failed to set keys in sysconfig: " << err.what() <<lend;
			this->SendErrorMessage(client, cmd, 500, "Failed to set keys in sysconfig");
			return;
		}

	}
	else
	{
		try
		{
			if ( this->getSysconfigString("backup","backend") == "s3op://")
			{
				// unmount OP backend to have a clean backup, but let target stay on
				// OP servers so that it will fail next time to make user aware that
				// backups do not work anymore.
				OPI::BackupHelperPtr backuphelper;
				backuphelper = BackupHelperPtr( new BackupHelper( "" ) );
				backuphelper->UmountRemote();
			}
			sysconfig.PutKey("hostinfo","unitidbak",unitid);
			sysconfig.PutKey("dns","enabled",false);
			if ( sysconfig.HasKey("hostinfo","unitid") )
			{
				sysconfig.RemoveKey("hostinfo","unitid");
			}
		}
		catch ( std::runtime_error& err )
		{
			logg << Logger::Error<< "Failed to disabled keys in sysconfig: " << err.what() <<lend;
			this->SendErrorMessage(client, cmd, 500, "Failed to disable keys in sysconfig");
			return;
		}
	}
	this->SendOK(client, cmd, ret);

}


void OpiBackendServer::DoSystemGetType(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
    ScopedLog l("Do System Get Type");
    Json::Value ret;

	size_t type;
    string typeText;

    type=OPI::sysinfo.Type();
    typeText=OPI::sysinfo.SysTypeText[type];

	ret["type"]=Json::Int(type);
    ret["typeText"]=typeText;

    try
    {
        ret["theme"] = SysConfig().GetKeyAsString("webapps","theme");
    }
    catch( std::runtime_error& err)
    {
		(void) err;
        logg << Logger::Debug << "No webapps theme set" <<lend;
    }

    this->SendOK(client, cmd, ret);

}

void OpiBackendServer::DoSystemGetPackages(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do System Get Packages");
	list<string> packages,dpkglist;
    string packagescript, packagelist, ExecOutput, FailedPkgs;
	bool valid_list=false;
	Json::Value ret;
	int retval;
	Regex r;

	if ( File::FileExists(PACKAGE_INFO) )
	{
		packagelist = "";
		packages = File::GetContent(PACKAGE_INFO);
		r.Compile("([^0-9a-zA-Z_\\-])");  // do not allow any weird characters i name....
		for( auto package: packages )
		{
			if ( package.length() ) // do not include empty lines
			{
				
				if ( r.DoMatch(package).size() )
				{
					logg << Logger::Debug << "PACKAGE NAME NOT SAFE for SHELL: " << package <<lend;
				} else {
					//logg << Logger::Debug << "SAFE PACKAGE NAME " << package <<lend;
					packagelist += " "+package;
					valid_list= true;
				}
				
			}
		}
		if( valid_list )
		{
            packagescript = "dpkg -l "+packagelist +" | grep ^ii | awk '{print $2 \" \" $3 \" \" $1}'";
			tie(retval,ExecOutput)=Process::Exec( packagescript );
		}

        // Also get packages not correctly installed
        packagescript = "dpkg -l | grep -v ^ii | tail -n +6 | awk '{print $2, $3, $1}'";
        tie(retval,FailedPkgs)=Process::Exec( packagescript );

        ExecOutput=ExecOutput+FailedPkgs;
		if (retval)
		{
			String::Split(ExecOutput,dpkglist,"\n");
			for( auto pkg:dpkglist )
			{
				vector<string> curr_pkg;
				String::Split(pkg,curr_pkg," ");
                if ( curr_pkg.size() == 3 ) {
                    ret["packages"][curr_pkg[0]] = curr_pkg[1] +"("+curr_pkg[2]+")";
				}
				else
				{
					logg << Logger::Debug << "Illegal package length " << pkg.length() <<lend;
				}
			}
			
			this->SendOK(client, cmd, ret);
		}
		else
		{
			this->SendErrorMessage(client, cmd, 500, "Internal Error");
		}
	}
	else
	{
		logg << Logger::Debug << "No package list available"<<lend;
		this->SendErrorMessage(client, cmd, 405, "Method not Allowed");
		return;
	}
}

string OpiBackendServer::getSysconfigString(string scope, string key)
{
	if ( SysConfig().HasKey(scope,key) )
	{
		try
		{
			return SysConfig().GetKeyAsString(scope,key);
		}
		catch( std::runtime_error& err)
		{
			(void) err;
			logg << Logger::Debug << "Missing "<< scope << "->" << key << " in sysconfig" <<lend;
		}
	}
	return "";
}

bool OpiBackendServer::getSysconfigBool(string scope, string key)
{
	if ( SysConfig().HasKey(scope,key) )
	{
		try
		{
			return SysConfig().GetKeyAsBool(scope,key);
		}
		catch( std::runtime_error& err)
		{
			(void) err;
			logg << Logger::Debug << "Missing "<< scope << "->" << key << " in sysconfig" <<lend;
		}
	}
	return false;
}

bool OpiBackendServer::CheckLoggedIn(UnixStreamClientSocketPtr &client, Json::Value &req)
{
	if( !req.isMember("token") && !req["token"].isString() )
	{
		this->SendErrorMessage(client, req, 400, "Missing argument");
		return false;
	}

	string token = req["token"].asString();

	if( ! this->clients.IsTokenLoggedin( token ) )
	{
		this->SendErrorMessage(client, req, 401, "Unauthorized");
		return false;
	}

	return true;
}

// Assumes that check for logged in has been performed
bool OpiBackendServer::CheckIsAdmin(UnixStreamClientSocketPtr &client, Json::Value &req)
{
	string token = req["token"].asString();

	if( ! this->isAdmin( token ) )
	{
		this->SendErrorMessage(client, req, 401, "Unauthorized");
		return false;
	}
	return true;
}

// Assumes that check for logged in has been performed
bool OpiBackendServer::CheckIsAdminOrUser(UnixStreamClientSocketPtr &client, Json::Value &req)
{
	string token = req["token"].asString();

	// If no username, check for admin only
	if( ! req.isMember("username") )
	{
		return this->CheckIsAdmin(client,req);
	}

	string user = req["username"].asString();

	if( ! this->isAdminOrUser( token, user ) )
	{
		this->SendErrorMessage(client, req, 401, "Unauthorized");
		return false;
	}
	return true;
}

bool OpiBackendServer::isAdmin(const string &token)
{
	return this->clients.GetClientByToken(token)->IsAdmin();
}

bool OpiBackendServer::isAdminOrUser(const string &token, const string &user)
{
	// return this->isAdmin( token ) || ( this->users[user] == token );

	if( this->isAdmin( token ) )
	{
		return true;
	}

	WebClientPtr wc = this->clients.GetClientByUsername(user);

	return wc &&  ( wc->Token() == token );
}

string OpiBackendServer::BackendLogin(const string &unit_id)
{
	AuthServer s( unit_id);

	int resultcode;
	Json::Value ret;

	tie(resultcode, ret) = s.Login();

	return resultcode == 200 ? ret["token"].asString() : "";
}

void OpiBackendServer::ReapClients()
{
	// Only reap once a minute
	if( this->lastreap + 60 > time(nullptr) )
	{
		return;
	}

	logg << Logger::Debug << "Reap clients"<<lend;

	this->clients.Reap();

	this->lastreap = time(nullptr);
}

Json::Value OpiBackendServer::UserToJson(const UserPtr user)
{

	Json::Value ret;
	ret["username"] = user->GetUsername();
	ret["id"] = user->GetUsername();
	ret["displayname"] = user->GetDisplayname();

	try
	{
		ret["defaultemail"] = user->GetAttribute("defaultemail");
	}
	catch( std::runtime_error& err)
	{
		// No error if default email is missing
		(void) err;
		ret["defaultemail"] ="";
	}

	return ret;
}

void OpiBackendServer::ProcessOneCommand(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	string action = cmd["cmd"].asString();
	if( this->actions.find(action) != this->actions.end() )
	{
		try
		{
			((*this).*actions[action])(client,cmd);
		}
		catch( std::runtime_error& err)
		{
			logg << Logger::Error << "Failed to execute command "<< action << " : "<<err.what()<<lend;
			this->SendErrorMessage(client, cmd, 4, "Internal error");
		}
	}
	else
	{
		this->SendErrorMessage(client, cmd, 4, "Unknown action");
		return;
	}

}

void OpiBackendServer::SendReply(UnixStreamClientSocketPtr &client, Json::Value &val)
{
	string r = this->writer.write(val);
    //logg << Logger::Debug << "JSON REPLY "<< r <<lend;
	client->Write(r.c_str(), r.length());
}

void OpiBackendServer::SendErrorMessage(UnixStreamClientSocketPtr &client, const Json::Value &cmd, int errcode, const string &msg)
{
	(void) cmd;
	Json::Value ret(Json::objectValue);
	ret["status"]["value"]=errcode;
	ret["status"]["desc"]=msg;
	
	this->SendReply(client, ret);
}

void OpiBackendServer::SendOK(UnixStreamClientSocketPtr &client, const Json::Value &cmd, const Json::Value &val)
{
	(void) cmd;
	Json::Value ret(Json::objectValue);
	ret["status"]["value"]=0;
	ret["status"]["desc"]="OK";

	// Append any possible extra values to answer
	if( ! val.isNull() )
	{
		for( auto x: val.getMemberNames() )
		{
			ret[x]=val[x];
		}
	}

	this->SendReply(client, ret);
}

void OpiBackendServer::typecheckcallback(const string& msg, void* data)
{
	(void) data;
	logg << Logger::Debug << "Typecheck failed: " << msg <<lend;
}

bool OpiBackendServer::CheckArguments(UnixStreamClientSocketPtr& client, int what,const Json::Value& cmd)
{
	if( ! this->typechecker.Verify(what, cmd) )
	{
		this->SendErrorMessage(client, cmd, 400, "Missing argument");
		return false;
	}
	return true;
}

bool OpiBackendServer::verifyCertificate(string cert, string type)
{
	logg << Logger::Debug << "Verify Certificate" << lend;

	int retval=1, sslret=0;
	string Message;

	string CustomKeyFile, opensslscript;
	string tmpFile=this->getTmpFile("/tmp/",".key");
	string tmpSplitCert=this->getTmpFile("/tmp/",".part");

	if ( type == "key" && ! cert.length())
	{
		logg << Logger::Debug << "No private key supplied, reading from file" << lend;
        // no key was passed in the post, try to use existing one on file
        try
        {
			CustomKeyFile = SCFG.GetKeyAsString("webcertificate","activekey");
        }
        catch (std::runtime_error& e)
        {
            logg << Logger::Error << "Failed to read sysconfig" << e.what() << lend;
            return false;
        }

		if( ! File::FileExists( File::RealPath(CustomKeyFile) ) )
		{
			logg << Logger::Debug << "File '" << CustomKeyFile <<"' does not seem to exist" << lend;
			return false;
		}
		else
		{
			logg << Logger::Debug << "Reading Private Key from file" << lend;
			opensslscript ="openssl rsa -check -noout -in " + CustomKeyFile;
			tie(retval,Message)=Process::Exec( opensslscript );
		}
	}
	else
	{
		if ( type == "key" )
		{
			logg << Logger::Debug << "Checking supplied key" << lend;
			File::Write( tmpFile, cert, 0600);		
			opensslscript ="openssl rsa -check -noout -in " + tmpFile;
			tie(retval,Message)=Process::Exec( opensslscript );
			if ( File::FileExists( tmpFile) )
			{
				File::Delete( tmpFile );
			}
		}
		else if ( type == "cert" )
		{
			logg << Logger::Debug << "Checking supplied cert" << lend;
			// check for multiple certs

			std::string delimiter = "-----END CERTIFICATE-----";

			size_t pos = 0;
			std::string token;
			int count=0;
			while ((pos = cert.find(delimiter)) != std::string::npos) {
				count++;
			    token = cert.substr(0, pos+delimiter.length());
				File::Write( tmpSplitCert, token, 0600);		
			    cert.erase(0, pos+delimiter.length());
				opensslscript ="openssl x509 -text -noout -in " + tmpSplitCert;
				tie(sslret,Message)=Process::Exec( opensslscript );
				if ( File::FileExists( tmpSplitCert) )
				{
					File::Delete( tmpSplitCert );
				}
				retval &= sslret;

			}
			retval &= sslret;

		}	
		else
		{
			logg << Logger::Debug << "Unknown certificate type" << lend;
			return false;
		}
	}	

	return retval;
}
string OpiBackendServer::getTmpFile(string path,string suffix)
{
	string filename;
	filename = path+String::UUID()+suffix;
	while( File::FileExists( filename ))
	{
		filename = path+String::UUID()+suffix;
	}
	return filename;
}
