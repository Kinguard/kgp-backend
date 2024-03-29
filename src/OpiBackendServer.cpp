#include "OpiBackendServer.h"
#include "Config.h"

#include <libutils/Logger.h>
#include <libutils/String.h>
#include <libutils/FileUtils.h>
#include <libutils/ConfigFile.h>
#include <libutils/UserGroups.h>
#include <libutils/Regex.h>
#include <libutils/HttpStatusCodes.h>

#include <libopi/AuthServer.h>
#include <libopi/CryptoHelper.h>
#include <libopi/ServiceHelper.h>
#include <libopi/NetworkConfig.h>
#include <libopi/SmtpConfig.h>
#include <libopi/SysInfo.h>
#include <libopi/SysConfig.h>

#include <libopi/JsonHelper.h>

#include <kinguard/IdentityManager.h>
#include <kinguard/NetworkManager.h>
#include <kinguard/BackupManager.h>
#include <kinguard/SystemManager.h>
#include <kinguard/UserManager.h>
#include <kinguard/MailManager.h>

#include <algorithm>

#include <unistd.h>
#include <linux/limits.h>

using namespace OPI;
using namespace OPI::JsonHelper;
using namespace KGP;
using namespace Utils::HTTP;

// Convenience defines
#define SCFG	(OPI::SysConfig())

/*
 * Bit patterns for argument checks
 * (A bit uggly but effective)
 */
constexpr int CHK_USR	= 0x00000001;	// Check username
constexpr int CHK_PWD	= 0x00000002;	// Check password
constexpr int CHK_DSP	= 0x00000004;	// Check displayname
constexpr int CHK_NPW	= 0x00000008;	// Check new password
constexpr int CHK_GRP	= 0x00000010;	// Check group
constexpr int CHK_DMN	= 0x00000020;	// Check domain
constexpr int CHK_ADR	= 0x00000040;	// Check address
constexpr int CHK_HST	= 0x00000080;  // Check hostname
constexpr int CHK_IDN	= 0x00000100;  // Check identity
constexpr int CHK_PRT	= 0x00000200;  // Check port
constexpr int CHK_EML	= 0x00000400;  // Check email
constexpr int CHK_SSL	= 0x00000800;  // Check ssl
constexpr int CHK_TYP	= 0x00001000;  // Check type
constexpr int CHK_SND	= 0x00002000;  // Check send
constexpr int CHK_RCV	= 0x00004000;  // Check receive
constexpr int CHK_DEM	= 0x00008000;  // Check default email

constexpr int CHK_ORIGID	= 0x00010000;  // Check original identity
constexpr int CHK_ORIGHST	= 0x00020000; // Check original hostname

static const vector<TypeChecker::Check> argchecks(
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

OpiBackendServer::OpiBackendServer(const string &socketpath):
	Utils::Net::NetServer(UnixStreamServerSocketPtr( new UnixStreamServerSocket(socketpath)), 0),
	islocked(false),
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
	this->actions["backupstartbackup"]=&OpiBackendServer::DoBackupStartBackup;

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
	this->actions["dosystemgetupgrade"]=&OpiBackendServer::DoSystemGetUpgrade;
	this->actions["dosystemstartupgrade"]=&OpiBackendServer::DoSystemStartUpgrade;
	this->actions["dosystemstartupdate"]=&OpiBackendServer::DoSystemStartUpdate;


	// Setup mail paths etc
	MailManager::SetupEnvironment();

	// Initialize time for last reap
	this->lastreap = time(nullptr);
}

constexpr static int32_t BUFSIZE = (64*1024);

void OpiBackendServer::Dispatch(SocketPtr con)
{
	ScopedLog l("Dispatch");

	// Convert into unixsocket
	UnixStreamClientSocketPtr sock = static_pointer_cast<UnixStreamClientSocket>(con);

	char buf[BUFSIZE];
	size_t rd = 0, rd_total=0;
	int retries = 5;

	try
	{
		while( (rd = sock->Read(&buf[rd_total], BUFSIZE - rd_total )) > 0 )
		{
			rd_total += rd;

			logg << "Read request of socket (" <<rd << "/"<<rd_total << ") bytes"<<lend;

			try
			{
				json req = json::parse(buf, buf+rd_total);

				if( req.contains("cmd") && req["cmd"].is_string() )
				{
					this->ProcessOneCommand(sock, req);
					retries = 5;
					rd_total = 0;
				}
				else
				{
					this->SendErrorMessage(sock, json(), 4, "Missing command in request");
					break;
				}

			}
			catch(json::parse_error& err)
			{
				logg << Logger::Notice << "Unable to parse request: " << err.what() << lend;
				if( retries-- == 0 )
				{
					this->SendErrorMessage(sock, json(), 4, "Unable to parse request");
					break;
				}
			}
		}
	}
	catch(Utils::ErrnoException& e)
	{
		logg << Logger::Debug << "Caught exception on socket read ("<<e.what()<<")"<<lend;
	}

	if( this->islocked )
	{
		// Backend is locked, make sure no one is logged in
		this->clients.Purge();
	}
	else
	{
		// Check and possibly remove clients not active
		// This is ok since we are guaranteed not to process any client now
		this->ReapClients();
	}

	this->decreq();

}

OpiBackendServer::~OpiBackendServer() = default;

void OpiBackendServer::DoLogin(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("DoLogin");

	if( this->islocked )
	{
		this->SendErrorMessage(client,cmd,Status::ServiceUnavailable,"Backend locked");
		return;
	}

	if( ! this->CheckArguments(client, CHK_USR|CHK_PWD, cmd) )
	{
		return;
	}

	string username = cmd["username"].get<string>();
	string password = cmd["password"].get<string>();

	if( this->clients.IsUsernameLoggedin( username ))
	{
		logg << Logger::Debug << "User seems already logged in, validating anyway"<<lend;

		try {
			WebClientPtr wc = this->clients.GetClientByUsername( username );
			SecopPtr secop = wc->Secop();

			if( ! secop )
			{
				logg << Logger::Error << "Missing connection to secop"<<lend;
				this->SendErrorMessage(client, cmd, Status::InternalServerError, "Failed connecting to backing store");
				return;
			}

			if( ! secop->PlainAuth(username, password)  )
			{
				this->SendErrorMessage(client, cmd, Status::Unauthorized, "Failed");
				return;
			}

			// User reauthorized?? Return same token
			json ret;
			ret["token"] = wc->Token();

			this->SendOK(client, cmd, ret);
		}
		catch (std::runtime_error& err)
		{
			logg << Logger::Notice << "Failed to (re)authenticate user. Stale connection?"
				 << " (" << err.what() << ")"
				 << lend;

			// Todo, fix generic cleanup.

			this->SendErrorMessage(client, cmd, Status::BadRequest, "Failed");
		}

		return;
	}
	else
	{
		SecopPtr secop(new Secop() );
		if( ! secop->PlainAuth(username,password) )
		{
			this->SendErrorMessage(client, cmd, Status::Unauthorized, "Failed");
			return;
		}

		// we have a new login
		WebClientPtr wc = this->clients.CreateNewClient( username, secop );

		json ret;
		ret["token"] = wc->Token();

		this->SendOK(client, cmd, ret);
	}
}

void OpiBackendServer::DoAuthenticate(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Do Authenticate");

	// TODO: Should one have to be logged in to do this?

	if( ! this->CheckArguments(client, CHK_USR|CHK_PWD, cmd) )
	{
		return;
	}

	string username = cmd["username"].get<string>();
	string password = cmd["password"].get<string>();

	// We do this on a new temporary connection
	SecopPtr secop(new Secop() );
	if( ! secop->PlainAuth(username,password) )
	{
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoCreateUser(UnixStreamClientSocketPtr &client, json &cmd)
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

	string token =		cmd["token"].get<string>();
	string user =		cmd["username"].get<string>();
	string pass =		cmd["password"].get<string>();
	string display =	cmd["displayname"].get<string>();

	SecopPtr secop = this->clients.GetClientByToken(token)->Secop();


	UserManagerPtr umgr = UserManager::Instance(secop);

	if( ! umgr->AddUser(user,pass, display, false) )
	{
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoDeleteUser(UnixStreamClientSocketPtr &client, json &cmd)
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

	string token =		cmd["token"].get<string>();
	string user =		cmd["username"].get<string>();

	WebClientPtr wc = this->clients.GetClientByToken( token );

	if( user == wc->Username() )
	{
		// Not allowed to comit suicide
		this->SendErrorMessage(client, cmd, Status::Forbidden, "Not allowed");
		return;
	}

	UserManagerPtr umgr = UserManager::Instance( wc->Secop() );

	if( ! umgr->DeleteUser(user) )
	{
		logg << Logger::Notice << "Failed to remove user: "<< umgr->StrError()<<lend;
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoGetUser(UnixStreamClientSocketPtr &client, json &cmd)
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

	string token =		cmd["token"].get<string>();
	string user =		cmd["username"].get<string>();

	SecopPtr secop = this->clients.GetClientByToken( token )->Secop();

	UserManagerPtr umgr = UserManager::Instance( secop );

	KGP::UserPtr usr = umgr->GetUser(user);

	if( ! usr )
	{
		logg << Logger::Notice << "User not found: " << umgr->StrError() << lend;
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Not found");
		return;
	}

	json ret = this->UserToJson(usr);

	this->SendOK(client, cmd,ret);
}

void OpiBackendServer::DoGetUserIdentities(UnixStreamClientSocketPtr &client, json &cmd)
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

	string user = cmd["username"].get<string>();

	// TODO: Validate that user exists!

	MailManager& mmgr = MailManager::Instance();

	// Get all remote addresses
	list<map<string,string>> accounts = mmgr.GetRemoteAccounts(user);

	json ids=json::array();
	for( auto& account: accounts )
	{
		ids.push_back(account["email"]);
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
				ids.push_back(get<0>(address)+"@"+domain);
			}
		}
	}

	json ret;
	ret["identities"] = ids;

	this->SendOK(client, cmd,ret);
}

void OpiBackendServer::DoUserExists(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Do user exists");

	if( ! this->CheckArguments(client, CHK_USR, cmd) )
	{
		return;
	}

	string user =		cmd["username"].get<string>();

	UserManagerPtr umgr = UserManager::Instance();

	bool exists = umgr->UserExists( user );

	json ret;
	ret["username"] = user;
	ret["exists"] = exists;

	this->SendOK(client, cmd,ret);
}

void OpiBackendServer::DoUpdateUser(UnixStreamClientSocketPtr &client, json &cmd)
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

	string token =			cmd["token"].get<string>();
	string user =			cmd["username"].get<string>();
	string disp =			cmd["displayname"].get<string>();
	string defaultemail =	cmd["defaultemail"].get<string>();

	SecopPtr secop = this->clients.GetClientByToken( token )->Secop();

	UserManagerPtr umgr = UserManager::Instance(secop);

	UserPtr usr = umgr->GetUser(user);

	if( ! usr )
	{
		logg <<  Logger::Notice << "Retrieve user failed: " << umgr->StrError() << lend;
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Operation failed");
		return;
	}

	usr->AddAttribute("displayname", disp);
	usr->AddAttribute("defaultemail", defaultemail);

	if( ! umgr->UpdateUser( usr ) )
	{
		logg <<  Logger::Notice << "Update user failed: " << umgr->StrError() << lend;
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Operation failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoGetUsers(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Do get users");

	if( ! this->CheckLoggedIn(client,cmd)  )
	{
		return;
	}

	string token = cmd["token"].get<string>();

	SecopPtr secop = this->clients.GetClientByToken( token )->Secop();

	UserManagerPtr umgr = UserManager::Instance(secop);

	list<UserPtr> users = umgr->GetUsers();

	json ret;
	ret["users"]=json::array();
	for(const auto& user: users)
	{
		ret["users"].push_back( this->UserToJson( user ) );
	}

	this->SendOK(client, cmd, ret);
}

void OpiBackendServer::DoGetUserGroups(UnixStreamClientSocketPtr &client, json &cmd)
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

	string user =		cmd["username"].get<string>();
	string token =		cmd["token"].get<string>();

	SecopPtr secop = this->clients.GetClientByToken( token )->Secop();

	UserManagerPtr umgr = UserManager::Instance(secop);

	list<string> groups = umgr->GetUserGroups( user );

	json ret;
	ret["groups"]=json::array();
	for(const auto& group: groups)
	{
		ret["groups"].push_back( group );
	}

	this->SendOK(client, cmd, ret);
}

void OpiBackendServer::DoUpdateUserPassword(UnixStreamClientSocketPtr &client, json &cmd)
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

	string token =		cmd["token"].get<string>();
	string user =		cmd["username"].get<string>();
	string passw =		cmd["password"].get<string>();
	string newps =		cmd["newpassword"].get<string>();

	WebClientPtr wc = this->clients.GetClientByToken( token );

	SecopPtr secop = wc->Secop();

	UserManagerPtr umgr = UserManager::Instance(secop);

	if( ! umgr->UpdateUserPassword( user, newps, passw ) )
	{
		logg << Logger::Notice << "Failed to update user password: " << umgr->StrError() << lend;
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Operation failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoGetGroups(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Do get groups");

	UserManagerPtr umgr = UserManager::Instance();

	list<string> groups = umgr->GetGroups();

	json ret;
	ret["groups"]= json::array();
	for(const auto& group: groups)
	{
		ret["groups"].push_back( group );
	}

	this->SendOK(client, cmd, ret);
}

void OpiBackendServer::DoAddGroup(UnixStreamClientSocketPtr &client, json &cmd)
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

	string token =	cmd["token"].get<string>();
	string group =	cmd["group"].get<string>();

	SecopPtr secop = this->clients.GetClientByToken( token )->Secop();
	UserManagerPtr umgr = UserManager::Instance(secop);


	if( !umgr->AddGroup(group) )
	{
		logg << Logger::Notice << "Failed to add group: " << umgr->StrError() << lend;
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Operation failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoAddGroupMember(UnixStreamClientSocketPtr &client, json &cmd)
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

	string token =	cmd["token"].get<string>();
	string group =	cmd["group"].get<string>();
	string member =	cmd["member"].get<string>();

	SecopPtr secop = this->clients.GetClientByToken( token )->Secop();
	UserManagerPtr umgr = UserManager::Instance(secop);

	if( !umgr->AddGroupMember(group, member) )
	{
		logg << Logger::Notice << "Failed to add member to group: " << umgr->StrError() << lend;
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Operation failed");
		return;
	}

	if( group == "admin" )
	{
		MailManager& mmgr = MailManager::Instance();

		if( ! mmgr.AddToAdmin( member ) )
		{
			logg << Logger::Error << "Failed to add user to admin mail: "<< mmgr.StrError() << lend;
			this->SendErrorMessage(client, cmd, Status::BadRequest, "Operation failed");
			return;
		}

		if( ! mmgr.Synchronize() )
		{
			logg << Logger::Error << "Failed to synchronize mail settings: "<< mmgr.StrError() << lend;
			this->SendErrorMessage(client, cmd, Status::InternalServerError, "Operation failed");
			return;
		}
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoGetGroupMembers(UnixStreamClientSocketPtr &client, json &cmd)
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

	string token =	cmd["token"].get<string>();
	string group =	cmd["group"].get<string>();

	SecopPtr secop = this->clients.GetClientByToken( token )->Secop();
	UserManagerPtr umgr = UserManager::Instance(secop);

	list<string> members = umgr->GetGroupMembers( group );

	json ret;
	ret["members"]= json::array();

	for( const auto& member: members)
	{
		ret["members"].push_back(member);
	}

	this->SendOK(client, cmd, ret);
}

void OpiBackendServer::DoRemoveGroup(UnixStreamClientSocketPtr &client, json &cmd)
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

	string token =	cmd["token"].get<string>();
	string group =	cmd["group"].get<string>();

	SecopPtr secop = this->clients.GetClientByToken( token )->Secop();
	UserManagerPtr umgr = UserManager::Instance(secop);

	if( !umgr->DeleteGroup(group) )
	{
		logg << Logger::Notice << "Failed to delete group: " << umgr->StrError() << lend;
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Operation failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoRemoveGroupMember(UnixStreamClientSocketPtr &client, json &cmd)
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

	string token =	cmd["token"].get<string>();
	string group =	cmd["group"].get<string>();
	string member =	cmd["member"].get<string>();

	WebClientPtr wc = this->clients.GetClientByToken( token );

	if( ( group == "admin" ) && ( member == wc->Username() ) )
	{
		this->SendErrorMessage(client, cmd, Status::Forbidden, "Not allowed");
		return;
	}

	SecopPtr secop = wc->Secop();
	UserManagerPtr umgr = UserManager::Instance(secop);

	if( !umgr->DeleteGroupMember(group, member) )
	{
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Operation failed");
		return;
	}

	if( group == "admin" )
	{
		MailManager& mmgr = MailManager::Instance();

		if( ! mmgr.RemoveFromAdmin( member ) )
		{
			logg << Logger::Error << "Failed to add user to admin mail: "<< mmgr.StrError() << lend;
			this->SendErrorMessage(client, cmd, Status::BadRequest, "Operation failed");
			return;
		}

		if( ! mmgr.Synchronize() )
		{
			logg << Logger::Error << "Failed to synchronize mail settings: "<< mmgr.StrError() << lend;
			this->SendErrorMessage(client, cmd, Status::InternalServerError, "Operation failed");
			return;
		}
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoShutdown(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Do shutdown");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	string action =	cmd["action"].get<string>();

	if( action == "shutdown" || action == "reboot" )
	{
		this->SendOK(client, cmd);
	}
	else
	{
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Bad request");
		return;
	}

	// give some time for UI to respond
	sleep(3);
	if( action == "shutdown")
	{
		tie(std::ignore, std::ignore) = Process::Exec("/sbin/poweroff");
	}
	else if( action == "reboot" )
	{
		tie(std::ignore, std::ignore) = Process::Exec("/sbin/reboot");
	}
}

void OpiBackendServer::DoUpdateGetstate(UnixStreamClientSocketPtr &client, json &cmd)
{
	json res;

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
		this->SendErrorMessage( client, cmd, Status::InternalServerError, "Failed to read config parameters");
        logg << Logger::Error << "Failed to read sysconfig" << e.what() << lend;
        return;
    }

}

void OpiBackendServer::DoUpdateSetstate(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Set update state");
	string doupdates = cmd["state"].get<string>();
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
		this->SendErrorMessage( client, cmd, Status::InternalServerError, "Failed to read config parameters");
        logg << Logger::Error << "Failed to read sysconfig" << e.what() << lend;
        return;
    }

	this->SendOK(client, cmd);

}

static json getAWSRegions()
{
	json regions;
	regions["us-east-1"			]="US East (Ohio)           ";
	regions["us-east-2"			]="US East (N. Virginia)    ";
	regions["us-west-1"			]="US West (N. California)  ";
	regions["us-west-2"			]="US West (Oregon)         ";
	regions["af-south-1"		]="Africa (Cape Town)       ";
	regions["ap-east-1"			]="Asia Pacific (Hong Kong) ";
	regions["ap-south-1"		]="Asia Pacific (Mumbai)    ";
	regions["ap-northeast-3"	]="Asia Pacific (Osaka)     ";
	regions["ap-northeast-2"	]="Asia Pacific (Seoul)     ";
	regions["ap-southeast-1"	]="Asia Pacific (Singapore) ";
	regions["ap-southeast-2"	]="Asia Pacific (Sydney)    ";
	regions["ap-northeast-1"	]="Asia Pacific (Tokyo)     ";
	regions["ca-central-1"		]="Canada (Central)         ";
	regions["cn-north-1"		]="China (Beijing)          ";
	regions["cn-northwest-1"	]="China (Ningxia)          ";
	regions["eu-central-1"		]="Europe (Frankfurt)       ";
	regions["eu-west-1"			]="Europe (Ireland)         ";
	regions["eu-west-2"			]="Europe (London)          ";
	regions["eu-south-1"		]="Europe (Milan)           ";
	regions["eu-west-3"			]="Europe (Paris)           ";
	regions["eu-north-1"		]="Europe (Stockholm)       ";
	regions["me-south-1"		]="Middle East (Bahrain)    ";
	regions["sa-east-1"			]="South America (São Paulo)";

	return regions;
}

// TODO: Refactor and modularize, opi/s3 specifics, move core to libkinguard
void OpiBackendServer::DoBackupGetSettings(UnixStreamClientSocketPtr &client, json &cmd)
{
	json res;
	string backend,key;
	bool enabled = false;
	string type, bucket, region;
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
		if ( sysconfig.HasKey("backup","region") )
		{
			region = sysconfig.GetKeyAsString("backup","region");
		}
	}
    catch (std::runtime_error& e)
    {
		this->SendErrorMessage( client, cmd, Status::InternalServerError, "Failed to read config parameters");
        logg << Logger::Error << "Failed to read sysconfig" << e.what() << lend;
        return;
    }


    logg << Logger::Error << "Backend: " << backend <<lend;
    res["enabled"] = enabled;
	res["location"] = "op"; //Default if backend == s3op or unknown value

	if (backend == "local://")
    {
        res["location"] = "local";
    }
    else if (backend == "s3://")
    {
        res["location"] = "amazon";
    }

	res["type"] = type;
    res["AWSbucket"] = bucket;
	res["AWSregion"] = region;
	res["AWSregions"] = getAWSRegions();

    IniFile aws(BACKUP_AUTH,":");
    aws.UseSection("s3");
    res["AWSkey"] = aws.ValueOrDefault("backend-login");

    this->SendOK(client, cmd, res);
}


// TODO: Refactor and modularize, opi/s3 specifics, move core to libkinguard
void OpiBackendServer::DoBackupSetSettings(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Set backup settings");
	string type = cmd["type"].get<string>();
	string backend = cmd["location"].get<string>();
	string AWSkey = cmd["AWSkey"].get<string>();
	string AWSseckey = cmd["AWSseckey"].get<string>();
	string AWSbucket = cmd["AWSbucket"].get<string>();
	string AWSregion = cmd["AWSregion"].get<string>();
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
			sysconfig.PutKey("backup","region", AWSregion);

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
		this->SendErrorMessage( client, cmd, Status::InternalServerError, "Failed to set config parameters");
        logg << Logger::Error << "Failed to write sysconfig" << e.what() << lend;
        return;
    }

    this->SendOK(client, cmd);
	if(backend == "remote" || backend == "local" || backend == "amazon")
	{

		static Utils::Thread::Function mountandlink = []()
		{
			Process::Exec( BACKUP_MOUNT_FS);
			Process::Exec( BACKUP_LINK);
		};

		logg << Logger::Debug << "Start detached mount and link of backup" << lend;
		Utils::Thread::Async( &mountandlink );
	}

}

void OpiBackendServer::DoBackupGetQuota(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Get Quota");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	string jsonMessage;
	json parsedFromString;

	tie(ignore,jsonMessage) = Process::Exec( BACKUP_GET_QUOTA );

	try
	{
		parsedFromString = json::parse(jsonMessage);
		this->SendOK(client, cmd, parsedFromString);
	}
	catch(json::parse_error& err)
	{
		logg << Logger::Notice << "Read quota failed: " << err.what() << lend;
		this->SendErrorMessage(client, cmd, Status::InternalServerError, "Read quota failed");
	}
}

void OpiBackendServer::DoBackupGetStatus(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Get Backup Status");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	json res;
	struct stat filestatus = {};
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

void OpiBackendServer::DoBackupStartBackup(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Do backup start backup");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	if( ! BackupManager::InProgress() )
	{
		if( ! BackupManager::StartBackup() )
		{
			this->SendErrorMessage(client, cmd, Status::InternalServerError, "Failed to start backup");
			return;
		}
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoSmtpGetDomains(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Do smtp get domains");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	MailManager& mmgr = MailManager::Instance();

	list<string> domains = mmgr.GetDomains();

	json res;
	res["domains"]= json::array();
	for( const auto& domain: domains )
	{
		res["domains"].push_back(domain);
	}

	this->SendOK(client, cmd, res);
}

void OpiBackendServer::DoSmtpAddDomain(UnixStreamClientSocketPtr &client, json &cmd)
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

	string domain = cmd["domain"].get<string>();

	MailManager& mmgr = MailManager::Instance();
	mmgr.AddDomain( domain );

	if( ! mmgr.Synchronize() )
	{
		logg << Logger::Error << "Failed to synchronize mail manager: " << mmgr.StrError() << lend;
		this->SendErrorMessage( client, cmd, Status::InternalServerError, "Failed to add domain");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoSmtpDeleteDomain(UnixStreamClientSocketPtr &client, json &cmd)
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

	string domain = cmd["domain"].get<string>();

	string token = cmd["token"].get<string>();
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
				this->SendErrorMessage( client, cmd, Status::Forbidden, "Not allowed");
				return;
			}
		}

	}

	mmgr.DeleteDomain( domain );

	if( !mmgr.Synchronize() )
	{
		logg << Logger::Error << "Failed to synchronize mailmanager: " << mmgr.StrError() << lend;
		this->SendErrorMessage( client, cmd, Status::InternalServerError, "Failed to reload mailserver");
	}
	else
	{
		this->SendOK(client, cmd);
	}
}

void OpiBackendServer::DoSmtpGetAddresses(UnixStreamClientSocketPtr &client, json &cmd)
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

	string domain = cmd["domain"].get<string>();

	string token = cmd["token"].get<string>();
	bool admin = this->isAdmin( token );
	string user = this->clients.GetClientByToken( token )->Username();

	MailManager& mmgr = MailManager::Instance();

	list<tuple<string,string>> addresses = mmgr.GetAddresses(domain);

	json res;
	res["addresses"]= json::array();
	for( auto address: addresses )
	{
		// Only return own adresses if not admin
		if( ! admin && user != get<1>(address) )
		{
			continue;
		}

		json adr;
		adr["address"] = get<0>(address);
		adr["username"] = get<1>(address);
		res["addresses"].push_back(adr);
	}

	this->SendOK(client, cmd, res);
}

void OpiBackendServer::DoSmtpAddAddress(UnixStreamClientSocketPtr &client, json &cmd)
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

	string domain = cmd["domain"].get<string>();
	string username = cmd["username"].get<string>();
	string address = cmd["address"].get<string>();

	string token = cmd["token"].get<string>();
	bool admin = this->isAdmin( token );
	string user = this->clients.GetClientByToken( token )->Username();

	if( !admin && ( user != username ) )
	{
		// If not admin you only can add/update mail addressed to yourself
		this->SendErrorMessage( client, cmd, Status::Forbidden, "Not allowed");
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
				this->SendErrorMessage( client, cmd, Status::Forbidden, "Not allowed");
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
		this->SendErrorMessage( client, cmd, Status::InternalServerError, "Failed to reload mailserver");
	}
}

void OpiBackendServer::DoSmtpDeleteAddress(UnixStreamClientSocketPtr &client, json &cmd)
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

	string token = cmd["token"].get<string>();
	bool admin = this->isAdmin( token );
	string user = this->clients.GetClientByToken( token )->Username();

	string domain = cmd["domain"].get<string>();
	string address = cmd["address"].get<string>();

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
				this->SendErrorMessage( client, cmd, Status::Forbidden, "Not allowed");
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
		this->SendErrorMessage( client, cmd, Status::InternalServerError, "Failed to reload mailserver");
	}
}

//TODO: Refactor this out, OPI specifics
void OpiBackendServer::DoSmtpGetSettings(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Do smtp get settings");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

    string saslpasswd = SysConfig().GetKeyAsString("filesystem","storagemount") + "/" + SysConfig().GetKeyAsString("mail","saslpasswd");
    SmtpConfig cfg(saslpasswd);

	json ret;
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

	// Indicate if it is possible to use relay for send/receive
	// This is a bit hackish and requires deeper knowledge
	// on the dns-functionality of OP services.
	// Realy should be refactored out
	ret["relaysend"] = false;
	ret["relayreceive"] = false;

	IdentityManager& mgr = IdentityManager::Instance();
	if( mgr.HasDnsProvider() )
	{
		ret["relaysend"] = true;

		list<string> domains = mgr.DnsAvailableDomains();
		string domain = IdentityManager::Instance().GetDomain();

		if( std::find(domains.begin(), domains.end(), domain) != domains.end() )
		{
			// Device uses a hosted domain that can handle receive email
			ret["relayreceive"] = true;
		}
	}

	this->SendOK(client, cmd,ret);
}

//TODO: Refactor this out, OPI specifics
void OpiBackendServer::DoSmtpSetSettings(UnixStreamClientSocketPtr &client, json &cmd)
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

	string type = cmd["type"].get<string>();
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

		conf.receive = cmd["receive"].get<bool>();
		conf.send = cmd["send"].get<bool>();

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
		conf.user = cmd["username"].get<string>();
		conf.pass = cmd["password"].get<string>();
		conf.host = cmd["hostname"].get<string>();
		conf.port = cmd["port"].get<string>();

		if( conf.host == "" )
		{
			logg << Logger::Debug<< "No relay host specified"<<lend;
			this->SendErrorMessage(client, cmd, Status::BadRequest, "No relay host specified");
			return;
		}

        SmtpConfig smtp( saslpwd );

		smtp.SetCustomMode( conf );
	}
	else
	{
		logg << Logger::Debug << "Missing smtp type"<<lend;
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Missing type argument");
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
		this->SendErrorMessage(client, cmd, Status::InternalServerError, "Operation failed");
	}
}

void OpiBackendServer::DoFetchmailGetAccounts(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Do fetchmail get accounts");

	if( ! this->CheckLoggedIn(client,cmd) || ! this->CheckIsAdminOrUser(client, cmd) )
	{
		return;
	}

	// Username is optional here
	string user;
	if(cmd.contains( "username" ) && cmd["username"].is_string())
	{
		user = cmd["username"].get<string>();
	}

	MailManager& mmgr = MailManager::Instance();

	list<map<string,string>> accounts = mmgr.GetRemoteAccounts(user);

	json ret;
	ret["accounts"] = json::array();

	for( auto& account: accounts )
	{
		json acc;
		acc["email"] = account["email"];
		acc["host"] = account["host"];
		acc["identity"] = account["identity"];
		acc["username"] = account["username"];
		acc["ssl"] = account["ssl"];
		ret["accounts"].push_back(acc);
	}

	this->SendOK(client, cmd,ret);

}

void OpiBackendServer::DoFetchmailGetAccount(UnixStreamClientSocketPtr &client, json &cmd)
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

	string host = cmd["hostname"].get<string>();
	string id = cmd["identity"].get<string>();

	MailManager& mmgr = MailManager::Instance();
	map<string,string> account = mmgr.GetRemoteAccount(host,id);

	json ret;
	ret["email"] = account["email"];
	ret["host"] = account["host"];
	ret["identity"] = account["identity"];
	ret["username"] = account["username"];
	ret["ssl"] = account["ssl"];

	if( this->isAdminOrUser(cmd["token"].get<string>(), account["username"]) )
	{
		this->SendOK(client, cmd,ret);
	}
	else
	{
		this->SendErrorMessage(client, cmd, Status::Unauthorized, "Not allowed");
	}
}

void OpiBackendServer::DoFetchmailAddAccount(UnixStreamClientSocketPtr &client, json &cmd)
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

	string email = cmd["email"].get<string>();
	string host = cmd["hostname"].get<string>();
	string id = cmd["identity"].get<string>();
	string pwd = cmd["password"].get<string>();
	string user = cmd["username"].get<string>();
	string ssl = cmd["ssl"].get<string>();

	if( ! this->isAdminOrUser(cmd["token"].get<string>(), user) )
	{
		this->SendErrorMessage(client, cmd, Status::Unauthorized, "Not allowed");
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
		this->SendErrorMessage(client, cmd, Status::InternalServerError, "Operation failed");
	}
}

void OpiBackendServer::DoFetchmailUpdateAccount(UnixStreamClientSocketPtr &client, json &cmd)
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

	string email = cmd["email"].get<string>();
	string ohost = cmd["orighostname"].get<string>();
	string host = cmd["hostname"].get<string>();
	string oid = cmd["origidentity"].get<string>();
	string id = cmd["identity"].get<string>();
	string pwd = cmd["password"].get<string>();
	string user = cmd["username"].get<string>();
	string token = cmd["token"].get<string>();
	string ssl = cmd["ssl"].get<string>();

	if( ! this->isAdminOrUser( token, user) )
	{
		this->SendErrorMessage(client, cmd, Status::Unauthorized, "Not allowed");
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
		this->SendErrorMessage(client, cmd, Status::InternalServerError, "Operation failed");
	}
}

void OpiBackendServer::DoFetchmailDeleteAccount(UnixStreamClientSocketPtr &client, json &cmd)
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

	string host = cmd["hostname"].get<string>();
	string id = cmd["identity"].get<string>();
	string token = cmd["token"].get<string>();

	MailManager& mmgr = MailManager::Instance();

	map<string,string> account = mmgr.GetRemoteAccount(host, id);

	if( ! this->isAdminOrUser( token, account["username"] ) )
	{
		this->SendErrorMessage(client, cmd, Status::Unauthorized, "Not allowed");
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
		this->SendErrorMessage(client, cmd, Status::InternalServerError, "Operation failed");
	}
}

void OpiBackendServer::DoNetworkGetPortStatus(UnixStreamClientSocketPtr &client, json &cmd) {
	json res;

	ScopedLog l("Get port state");
    SysConfig sysconfig;

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin( client, cmd ) )
	{
		return;
	}
	string port = cmd["port"].get<string>();
    string forwardports;

    try
    {
        forwardports = sysconfig.GetKeyAsString("upnp","forwardports");
    }
    catch (std::runtime_error& e)
    {
		this->SendErrorMessage( client, cmd, Status::InternalServerError, "Failed to read config parameters");
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

void OpiBackendServer::DoNetworkSetPortStatus(UnixStreamClientSocketPtr &client, json &cmd) {
	json res;

	ScopedLog l("Set port state");
    SysConfig sysconfig(true);


	string port = cmd["port"].get<string>();
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
		this->SendErrorMessage( client, cmd, Status::InternalServerError, "Failed to read config parameters");
        logg << Logger::Error << "Failed to read sysconfig" << e.what() << lend;
    }
    list<string> ports = Utils::String::Split(forwardports," ");
    list<string>::iterator i;

    i = find(ports.begin(), ports.end(), port);
    if (i != ports.end()) {
        // found port in config
		if (! cmd["set_open"].get<bool>())
        {
            // remove port
            logg << Logger::Debug << "Remove port" << port << lend;
            ports.erase(i);
        }
    }
    else
    {
        // port is not in config
		if (cmd["set_open"].get<bool>())
        {
            // add port
            logg << Logger::Debug << "Add port" << port << lend;
            ports.push_back(port);
        }
    }

    forwardports = "";
	for (auto it=ports.begin(); it!=ports.end(); ++it)
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
		this->SendErrorMessage( client, cmd, Status::InternalServerError, "Failed to read config parameters");
        logg << Logger::Error << "Failed to read sysconfig" << e.what() << lend;
        return;
    }

    this->SendOK(client, cmd);
}

void OpiBackendServer::DoNetworkGetOpiName(UnixStreamClientSocketPtr &client, json &cmd) {
	json res;

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
		this->SendErrorMessage( client, cmd, Status::InternalServerError, "Failed to read config parameters");
        logg << Logger::Error << "Failed to read sysconfig" << e.what() << lend;
        return;
	}
}

void OpiBackendServer::DoNetworkSetOpiName(UnixStreamClientSocketPtr &client, json &cmd)
{

	ScopedLog l("Set OPI name");
	json response;
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

	string hostname = cmd["hostname"].get<string>();
	string domain = cmd["domain"].get<string>();
	bool   enableDns = cmd["dnsenabled"].get<bool>();
	string certtype = cmd["CertType"].get<string>();
	string certificate = cmd["CustomCertVal"].get<string>();
	string key = cmd["CustomKeyVal"].get<string>();

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
			this->SendErrorMessage( client, cmd, Status::Unauthorized, "FQDN not available");
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

	bool updatename = false;
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
			this->SendErrorMessage( client, cmd, Status::InternalServerError, "Failed to set hostname/domain config parameters");
			logg << Logger::Error << "Failed to set hostname/domain config parameters" << lend;
			return;
		}
	}

	if ( managedDomain ) {
		/* Try update DNS, i.e. reserve name */
		logg << Logger::Info << "Update DNS" << lend;
		if( ! idmgr.AddDnsName(hostname,domain) )
		{
			this->SendErrorMessage( client, cmd, Status::BadRequest, "Failed to register new name/domain");
			return;
		}
	}


	/* Generate certificates */
	/* Certificate backend will not do anything for custom certs, just immediately terminate */
	logg << Logger::Info << "Generate certificates" << lend;
	if ( !idmgr.CreateCertificate(updatename,certtype) )
	{
		this->SendErrorMessage( client, cmd, Status::BadRequest, "Failed to generate certificate(s)");
		return;
	}

	if (certtype == "CUSTOMCERT")
	{

		logg << Logger::Debug << "Validating custom certificate" << lend;

		//TODO: Really should verify that key is used in cert
		bool valid_cert = this->verifyCertificate(certificate,"cert");
		bool valid_key =  this->verifyCertificate(key,"key");

		if ( ! (  valid_cert && valid_key ) )
		{
			logg << Logger::Debug << "Combination of certs not valid" << lend;
			if ( valid_cert )
			{
				this->SendErrorMessage( client, cmd, Status::BadRequest, "Failed to verify Private Key, possibly missing file or uploaded data.");
			}
			else if ( valid_key )
			{
				this->SendErrorMessage( client, cmd, Status::BadRequest, "Failed to verify Certificate");
			}
			else
			{
				this->SendErrorMessage( client, cmd, Status::BadRequest, "Failed to verify certificate and key");
			}
			return;
		}

		// INPUT VALIDATED, WRITE FILES
		logg << Logger::Debug << "Certificates seem to be Valid" << lend;

		string retmsg;
		bool retval = false;
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
			this->SendErrorMessage( client, cmd, Status::InternalServerError, retmsg);
		}


	}

	this->SendOK(client, cmd, response);

	idmgr.CleanUp();

}

void OpiBackendServer::DoNetworkGetDomains(UnixStreamClientSocketPtr &client, json &cmd) {

    ScopedLog l("Get Domains!");
	KGP::IdentityManager& idmgr = KGP::IdentityManager::Instance();

    if( ! this->CheckLoggedIn(client,cmd) )
    {
        return;
    }

	json res;
	json d = json::array();
	list<string> domains = idmgr.DnsAvailableDomains();

	for(const auto& val: domains)
	{
		d.push_back(val);
	}
	res["availabledomains"] = d;

	this->SendOK(client, cmd, res);
}

void OpiBackendServer::DoNetworkGetCert(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Get Webserver Certificates");
	json cfg;

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
		this->SendErrorMessage( client, cmd, Status::BadRequest, "Failed to read certificate type from sysconfig");
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

void OpiBackendServer::DoNetworkCheckCert(UnixStreamClientSocketPtr &client, json &cmd) {
	ScopedLog l("Check Webserver Certificates");

	string type = cmd["type"].get<string>();
	string certificate = cmd["CertVal"].get<string>();
	
	bool res = this->verifyCertificate(certificate,type);
	if ( res )
	{
		this->SendOK( client, cmd);
	}
	else
	{
		this->SendErrorMessage( client, cmd, Status::BadRequest, "Failed to verify certificate/key");
	}

}


void OpiBackendServer::DoNetworkGetSettings(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Get network settings");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin( client, cmd ) )
	{
		return;
	}
	string netif = OPI::SysInfo().NetworkDevice();
	if( netif == "" )
	{
		logg << Logger::Error << "Missing default network interface!" << lend;
		this->SendErrorMessage(client, cmd, Status::InternalServerError, "Unable to find default network interface");
		return;
	}

	NetworkManager& nm = NetworkManager::Instance();

	json cfg = nm.GetConfiguration( netif );
	json ret;
	if( cfg["addressing"].get<string>() == "static" )
	{
		ret["type"] = "static";
		ret["ipnumber"] = cfg["options"]["address"][static_cast<uint>(0)].get<string>();
		ret["netmask"] = cfg["options"]["netmask"][static_cast<uint>(0)].get<string>();
		ret["gateway"] = cfg["options"]["gateway"][static_cast<uint>(0)].get<string>();
		ret["dns"] = cfg["options"]["dns"];
	}
	else if( cfg["addressing"].get<string>() == "dhcp" )
	{
		ret["type"] = "dhcp";
        ret["ipnumber"] = NetUtils::GetAddress( netif );
        ret["netmask"] = NetUtils::GetNetmask( netif );
		ret["gateway"] = NetUtils::GetDefaultRoute();

		//TODO: This should be handled by NetworkManager
		NetUtils::ResolverConfig rc;
		list<string> nss = rc.getNameservers();
		ret["dns"]=JsonHelper::ToJsonArray(nss);
	}
	else
	{
		logg << Logger::Error << "Unknown addressing of interface: '" << netif <<"'" << lend;
		this->SendErrorMessage(client, cmd, Status::InternalServerError, "Unknown addressing of network interface");
		return;
	}

	this->SendOK( client, cmd, ret);
}

void OpiBackendServer::DoNetworkSetSettings(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Set network settings");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin( client, cmd ) )
	{
		return;
	}

	// Manually verify
	if( !cmd.contains("type") && !cmd["type"].is_string() )
	{
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Missing argument");
		return;
	}

	string type = cmd["type"].get<string>();
	if( type != "dhcp" && type != "static")
	{
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Missing argument");
		return;
	}

    string netif = sysinfo.NetworkDevice();
	NetworkManager& nm = NetworkManager::Instance();

	// We currently have no choice but to send the reply now
	// and assume everything is OK.
	//
	// If not we will be disconnected from the client that then
	// will report an error, even though everything might be ok.
	//
	// We should probably do more tests before comitting this operation
	// since it potentially will lock users out of their system :|
	//
	this->SendOK(client, cmd);

	bool res = false;
	if( type == "dhcp" )
	{
		res = nm.DynamicConfiguration( netif );
	}
	else
	{
		if( !cmd.contains("ipnumber") && !cmd["ipnumber"].is_string() )
		{
			this->SendErrorMessage(client, cmd, Status::BadRequest, "Missing argument");
			return;
		}
		if( !cmd.contains("netmask") && !cmd["netmask"].is_string() )
		{
			this->SendErrorMessage(client, cmd, Status::BadRequest, "Missing argument");
			return;
		}
		if( !cmd.contains("gateway") && !cmd["gateway"].is_string() )
		{
			this->SendErrorMessage(client, cmd, Status::BadRequest, "Missing argument");
			return;
		}
		if( !cmd.contains("dns") && !cmd["dns"].is_array() )
		{
			this->SendErrorMessage(client, cmd, Status::BadRequest, "Missing argument");
			return;
		}

		res = nm.StaticConfiguration( netif,
								cmd["ipnumber"].get<string>(),
								cmd["netmask"].get<string>(),
								cmd["gateway"].get<string>(),
								JsonHelper::FromJsonArray(cmd["dns"])
								);
	}

	if( ! res )
	{
		logg << Logger::Notice << "Failed to set network settings" << lend;
	}

}

void OpiBackendServer::DoShellGetSettings(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Do shell get settings");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	SystemManager& sm = SystemManager::Instance();

	json ret;
	ret["available"] = sm.ShellAccessAvailable();
	ret["enabled"] = sm.ShellAccessEnabled();

	this->SendOK(client, cmd, ret);
}

void OpiBackendServer::DoShellEnable(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Do shell enabled");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	bool ret = SystemManager::Instance().ShellAccessEnable();

	if( ! ret )
	{
		this->SendErrorMessage( client, cmd, Status::InternalServerError, "Failed to enable shell");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoShellDisable(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Do shell disabled");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	bool ret = SystemManager::Instance().ShellAccessDisable();

	if( !ret )
	{
		this->SendErrorMessage( client, cmd, Status::InternalServerError, "Failed to disable shell");
		return;
	}

	this->SendOK(client, cmd);
}


void OpiBackendServer::DoSystemGetMessages(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Do System Get Messages");
	if( ! this->CheckLoggedIn(client,cmd)  )
	{
		return;
	}

	json messages = json::array();
	// return array of json encoded messages

	// for each file in /var/spool/notify
	if( File::DirExists(NOTIFY_DIR) ) {
		list<string> files = File::Glob(NOTIFY_DIR "*");
		for( const string& file: files)
		{
            if( File::FileExists(file) )
            {
				messages.push_back(File::GetContentAsString(file, true));
            }
		}
	}
	else
	{
		logg << Logger::Debug << "Spool dir does not exist"<<lend;
		this->SendErrorMessage(client, cmd, Status::MethodNotAllowed, "Method not Allowed");
		return;
	}
	json ret;
	ret["messages"] = messages;
	this->SendOK(client, cmd, ret);
}

void OpiBackendServer::DoSystemAckMessage(UnixStreamClientSocketPtr &client, json &cmd)
{
    ScopedLog l("Do System Ack Message");
	json ret;
	
	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		this->SendErrorMessage(client, cmd, Status::Forbidden, "Forbidden");
		return;
	}
	// Manually verify
	if( !cmd.contains("id") && !cmd["id"].is_string() )
	{
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Missing argument");
		return;
	}
	logg << Logger::Debug << "Ack message with id: " << cmd["id"].get<string>() <<lend;
	Notify::ExistingMessage msg(cmd["id"].get<string>());
    msg.Ack();

	ret["deleted"] = cmd["id"];
	this->SendOK(client, cmd, ret);
}

void OpiBackendServer::DoSystemGetStatus(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Do System Get Status");
	json ret;
	string Message, uptimescript, tempscript;
	int retval = 0;

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
		Message = File::GetContentAsString( tempscript );
		ret["temperature"]=Message;
	} else {
		ret["temperature"]=0;
	}
	this->SendOK(client, cmd, ret);
}

#include <libopi/DiskHelper.h>

void OpiBackendServer::DoSystemGetStorage(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Do System Get Storage");
	json ret;

	try
	{
		json st = OPI::DiskHelper::StatFs(SysConfig().GetKeyAsString("filesystem","storagemount"));

		uint64_t fragsize = st["fragment_size"];
		uint64_t sizefree = (fragsize * st["blocks_free"].get<uint64_t>()) / 1024;
		uint64_t sizetotal = (fragsize * st["blocks_total"].get<uint64_t>()) / 1024;
		ret["storage"]["total"]= sizetotal;
		ret["storage"]["available"]= sizefree;
		ret["storage"]["used"]= sizetotal-sizefree;

		this->SendOK(client, cmd, ret);
	}
	catch (std::runtime_error& err)
	{
		this->SendErrorMessage(client, cmd, Status::InternalServerError, "Internal Error");
	}
}

//TODO: Refactor
void OpiBackendServer::DoSystemGetUnitid(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Do System Get Unitid");
	json ret;
	string scope;
	string key;

	if( !this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	ret["unitid"] = this->getSysconfigString("hostinfo","unitid");
	ret["unitidbak"] = this->getSysconfigString("hostinfo","unitidbak");

	string provider = this->getSysconfigString( "dns","provider");
	if( provider == "none")
	{
		// Ugly workaround to make Module providers work if on clean KGP system
		provider = "OpenProducts";
	}

	ret["provider"] = provider;
	ret["enabled"] = this->getSysconfigBool( "dns","enabled");

/* Todo, generalize provider concept and use below instead of above.
 * There is a started but unused API getModulesProviders in webfrontend
	SystemManager& sysmgr = SystemManager::Instance();

	ret["providers"] = JsonHelper::ToJsonArray(sysmgr.Providers());
*/
	this->SendOK(client, cmd, ret);

}

//TODO: Refactor
void OpiBackendServer::DoSystemSetUnitid(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Do System Set Unitid");
	json ret;

	string passphrase;
	bool passphrasefound = false;

	if( !this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	// Manually verify passed parameters
	if( !cmd.contains("unitid") && !cmd["unitid"].is_string() )
	{
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Missing argument");
		return;
	}
	if( !cmd.contains("mpwd") && !cmd["mpwd"].is_string() )
	{
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Missing argument");
		return;
	}
	if( !cmd.contains("enabled") && !cmd["enabled"].is_boolean() )
	{
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Missing argument");
		return;
	}

	string mpwd = cmd["mpwd"].get<string>();
	string unitid = cmd["unitid"].get<string>();
	bool enabled = cmd["enabled"].get<bool>();

	// Read fs-passphrase from backup config.
	string authfile = this->getSysconfigString("backup","authfile");
	list<string> authdata = File::GetContent(authfile);
	if ( authfile == "" ){
		logg << Logger::Info<< "No backup authfile found, unable to verify MPWD: " <<lend;
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Unable to verify Master Password");
		return;
	}

	// Find the passphrase
	for( const auto& authline: authdata )
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
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Unable to verify Master Password");
		return;
	}

	// Input data confirmed, move on to verify password.

	string calc_passphrase;
	CryptoHelper::SecString spass(mpwd.c_str(), mpwd.size() );
	CryptoHelper::SecVector<byte> key = CryptoHelper::PBKDF2( spass, 20);
	vector<byte> ukey(key.begin(), key.end());

	calc_passphrase = CryptoHelper::Base64Encode( ukey );
	// Don't write sensitive data to logfile
	//logg << Logger::Debug<< "Calculated passphrase: " << calc_passphrase <<lend;

	if ( passphrase != calc_passphrase)
	{
		logg << Logger::Info<< "Incorrect Master Password" <<lend;
		this->SendErrorMessage(client, cmd, Status::Forbidden, "Incorrect Master Password");
		return;
	}

	SysConfig sysconfig(true);
	KGP::IdentityManager& idmgr = KGP::IdentityManager::Instance();

	if ( enabled )
	{
		// Enable in config
		idmgr.EnableDnsProvider("OpenProducts");

		// Try to login and set system keys
		bool status = false;
		string token;

		tie(status,token) = idmgr.UploadKeys(unitid,mpwd);

		if (! status) {
			logg << Logger::Error<< "Failed to upload keys" <<lend;
			this->SendErrorMessage(client, cmd, Status::InternalServerError, "Failed to upload keys");
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
			this->SendErrorMessage(client, cmd, Status::InternalServerError, "Failed to set keys in sysconfig");
			return;
		}

		// Get a OP signed certificate
		logg << Logger::Debug << "Request OP signed certificate" << lend;
		idmgr.CreateCertificate(true, "LETSENCRYPT");
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
				backuphelper = std::make_shared<BackupHelper>( "" );
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
			this->SendErrorMessage(client, cmd, Status::InternalServerError, "Failed to disable keys in sysconfig");
			return;
		}
	}
	this->SendOK(client, cmd, ret);

}

// Start a detached update
void OpiBackendServer::DoSystemStartUpdate(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("DoSystemStartUpdate");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	SystemManager::Instance().StartUpdate();

	this->SendOK(client, cmd);
}

// Is there a system upgrade available
void OpiBackendServer::DoSystemGetUpgrade(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("DoSystemGetUpgrade");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	bool upgradeavailable = false;
	string description;

	tie(upgradeavailable, description) = SystemManager::Instance().UpgradeAvailable();

	json res;

	res["available"] = upgradeavailable;
	res["description"] = "";
	if( upgradeavailable )
	{
		res["description"] = description;
	}

	this->SendOK(client, cmd, res);
}

// Initialize system upgrade
void OpiBackendServer::DoSystemStartUpgrade(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("DoSystemStartUpgrade");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	// Don't allow usage during upgrade, system must restart when upgrade completes
	this->LockBackend();

	SystemManager::Instance().StartUpgrade();

	this->SendOK(client, cmd);
}


void OpiBackendServer::DoSystemGetType(UnixStreamClientSocketPtr &client, json &cmd)
{
    ScopedLog l("Do System Get Type");
	json ret;

	size_t type=OPI::sysinfo.Type();
	string typeText=OPI::sysinfo.SysTypeText[type];

	ret["type"]=type;
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

	if( File::FileExists( KINGUARD_VERSIONFILE ) )
	{
		string version =  File::GetContentAsString(KINGUARD_VERSIONFILE);
		if( version.length() > 0 )
		{
			ret["osversion"] = version;
		}
		else
		{
			ret["osversion"] = "N/A";
		}
	}
	else
	{
		ret["osversion"] = "N/A";
	}

    this->SendOK(client, cmd, ret);

}

void OpiBackendServer::DoSystemGetPackages(UnixStreamClientSocketPtr &client, json &cmd)
{
	ScopedLog l("Do System Get Packages");
	json ret, tmp;

	if( ! File::FileExists(PACKAGE_STATUSFILE) )
	{
		// Really should not happen
		logg << Logger::Error << "Missing package status file"  << lend;
		this->SendErrorMessage(client, cmd, Status::MethodNotAllowed, "Method not Allowed");
		return;
	}

	string pkgstatus = File::GetContentAsString( PACKAGE_STATUSFILE );

	if( pkgstatus.length() == 0 )
	{
		logg << Logger::Error << "Package status file truncated"  << lend;
		this->SendErrorMessage(client, cmd, Status::InternalServerError, "Internal Error (Truncated status file)");
		return;
	}

	try
	{
		tmp = json::parse(pkgstatus);
	}
	catch(json::parse_error& err)
	{
		logg << Logger::Error << "Failed to parse status file (" << err.what() << ")"  << lend;
		this->SendErrorMessage(client, cmd, Status::InternalServerError, "Internal Error (Failed to parse status file)");
		return;
	}

	if( !tmp.contains("packages") || ! tmp["packages"].is_object() )
	{
		logg << Logger::Error << "Malformed statusfile" << lend;
		this->SendErrorMessage(client, cmd, Status::InternalServerError, "Internal Error (Malformed status file)");
		return;
	}


	for( const auto& member: tmp["packages"].items() )
	{
		json pkg = member.value();

		if(pkg["status"].get<string>() == "un" )
		{
			// Skip all uninstalled packages
			continue;
		}
		ret["packages"][member.key()] = pkg["version"].get<string>() + string(" (")+pkg["status"].get<string>()+string(")");
	}

	this->SendOK(client, cmd, ret);
}

string OpiBackendServer::getSysconfigString(const string& scope, const string& key)
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

bool OpiBackendServer::getSysconfigBool(const string& scope, const string& key)
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

void OpiBackendServer::LockBackend()
{
	ScopedLog l("Lock backend");
	this->islocked = true;
}

void OpiBackendServer::UnlockBackend()
{
	ScopedLog l("UnLock backend");
	this->islocked = false;
}

bool OpiBackendServer::CheckLoggedIn(UnixStreamClientSocketPtr &client, json &req)
{
	if( !req.contains("token") && !req["token"].is_string() )
	{
		this->SendErrorMessage(client, req, Status::BadRequest, "Missing argument");
		return false;
	}

	string token = req["token"].get<string>();

	if( ! this->clients.IsTokenLoggedin( token ) )
	{
		this->SendErrorMessage(client, req, Status::Unauthorized, "Unauthorized");
		return false;
	}

	return true;
}

// Assumes that check for logged in has been performed
bool OpiBackendServer::CheckIsAdmin(UnixStreamClientSocketPtr &client, json &req)
{
	string token = req["token"].get<string>();

	if( ! this->isAdmin( token ) )
	{
		this->SendErrorMessage(client, req, Status::Unauthorized, "Unauthorized");
		return false;
	}
	return true;
}

// Assumes that check for logged in has been performed
bool OpiBackendServer::CheckIsAdminOrUser(UnixStreamClientSocketPtr &client, json &req)
{
	string token = req["token"].get<string>();

	// If no username, check for admin only
	if( ! req.contains("username")  || req["username"].is_null() )
	{
		return this->CheckIsAdmin(client,req);
	}

	string user = req["username"].get<string>();

	if( ! this->isAdminOrUser( token, user ) )
	{
		this->SendErrorMessage(client, req, Status::Unauthorized, "Unauthorized");
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

	int resultcode = 0;
	json ret;

	tie(resultcode, ret) = s.Login();

	return resultcode == Status::Ok ? ret["token"].get<string>() : "";
}

void OpiBackendServer::ReapClients()
{
	// Only reap once a minute
	constexpr int MINUTE = 60;
	if( this->lastreap + MINUTE > time(nullptr) )
	{
		return;
	}

	logg << Logger::Debug << "Reap clients"<<lend;

	this->clients.Reap();

	this->lastreap = time(nullptr);
}

json OpiBackendServer::UserToJson(const UserPtr& user)
{

	json ret;
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

void OpiBackendServer::ProcessOneCommand(UnixStreamClientSocketPtr &client, json &cmd)
{
	string action = cmd["cmd"].get<string>();
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

void OpiBackendServer::SendReply(UnixStreamClientSocketPtr &client, json &val)
{
	string r = val.dump() + "\n";
    //logg << Logger::Debug << "JSON REPLY "<< r <<lend;
	client->Write(r.c_str(), r.length());
}

void OpiBackendServer::SendErrorMessage(UnixStreamClientSocketPtr &client, const json &cmd, int errcode, const string &msg)
{
	(void) cmd;
	json ret;
	ret["status"]["value"]=errcode;
	ret["status"]["desc"]=msg;
	
	this->SendReply(client, ret);
}

void OpiBackendServer::SendOK(UnixStreamClientSocketPtr &client, const json &cmd, const json &val)
{
	(void) cmd;
	json ret;
	ret["status"]["value"]=0;
	ret["status"]["desc"]="OK";

	// Append any possible extra values to answer
	if( ! val.is_null() )
	{
		for( const auto &x: val.items() )
		{
			ret[x.key()]=x.value();
		}
	}

	this->SendReply(client, ret);
}

void OpiBackendServer::typecheckcallback(const string& msg, void* data)
{
	(void) data;
	logg << Logger::Debug << "Typecheck failed: " << msg <<lend;
}

bool OpiBackendServer::CheckArguments(UnixStreamClientSocketPtr& client, int what,const json& cmd)
{
	if( ! this->typechecker.Verify(what, cmd) )
	{
		this->SendErrorMessage(client, cmd, Status::BadRequest, "Missing argument");
		return false;
	}
	return true;
}

bool OpiBackendServer::verifyCertificate(string cert, const string& type)
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
			File::Write( tmpFile, cert, File::UserRW);
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
				File::Write( tmpSplitCert, token, File::UserRW);
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
string OpiBackendServer::getTmpFile(const string& path, const string& suffix)
{
	string filename;
	filename = path+String::UUID()+suffix;
	while( File::FileExists( filename ))
	{
		filename = path;
		filename += String::UUID();
		filename += suffix;
	}
	return filename;
}
