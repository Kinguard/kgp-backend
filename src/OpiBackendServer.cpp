#include "OpiBackendServer.h"
#include "Config.h"

#include <libutils/Logger.h>
#include <libutils/String.h>
#include <libutils/FileUtils.h>
#include <libutils/ConfigFile.h>
#include <libutils/UserGroups.h>
#include <libutils/Process.h>
#include <libutils/Regex.h>

#include <libopi/DnsServer.h>
#include <libopi/AuthServer.h>
#include <libopi/CryptoHelper.h>
#include <libopi/ServiceHelper.h>
#include <libopi/NetworkConfig.h>
#include <libopi/SmtpConfig.h>
#include <libopi/FetchmailConfig.h>
#include <libopi/MailConfig.h>
#include <libopi/SysInfo.h>
#include <libopi/ExtCert.h>
#include <libopi/SysConfig.h>
#include <algorithm>
#include <unistd.h>
#include <uuid/uuid.h>
#include <regex>

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

enum ArgCheckType{
	STRING,
	INT,
	BOOL
};

typedef struct ArgCheckStruct
{
	int				check;
	const char*		member;
	ArgCheckType	type;
}ArgCheckLine;

static vector<ArgCheckLine> argchecks(
	{
			{ CHK_USR, "username",		ArgCheckType::STRING },
			{ CHK_PWD, "password",		ArgCheckType::STRING },
			{ CHK_NPW, "newpassword",	ArgCheckType::STRING },
			{ CHK_DSP, "displayname",	ArgCheckType::STRING },
			{ CHK_DEM, "defaultemail",	ArgCheckType::STRING },
			{ CHK_DMN, "domain",		ArgCheckType::STRING },
			{ CHK_GRP, "group",			ArgCheckType::STRING },
			{ CHK_ADR, "address",		ArgCheckType::STRING },
			{ CHK_HST, "hostname",		ArgCheckType::STRING },
			{ CHK_IDN, "identity",		ArgCheckType::STRING },
			{ CHK_PRT, "port",			ArgCheckType::STRING },
			{ CHK_EML, "email",			ArgCheckType::STRING },
			{ CHK_SSL, "ssl",			ArgCheckType::STRING },
			{ CHK_TYP, "type",			ArgCheckType::STRING },
			{ CHK_SND, "send",			ArgCheckType::BOOL },
			{ CHK_RCV, "receive",		ArgCheckType::BOOL },
	});

// Forwards
static bool CheckArgument(const Json::Value& cmd, const string& member, ArgCheckType type);

// Convenience class for debug/trace
class ScopedLog: public NoCopy
{
private:
	string name;
public:
	ScopedLog(const string& name): name(name)
	{
		logg << Logger::Debug << name << " start"<<lend;
	}

	virtual ~ScopedLog()
	{
		logg << Logger::Debug << name << " stop"<<lend;
	}

};

// Utility function forwards
static bool update_postfix();
static void postfix_fixpaths();
static bool addusertomailadmin( const string& user );
static bool removeuserfrommailadmin( const string& user );


OpiBackendServer::OpiBackendServer(const string &socketpath):
	Utils::Net::NetServer(UnixStreamServerSocketPtr( new UnixStreamServerSocket(socketpath)), 0)
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
	this->actions["networkdisabledns"]=&OpiBackendServer::DoNetworkDisableDNS;
	this->actions["networkgetcert"]=&OpiBackendServer::DoNetworkGetCert;
	this->actions["networksetcert"]=&OpiBackendServer::DoNetworkSetCert;
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


	// Setup mail paths etc
	postfix_fixpaths();

	// Initialize time for last reap
	this->lastreap = time(NULL);
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
    SysConfig sysconfig;

	if( ! secop->CreateUser( user, pass,display ) )
	{
		this->SendErrorMessage(client, cmd, 400, "Failed");
		return;
	}

	string opiname;
	string domain;
	try
	{
		opiname = sysconfig.GetKeyAsString("hostinfo","hostname");
		domain = sysconfig.GetKeyAsString("hostinfo","domain");
	}
	catch (std::runtime_error& e)
	{
		this->SendErrorMessage( client, cmd, 500, "Failed to read config parameters");
		logg << Logger::Error << "Failed to set sysconfig" << e.what() << lend;
		return;
	}

	// set default email in secop
	string defaultemail = user+"@"+opiname+"."+domain;
	logg << Logger::Debug << "Setting defult email in secop to: " << defaultemail << lend;
	if( ! secop->AddAttribute(user, "defaultemail", defaultemail) )
	{
		this->SendErrorMessage(client, cmd, 400, "Operation failed");
		return;
	}

	// Add user to local mail
    string localmail = sysconfig.GetKeyAsString("filesystem","storagemount") + "/" + sysconfig.GetKeyAsString("mail","localmail");
    MailMapFile mmf( localmail );
	mmf.ReadConfig();
	mmf.SetAddress("localdomain", user, user);
	mmf.WriteConfig();

	// Add user to opi-domain
	MailConfig mc;
	mc.ReadConfig();
    mc.SetAddress(opiname+"."+domain,user,user);
	mc.WriteConfig();

	update_postfix();

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

	SecopPtr secop = wc->Secop();

	vector<string> groups = secop->GetUserGroups( user );
	bool wasadmin = find( groups.begin(), groups.end(), "admin") != groups.end();

    if( ! secop->RemoveUser( user ) )
	{
		this->SendErrorMessage(client, cmd, 400, "Failed");
		return;
	}

    if( wasadmin )
	{
		removeuserfrommailadmin( user );

		// Possibly remove user from OC internal user-db
		if( File::FileExists( OC_CLEAN_SCRIPT ) )
		{
			Process::Exec( OC_CLEAN_SCRIPT );
		}
		else
		{
			logg << Logger::Error << "Missing OC clean script ["<< OC_CLEAN_SCRIPT << "]" << lend;
		}
	}

    // Remove user from local mail
    string localmail = sysconfig.GetKeyAsString("filesystem","storagemount") + "/" + sysconfig.GetKeyAsString("mail","localmail");
    MailMapFile mmf( localmail );
	mmf.ReadConfig();
	mmf.DeleteAddress("localdomain", user);
	mmf.WriteConfig();

    // Remove user from opi-domain
    string opiname;
    string domain;
    try {
        opiname = sysconfig.GetKeyAsString("hostinfo","hostname");
        domain = sysconfig.GetKeyAsString("hostinfo","domain");
    }
    catch (std::runtime_error& e)
    {
        logg << Logger::Error << "Failed to read sysconfig" << e.what() << lend;
        this->SendErrorMessage(client, cmd, 400, "Failed");
        return;
    }

    MailConfig mc;
    mc.ReadConfig();
    try {
        mc.DeleteAddress(opiname+"."+domain,user);
    }
    catch (std::runtime_error& e)
    {
        logg << Logger::Error << "Failed to delete user" << e.what() << lend;
        this->SendErrorMessage(client, cmd, 400, "Failed");
        return;
    }
    mc.WriteConfig();
    update_postfix();

    // delete the users files and mail
    logg << Logger::Debug << "Deleting files for user: " << user << lend;
    try {
        string storage = sysconfig.GetKeyAsString("filesystem","storagemount");
        string dir = storage + "/mail/data/" + user;
        if( File::DirExists(dir.c_str()))
        {
            Process::Exec("rm -rf "+ dir);
        }
        dir = storage + "/nextcloud/data/" + user;
        if( File::DirExists(dir.c_str()))
        {
            Process::Exec("rm -rf "+ dir);
        }
    }
    catch (std::runtime_error& e)
    {
        logg << Logger::Error << "Failed to delete user files" << e.what() << lend;
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

	vector<string> users  = secop->GetUsers();

	if( std::find(users.begin(), users.end(), user) == users.end() )
	{
		this->SendErrorMessage(client, cmd, 404, "User not found");
		return;
	}

	Json::Value ret = this->GetUser(token, user);

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

	string user =		cmd["username"].asString();

	// TODO: Validate that user exists!

	// Get fetchmail addresses
	FetchmailConfig fc( FETCHMAILRC );
	list<map<string,string>> accounts = fc.GetAccounts(user);

	Json::Value ids(Json::arrayValue);
	for( auto& account: accounts )
	{
		ids.append(account["email"]);
	}

	// Get all smtp addresses
	MailConfig mc;

	list<string> domains = mc.GetDomains();
	for( const string& domain: domains)
	{
		list<tuple<string, string> > addresses = mc.GetAddresses( domain );
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

	SecopPtr secop = SecopPtr( new Secop() );

	secop->SockAuth();

	vector<string> users  = secop->GetUsers();

	bool exists = std::find(users.begin(), users.end(), user) != users.end();

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

	if( ! secop->AddAttribute(user, "displayname", disp) )
	{
		this->SendErrorMessage(client, cmd, 400, "Operation failed");
		return;
	}
	if( ! secop->AddAttribute(user, "defaultemail", defaultemail) )
	{
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

	vector<string> usernames = secop->GetUsers();
	Json::Value ret;
	ret["users"]=Json::arrayValue;
	for(auto user: usernames)
	{
		ret["users"].append( this->GetUser(token, user) );
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

	vector<string> groups = secop->GetUserGroups( user );

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

	list<map<string,string>>  ids = secop->GetIdentifiers( user, "opiuser");
	if(ids.size() == 0 )
	{
		this->SendErrorMessage(client, cmd, 500, "Database error");
		return;
	}

	map<string,string> id = ids.front();
	if( id.find("password") == id.end() )
	{
		this->SendErrorMessage(client, cmd, 500, "Database error");
		return;
	}

	/*
	 *If user tries to change own password we want to verify that
	 * they know old password.
	 * Else we rely on secop catching unauthorized updates
	 */

	if( user == wc->Username() )
	{
		if( passw != id["password"] )
		{
			this->SendErrorMessage(client, cmd, 400, "Bad request");
			return;

		}
	}

	if( ! secop->UpdateUserPassword(user, newps) )
	{
		this->SendErrorMessage(client, cmd, 400, "Operation failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoGetGroups(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do get groups");

	SecopPtr secop = SecopPtr( new Secop() );
	secop->SockAuth();

	vector<string> groups = secop->GetGroups();

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

	if( !secop->AddGroup(group) )
	{
		this->SendErrorMessage(client, cmd, 400, "Operation failed");
		return;
	}

	this->SendOK(client, cmd);
}


static bool addusertomailadmin( const string& user )
{
	try
	{
        string valias = SysConfig().GetKeyAsString("filesystem","storagemount") + "/" + SysConfig().GetKeyAsString("mail","virtualalias");

        MailAliasFile mf( valias );

		mf.AddUser("/^postmaster@/",user+"@localdomain");
		mf.AddUser("/^root@/",user+"@localdomain");

		mf.WriteConfig();

		ServiceHelper::Reload("postfix");
	}
	catch( runtime_error& err )
	{
		logg << Logger::Error << "Failed to add user to adminmail" << err.what()<<lend;
	}
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

	if( !secop->AddGroupMember(group, member) )
	{
		this->SendErrorMessage(client, cmd, 400, "Operation failed");
		return;
	}

	if( group == "admin" )
	{
		addusertomailadmin(member);
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

	vector<string> members = secop->GetGroupMembers( group );

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

	if( !secop->RemoveGroup(group) )
	{
		this->SendErrorMessage(client, cmd, 400, "Operation failed");
		return;
	}

	this->SendOK(client, cmd);
}

static bool removeuserfrommailadmin( const string& user )
{
	try
	{
        string valias = SysConfig().GetKeyAsString("filesystem","storagemount") + "/" + SysConfig().GetKeyAsString("mail","virtualalias");

        MailAliasFile mf( valias );

		mf.RemoveUser("/^postmaster@/",user+"@localdomain");
		mf.RemoveUser("/^root@/",user+"@localdomain");

		mf.WriteConfig();

		ServiceHelper::Reload("postfix");
	}
	catch( runtime_error& err )
	{
		logg << Logger::Error << "Failed to remove user from adminmail" << err.what()<<lend;
	}
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

	if( !secop->RemoveGroupMember(group, member) )
	{
		this->SendErrorMessage(client, cmd, 400, "Operation failed");
		return;
	}

	if( group == "admin" )
	{
		removeuserfrommailadmin( member );
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
        res["location"] = "remote";  // Show as default target in UI
    }
    res["type"] = type;
    res["AWSbucket"] = bucket;


    IniFile aws(BACKUP_AUTH,":");
    aws.UseSection("s3");
    res["AWSkey"] = aws.ValueOrDefault("backend-login");

    this->SendOK(client, cmd, res);
}

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
            if(sysconfig.GetKeyAsString("backup","bucket") != AWSbucket)
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

	this->SendOK(client, cmd, res);

}

void OpiBackendServer::DoSmtpGetDomains(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do smtp get domains");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	MailConfig mc;

	list<string> domains = mc.GetDomains();

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

	MailConfig mc;

	mc.AddDomain(domain);
	mc.WriteConfig();

	this->SendOK(client, cmd);
}


// Todo: rewrite (Implement service/process in utils?)
static bool update_postfix()
{
	int ret;
    SysConfig sysconfig;

    string aliases = sysconfig.GetKeyAsString("filesystem","storagemount") + "/" + sysconfig.GetKeyAsString("mail","vmailbox");
    tie(ret, std::ignore) = Utils::Process::Exec( "/usr/sbin/postmap " + aliases );

	if( (ret < 0) || WEXITSTATUS(ret) != 0 )
	{
		return false;
	}
    string saslpwd = sysconfig.GetKeyAsString("filesystem","storagemount") + "/" + sysconfig.GetKeyAsString("mail","saslpasswd");
    tie(ret, std::ignore) = Utils::Process::Exec( "/usr/sbin/postmap " + saslpwd );

	if( (ret < 0) || WEXITSTATUS(ret) != 0 )
	{
		return false;
	}

    string localmail = sysconfig.GetKeyAsString("filesystem","storagemount") + "/" + sysconfig.GetKeyAsString("mail","localmail");
    tie(ret, std::ignore) = Utils::Process::Exec( "/usr/sbin/postmap " + localmail );

	if( (ret < 0) || WEXITSTATUS(ret) != 0 )
	{
		return false;
	}

	ret = system( "/usr/sbin/service postfix reload &> /dev/null" );

	if( (ret < 0) || WEXITSTATUS(ret) != 0 )
	{
		return false;
	}

	return true;
}

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

    if( chown( aliases.c_str(), User::UserToUID("postfix"), Group::GroupToGID("postfix") ) != 0)
	{
		logg << Logger::Error << "Failed to change owner on aliases file"<<lend;
	}

    if( chown( saslpwd.c_str(), User::UserToUID("postfix"), Group::GroupToGID("postfix") ) != 0)
	{
		logg << Logger::Error << "Failed to change owner on saslpasswd file"<<lend;
	}

    if( chown( domains.c_str(), User::UserToUID("postfix"), Group::GroupToGID("postfix") ) != 0)
	{
		logg << Logger::Error << "Failed to change owner on domain file"<<lend;
	}

    if( chown( File::GetPath(domains).c_str(), User::UserToUID("postfix"), Group::GroupToGID("postfix") ) != 0)
	{
		logg << Logger::Error << "Failed to change owner on config directory"<<lend;
	}

    if( chmod( File::GetPath(domains).c_str(), 0700 ) != 0)
	{
		logg << Logger::Error << "Failed to change mode on config directory"<<lend;
	}
}

static bool restart_fetchmail()
{
	int ret;


	ret = system( "/usr/sbin/service fetchmail restart &> /dev/null" );

	if( (ret < 0) || WEXITSTATUS(ret) != 0 )
	{
		return false;
	}

	return true;
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

	MailConfig mc;

	// We only allow delete of domain if you are admin OR
	// is the only user of this domain
	if( ! admin )
	{
		list<tuple<string, string> > addresses = mc.GetAddresses(domain);

		for( auto address: addresses)
		{
			if( get<1>(address) != user )
			{
				this->SendErrorMessage( client, cmd, 403, "Not allowed");
				return;
			}
		}

	}

	mc.DeleteDomain(domain);
	mc.WriteConfig();

	if( update_postfix() )
	{
		this->SendOK(client, cmd);
	}
	else
	{
		this->SendErrorMessage( client, cmd, 500, "Failed to reload mailserver");
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

	MailConfig mc;

	list<tuple<string,string>> addresses = mc.GetAddresses(domain);

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

	MailConfig mc;

	if( ! admin )
	{
		// Non admin users can only add not used addresses
		// or update their own addresses
		if( mc.hasAddress( domain, address) )
		{
			string adr, localuser;
			tie(adr, localuser) = mc.GetAddress(domain,address);

			if( user != localuser )
			{
				this->SendErrorMessage( client, cmd, 403, "Not allowed");
				return;

			}
		}
	}

	mc.SetAddress(domain, address, username);
	mc.WriteConfig();

	if( update_postfix() )
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

	MailConfig mc;

	if( ! admin )
	{
		// None admins can only delete their own addresses
		if( mc.hasAddress(domain, address) )
		{
			string adr, localuser;
			tie(adr, localuser) = mc.GetAddress(domain,address);

			if( user != localuser )
			{
				this->SendErrorMessage( client, cmd, 403, "Not allowed");
				return;

			}
		}
	}

	mc.DeleteAddress( domain, address );
	mc.WriteConfig();

	if( update_postfix() )
	{
		this->SendOK(client, cmd);
	}
	else
	{
		this->SendErrorMessage( client, cmd, 500, "Failed to reload mailserver");
	}
}

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
	default:
		throw runtime_error("No valid config");
		break;
	}

	this->SendOK(client, cmd,ret);
}

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

	update_postfix();

	this->SendOK(client, cmd);
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

	FetchmailConfig fc( FETCHMAILRC );
	list<map<string,string>> accounts = fc.GetAccounts(user);

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

	FetchmailConfig fc( FETCHMAILRC );
	map<string,string> account = fc.GetAccount(host,id);

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

	FetchmailConfig fc( FETCHMAILRC );

	fc.AddAccount(email, host, id, pwd, user, ssl == "true" );
	fc.WriteConfig();
	restart_fetchmail();

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoFetchmailUpdateAccount(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do fetchmail update account");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_HST | CHK_IDN | CHK_PWD | CHK_USR | CHK_EML | CHK_SSL, cmd) )
	{
		return;
	}

	// Non common arguments check
	if( ! CheckArgument( cmd, "origidentity",ArgCheckType::STRING) )
	{
		this->SendErrorMessage(client, cmd, 400, "Missing argument");
		return;
	}

	if( ! CheckArgument( cmd, "orighostname",ArgCheckType::STRING) )
	{
		this->SendErrorMessage(client, cmd, 400, "Missing argument");
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

	FetchmailConfig fc( FETCHMAILRC );

	if( (ohost != host) || (oid != id ) )
	{
		// We have updated id fields, need to re-add account
		map<string,string> acc = fc.GetAccount(ohost, oid);

		fc.DeleteAccount(ohost, oid);

		acc["email"] =		(email != "" ) ? email : acc["email"];
		acc["host"] =		host;
		acc["identity"]	=	id;
		acc["username"] =	(user != "") ? user : acc["username"];
		acc["password"] =	(pwd != "") ? pwd : acc["password"];
		acc["ssl"] =		(ssl != "") ? ssl : acc["ssl"];

		fc.AddAccount(acc["email"],acc["host"],acc["identity"],acc["password"],acc["username"],acc["ssl"]=="true");
	}
	else
	{
		fc.UpdateAccount(email, host, id, pwd, user, ssl == "true" );
	}
	fc.WriteConfig();
	restart_fetchmail();

	this->SendOK(client, cmd);
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

	FetchmailConfig fc( FETCHMAILRC );

	map<string,string> account = fc.GetAccount(host, id);

	if( ! this->isAdminOrUser( token, account["username"] ) )
	{
		this->SendErrorMessage(client, cmd, 401, "Not allowed");
		return;
	}

	fc.DeleteAccount(host, id );
	fc.WriteConfig();
	restart_fetchmail();

	this->SendOK(client, cmd);
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
        res["opiname"] = sysconfig.GetKeyAsString("hostinfo","hostname");
        res["dnsenabled"] = sysconfig.GetKeyAsBool("dns","enabled");
        res["domain"] = sysconfig.GetKeyAsString("hostinfo","domain");
        logg << Logger::Debug << "opiname: " << sysconfig.GetKeyAsString("hostinfo","hostname").c_str() << " domain: " << sysconfig.GetKeyAsString("hostinfo","domain").c_str() <<lend;

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
    SysConfig sysconfig(true);

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin( client, cmd ) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_HST , cmd) )
	{
		return;
	}

    string unit_id;
    string oldopiname;
    string hostname;
    string domain;
    string olddomain;
    string fqdn;

    try
    {
        unit_id = sysconfig.GetKeyAsString("hostinfo","unitid");
        oldopiname = sysconfig.GetKeyAsString("hostinfo","hostname");
        hostname = cmd["hostname"].asString();
        domain = cmd["domain"].asString();
        olddomain = sysconfig.GetKeyAsString("hostinfo","domain");
        fqdn = hostname+"."+domain;
    }
    catch (std::runtime_error& e)
    {
        this->SendErrorMessage( client, cmd, 500, "Failed to read config parameters");
    }

    if( (hostname == oldopiname) && (olddomain == domain))
	{
		// no need to do any updates on server side
		// make sure dns is enabled and return vith OK
        try
        {
            sysconfig.PutKey("dns","enabled",true);
        }
        catch (std::runtime_error& e)
        {
            this->SendErrorMessage( client, cmd, 500, "Failed to set config parameters");
            logg << Logger::Error << "Failed to set sysconfig" << e.what() << lend;
            return;
        }

		this->SendOK(client, cmd);
		return;
	}
	if( unit_id == "" )
	{
		this->SendErrorMessage( client, cmd, 500, "Failed to retrieve unit id");
		return;
	}

	/* Try update DNS, i.e. reserve name */
	OPI::DnsServer dns;
    logg << Logger::Debug << "Try to set new device name on server"<<lend;

    if( !dns.UpdateDynDNS(unit_id, fqdn) )
	{
		this->SendErrorMessage( client, cmd, 400, "Failed to set opi name");
		return;
	}

    logg << Logger::Debug << "Update sysconfig with new name"<<lend;
    // Update sysconfig with new name
    try
    {
        sysconfig.PutKey("hostinfo","hostname",hostname);
        sysconfig.PutKey("hostinfo","domain",domain);
        sysconfig.PutKey("dns","enabled",true);

    }
    catch (std::runtime_error& e)
    {
        this->SendErrorMessage( client, cmd, 500, "Failed to set config parameters");
        logg << Logger::Error << "Failed to set sysconfig" << e.what() << lend;
        return;
    }

	/* Get a signed certificate for the new name */
    logg << Logger::Debug << "Get OP cert"<<lend;
	string token = this->BackendLogin( unit_id );
	if( token == "" )
	{
		this->SendErrorMessage( client, cmd, 400, "Failed to authenticate");
		return;
	}

    string defaultcert = sysconfig.GetKeyAsString("webcertificate","defaultcert");
    string csrfile = File::GetPath(defaultcert) + "/" + fqdn +".csr";
    if( ! CryptoHelper::MakeCSR(sysconfig.GetKeyAsString("dns","dnsauthkey"), csrfile, fqdn, "OPI") )
	{
		this->SendErrorMessage( client, cmd, 500, "Failed create CSR");
		return;
	}

    string csr = File::GetContentAsString(csrfile, true);

	AuthServer s(unit_id);

	int resultcode;
	Json::Value ret;
	tie(resultcode, ret) = s.GetCertificate(csr, token );

	if( resultcode != 200 )
	{
		this->SendErrorMessage( client, cmd, 400, "Failed get signed certificate");
		return;
	}

	if( ! ret.isMember("cert") || ! ret["cert"].isString() )
	{
		this->SendErrorMessage( client, cmd, 500, "Malformed reply from server");
		return;
	}

	// Make sure we have no symlinked tempcert in place
    unlink( defaultcert.c_str());
    File::Write( defaultcert, ret["cert"].asString(), 0644);

	/* Update postfix with new "hostname" */
    logg << Logger::Debug << "Update mail config"<<lend;
    File::Write("/etc/mailname", fqdn, 0644);

	MailConfig mc;
    try
    {
        mc.ReadConfig();
        mc.ChangeDomain(oldopiname+"."+domain,fqdn);
        mc.WriteConfig();
    }
    catch (std::runtime_error& err)
    {
        string errmsg="Failed to update domain in MailConfig";
        response["errmsg"]=errmsg;
        logg << Logger::Error << "Caught exception: " << err.what() <<lend;
        Notify::NewMessage Msg(LOG_ERR,errmsg);
        Msg.Send();
    }

    //this->SendOK(client, cmd);



    /* Try to get a signed external certificate */
    /* The script(s) responsible for external certs shall read hostname and domain from sysinfo */
    logg << Logger::Debug << "Start generation of external certificates"<<lend;
    int retval;
    string msg;

    OPI::ExtCert ec;
    tie(retval,msg) = ec.GetExternalCertificates(false);
    logg << Logger::Debug << "Ext Cert returned: " << retval << lend;
    if ( ! retval )
    {
        string errmsg=" Failed to generate new externally signed certificate when setting name '"+fqdn+"'.";
        response["errmsg"] = response["errmsg"].asString() + errmsg;
        logg << Logger::Warning << errmsg << lend;
        Notify::NewMessage Msg(LOG_WARNING,errmsg);
        Msg.Send();

    }

    this->SendOK(client, cmd, response);


    /* Restart related services */
    update_postfix();
    ServiceHelper::Reload("nginx");


}

void OpiBackendServer::DoNetworkGetDomains(UnixStreamClientSocketPtr &client, Json::Value &cmd) {

    ScopedLog l("Get Domains!");


    if( ! this->CheckLoggedIn(client,cmd) )
    {
        return;
    }

    try
    {
        SysConfig sysconfig;
        Json::Value res(Json::objectValue);
        Json::Value d(Json::arrayValue);
        list<string> domains = sysconfig.GetKeyAsStringList("dns","availabledomains");

        for(const auto& val: domains)
        {
            d.append(val);
        }
        res["availabledomains"] = d;

        this->SendOK(client, cmd, res);
    }
    catch (std::runtime_error& e)
    {
        this->SendErrorMessage( client, cmd, 500, "Failed to read config parameters");
        logg << Logger::Error << "Failed to read sysconfig" << e.what() << lend;
        return;
    }
}


void OpiBackendServer::DoNetworkDisableDNS(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Disalbe OPI DNS");
    SysConfig sysconfig(true);
	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

    try
    {
        sysconfig.PutKey("dns","enabled",false);
    }
    catch (std::runtime_error& e)
    {
        this->SendErrorMessage( client, cmd, 500, "Failed to set config parameters");
        logg << Logger::Error << "Failed to set sysconfig" << e.what() << lend;
        return;
    }

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoNetworkGetCert(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Get Webserver Certificates");
	Json::Value cfg;
	string CustomCertFile,CustomKeyFile;
    SysConfig sysconfig;


	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin( client, cmd ) )
	{
		return;
	}

    cfg["CertType"] = sysconfig.GetKeyAsString("webcertificate","backend");
    if (sysconfig.HasKey("webcertificate","customcert"))
    {
        CustomCertFile = sysconfig.GetKeyAsString("webcertificate","customcert");
    }

	if ( File::FileExists( CustomCertFile ) )
	{
		cfg["CustomCertVal"] = File::GetContentAsString(CustomCertFile, true);
	}
	else
	{
		cfg["CustomCertVal"] = "";

	}

	if ( cfg["CertType"] == "LETSENCRYPT" )
	{
        string webcert = sysconfig.GetKeyAsString("webcertificate","activecert");
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

            if ( File::GetFileName(File::RealPath(certpath)) == File::GetFileName(sysconfig.GetKeyAsString("webcertificate","defaultcert")) )
	    	{
	    		cfg["CertStatus"] = "ERROR";
	    		logg << Logger::Debug << "Lets Encrypt cert asked for, but not used."<<lend;		      
	    	}
	    }
	}


	this->SendOK( client, cmd, cfg);
}

void OpiBackendServer::DoNetworkSetCert(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Set Webserver Certificates");

	string CustomCertFile,CustomKeyFile;
    Json::Value response;

	string certtype = cmd["CertType"].asString();
	string certificate = cmd["CustomCertVal"].asString();
	string key = cmd["CustomKeyVal"].asString();
    SysConfig sysconfig(true);
	int linkval;

	if (certtype == "LETSENCRYPT") 
	{
        // actual certificate generation and updates handled by kinguard-certhandler triggered by cron
        try
        {
            sysconfig.PutKey("webcertificate","backend",certtype);
        }
        catch (std::runtime_error& e)
        {
            this->SendErrorMessage( client, cmd, 500, "Failed to set config parameters");
            logg << Logger::Error << "Failed to set sysconfig" << e.what() << lend;
            return;
        }

        logg << Logger::Debug << "Start generation of external certificates"<<lend;
        int retval;
        string msg;

        OPI::ExtCert ec;
        tie(retval,msg) = ec.GetExternalCertificates(false);
        logg << Logger::Debug << "Ext Cert returned: " << retval << lend;
        if ( ! retval )
        {
            string errmsg="Failed to generate externally signed certificate";
            response["errmsg"] = errmsg;
            logg << Logger::Warning << errmsg << lend;
            Notify::NewMessage Msg(LOG_WARNING,errmsg);
            Msg.Send();
        }
        this->SendOK(client, cmd, response);

        /* Restart related services */
        ServiceHelper::Reload("nginx");

	}
	else if (certtype == "CUSTOMCERT")
	{
		if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin( client, cmd ) )
		{
			this->SendErrorMessage( client, cmd, 404, "Unauthorized");
			return;
		}

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

        string CustomCertPath = "/etc/kinguard/usercert/";
        string webcert = sysconfig.GetKeyAsString("webcertificate","activecert");
        string webkey = sysconfig.GetKeyAsString("webcertificate","activekey");
        if (sysconfig.HasKey("webcertificate","customkey") && sysconfig.HasKey("webcertificate","customcert") )
        {
            CustomKeyFile = sysconfig.GetKeyAsString("webcertificate","customkey");
            CustomCertFile = sysconfig.GetKeyAsString("webcertificate","customcert");
            CustomCertPath = File::GetPath(CustomCertFile);
        }


        string keyFilename = this->getTmpFile(CustomCertPath,".key");
        string certFilename = this->getTmpFile(CustomCertPath,".cert");

		if ( key.length() )
		{
			if (! this->writeCertificate(key,keyFilename,CustomKeyFile) )
			{
				this->SendErrorMessage( client, cmd, 500, "Failed to write key to file");
				return;
			}

		} else {
			// using existing key on file, since no key is posted we have validated the key 
			// already on file otherwise we can not come here.
			logg << Logger::Debug << "Using Private Key from file" << lend;
			keyFilename = CustomKeyFile;
		}
		if (! this->writeCertificate(certificate,certFilename,CustomCertFile) )
		{
			this->SendErrorMessage( client, cmd, 500, "Failed to write certificate to file");
			return;
		}

		// create a backup copy of the cert symlinks nginx uses
		string curr_key,curr_cert;
        curr_key = File::RealPath(webkey);
        curr_cert = File::RealPath(webcert);

        File::Delete(webcert);
        File::Delete(webkey);

        linkval=symlink(certFilename.c_str(),webcert.c_str());
        linkval=symlink(keyFilename.c_str(),webkey.c_str());

		// new links should now be in place, let nginx test the config
		int retval;
		string Message;

		tie(retval,Message)=Process::Exec( "nginx -t" );
		if ( retval )
		{
            try
            {
                sysconfig.PutKey("webcertificate","customkey",keyFilename);
                sysconfig.PutKey("webcertificate","customcert",certFilename);
                sysconfig.PutKey("webcertificate","backend",certtype);
            }
            catch (std::runtime_error& e)
            {
                this->SendErrorMessage( client, cmd, 500, "Failed to set config parameters");
                logg << Logger::Error << "Failed to set sysconfig" << e.what() << lend;
                return;
            }

            // send ok message prior to ngix restart
            this->SendOK( client, cmd);

			// update config file

			// nginx config is correct, restart webserver
            logg << Logger::Debug << "Reloading Nginx config" << lend;
            ServiceHelper::Reload("nginx");
            return;
		}
		else
		{
			// nginx config test failed, restore old links
			logg << Logger::Debug << "Nginx config test failed" << lend;
            File::Delete(webcert);
            File::Delete(webkey);

            linkval=symlink(curr_cert.c_str(),webcert.c_str());
            linkval=symlink(curr_key.c_str(),webkey.c_str());

			this->SendErrorMessage( client, cmd, 500, "Webserver config test failed with new certificates");
			return;

		}
		this->SendOK( client, cmd);
	}
	else 
	{
		this->SendErrorMessage( client, cmd, 500, "Unable to handle certificate requests");
		return;
	}


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
		ret["ipnumber"] = cfg["options"]["address"][(uint)0].asString();
		ret["netmask"] = cfg["options"]["netmask"][(uint)0].asString();
		ret["gateway"] = cfg["options"]["gateway"][(uint)0].asString();
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

void OpiBackendServer::DoSystemGetType(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
    ScopedLog l("Do System Get Type");
    Json::Value ret;

    int type;
    string typeText;

    type=OPI::sysinfo.Type();
    typeText=OPI::sysinfo.SysTypeText[type];

    ret["type"]=type;
    ret["typeText"]=typeText;

    try
    {
        ret["theme"] = SysConfig().GetKeyAsString("webapps","theme");
    }
    catch( std::runtime_error& err)
    {
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
	if( this->lastreap + 60 > time(NULL) )
	{
		return;
	}

	logg << Logger::Debug << "Reap clients"<<lend;

	this->clients.Reap();

	this->lastreap = time(NULL);
}

Json::Value OpiBackendServer::GetUser(const string &token, const string &user)
{
	SecopPtr secop = this->clients.GetClientByToken(token)->Secop();

	Json::Value ret;
	ret["username"] = user;
	ret["id"] = user;
	try
	{
		ret["displayname"] = secop->GetAttribute(user,"displayname");
	}
	catch( std::runtime_error err)
	{
		// No error if displayname missing
		ret["displayname"] ="";
	}
	try
	{
		ret["defaultemail"] = secop->GetAttribute(user,"defaultemail");
	}
	catch( std::runtime_error err)
	{
		// No error if default email is missing
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
	Json::Value ret(Json::objectValue);
	ret["status"]["value"]=errcode;
	ret["status"]["desc"]=msg;
	
	this->SendReply(client, ret);
}

void OpiBackendServer::SendOK(UnixStreamClientSocketPtr &client, const Json::Value &cmd, const Json::Value &val)
{
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

static inline bool
CheckArgument(const Json::Value& cmd, const string& member, ArgCheckType type)
{
	if( cmd.isNull() )
	{
		return false;
	}

	switch( type )
	{
	case ArgCheckType::STRING:
		return cmd.isMember( member ) && cmd[member].isString();
		break;
	case ArgCheckType::INT:
		return cmd.isMember( member ) && cmd[member].isInt();
		break;
	case ArgCheckType::BOOL:
		return cmd.isMember( member ) && cmd[member].isBool();
		break;
	default:
		return false;
	}
}

bool OpiBackendServer::CheckArguments(UnixStreamClientSocketPtr& client, int what,const Json::Value& cmd)
{
	for( auto check: argchecks )
	{
		if( what & check.check && ! CheckArgument( cmd, check.member, check.type) )
		{
			logg << Logger::Debug << "Failed to verify argument "<<check.member<<lend;
			this->SendErrorMessage(client, cmd, 400, "Missing argument");
			return false;
		}
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
        // no key was passed in the post, try to use existing one on file
        try
        {
            SysConfig sysconfig;
            CustomKeyFile = sysconfig.GetKeyAsString("webcertificate","customkey");
        }
        catch (std::runtime_error& e)
        {
            logg << Logger::Error << "Failed to read sysconfig" << e.what() << lend;
            return false;
        }

		if( ! File::FileExists( CustomKeyFile ) )
		{
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


bool OpiBackendServer::writeCertificate(string cert, string &newFile, string oldFile)
{
	std::size_t fileHash=0;
	std::size_t certHash=0;
	string filepath = File::GetPath(newFile);

	if ( File::FileExists(oldFile) )
	{
		fileHash = std::hash<std::string>{}(File::GetContentAsString(oldFile, true));
	}
	certHash = std::hash<std::string>{}(cert);

	// check if the files are the same
	if (fileHash == certHash ) 
	{
		logg << Logger::Debug << "Received data is the same as already on file." << lend;
		newFile = oldFile;
	}
	else
	{
	 	// write Private Key file
	 	if (! File::DirExists( filepath) )
	 	{
	 		File::MkPath(filepath, 0755);
	 	}
	 	File::Write( newFile,cert,600);
	}
	return true;
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
