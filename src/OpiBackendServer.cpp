#include "OpiBackendServer.h"
#include "SmtpClientConfig.h"
#include "FetchmailConfig.h"
#include "MailConfig.h"
#include "Config.h"

#include <libutils/Logger.h>
#include <libutils/String.h>
#include <libutils/FileUtils.h>
#include <libutils/ConfigFile.h>
#include <libutils/UserGroups.h>

#include <libopi/DnsServer.h>
#include <libopi/AuthServer.h>
#include <libopi/CryptoHelper.h>
#include <libopi/ServiceHelper.h>

#include <algorithm>

/*
 * Bit patterns for argument checks
 * (A bit uggly but effective)
 */
#define CHK_USR	0x0001	// Check username
#define CHK_PWD	0x0002	// Check password
#define CHK_DSP	0x0004	// Check displayname
#define CHK_NPW 0x0008	// Check new password
#define CHK_GRP 0x0010	// Check group
#define CHK_DMN 0x0020	// Check domain
#define CHK_ADR 0x0040	// Check address
#define CHK_HST 0x0080  // Check hostname
#define CHK_IDN 0x0100  // Check identity
#define CHK_PRT 0x0200  // Check port
#define CHK_EML 0x0400  // Check email
#define CHK_SSL 0x0800  // Check ssl

enum ArgCheckType{
	STRING,
	INT
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
			{ CHK_DMN, "domain",		ArgCheckType::STRING },
			{ CHK_GRP, "group",			ArgCheckType::STRING },
			{ CHK_ADR, "address",		ArgCheckType::STRING },
			{ CHK_HST, "hostname",		ArgCheckType::STRING },
			{ CHK_IDN, "identity",		ArgCheckType::STRING },
			{ CHK_PRT, "port",			ArgCheckType::STRING },
			{ CHK_EML, "email",			ArgCheckType::STRING },
			{ CHK_SSL, "ssl",			ArgCheckType::STRING },
	});

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

	// Setup mail paths etc
	postfix_fixpaths();

	// Initialize time for last reap
	this->lastreap = time(NULL);
}

void OpiBackendServer::Dispatch(SocketPtr con)
{
	ScopedLog l("Dispatch");

	// Convert into unixsocket
	UnixStreamClientSocketPtr sock = static_pointer_cast<UnixStreamClientSocket>(con);

	char buf[64*1024];
	size_t rd;

	try
	{
		while( (rd = sock->Read(buf, sizeof(buf))) > 0 )
		{
			logg << "Read request of socket"<<lend;
			Json::Value req;
			if( reader.parse(buf, buf+rd, req) )
			{
				if( req.isMember("cmd") && req["cmd"].isString() )
				{
					this->ProcessOneCommand(sock, req);
				}
				else
				{
					this->SendErrorMessage(sock, Json::Value::null, 4, "Missing command in request");
					break;
				}
			}
			else
			{
				this->SendErrorMessage(sock, Json::Value::null, 4, "Unable to parse request");
				break;
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

	if( this->CheckLoggedIn( username ))
	{
		logg << Logger::Debug << "User seems already logged in, validating anyway"<<lend;
		SecopPtr secop = this->clients[this->users[ username ] ].secop;

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
		ret["token"] = this->users[username];

		this->SendOK(client, cmd, ret);

		// Update last access
		this->TouchCLient( this->users[username]);

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
		string token = this->AddUser(username, secop);

		Json::Value ret;
		ret["token"] = token;

		this->SendOK(client, cmd, ret);

		this->TouchCLient( this->users[username]);
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

	SecopPtr secop = this->clients[token].secop;

	if( ! secop->CreateUser( user, pass,display ) )
	{
		this->SendErrorMessage(client, cmd, 400, "Failed");
		return;
	}

	// Add user to local mail
	MailMapFile mmf( LOCAL_MAILFILE );
	mmf.ReadConfig();
	mmf.SetAddress("localdomain", user, user);
	mmf.WriteConfig();

	// Add user to opi-domain
	ConfigFile c(SYS_INFO);
	string opiname = c.ValueOrDefault("opi_name");

	MailConfig mc;
	mc.ReadConfig();
	mc.SetAddress(opiname+".op-i.me",user,user);
	mc.WriteConfig();

	update_postfix();

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoDeleteUser(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do Delete user");

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

	if( user == this->UserFromToken( token ) )
	{
		this->SendErrorMessage(client, cmd, 403, "Not allowed");
		return;
	}

	SecopPtr secop = this->clients[token].secop;

	if( ! secop->RemoveUser( user ) )
	{
		this->SendErrorMessage(client, cmd, 400, "Failed");
		return;
	}

	// Remove user from local mail
	MailMapFile mmf( LOCAL_MAILFILE );
	mmf.ReadConfig();
	mmf.DeleteAddress("localdomain", user);
	mmf.WriteConfig();

	// Remove user from opi-domain
	ConfigFile c(SYS_INFO);
	string opiname = c.ValueOrDefault("opi_name");

	MailConfig mc;
	mc.ReadConfig();
	mc.DeleteAddress(opiname+".op-i.me",user);
	mc.WriteConfig();

	update_postfix();

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

	if( ! this->CheckIsAdminOrUser(client, cmd) )
	{
		return;
	}

	string token =		cmd["token"].asString();
	string user =		cmd["username"].asString();

	SecopPtr secop = this->clients[token].secop;

	vector<string> users  = secop->GetUsers();

	if( std::find(users.begin(), users.end(), user) == users.end() )
	{
		this->SendErrorMessage(client, cmd, 404, "User not found");
		return;
	}

	Json::Value ret = this->GetUser(token, user);

	this->SendOK(client, cmd,ret);
}

void OpiBackendServer::DoUpdateUser(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do update user");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_USR|CHK_DSP, cmd) )
	{
		return;
	}

	if( ! this->CheckIsAdminOrUser( client, cmd) )
	{
		return;
	}

	string token =		cmd["token"].asString();
	string user =		cmd["username"].asString();
	string disp =		cmd["displayname"].asString();

	SecopPtr secop = this->clients[token].secop;

	if( ! secop->AddAttribute(user, "displayname", disp) )
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

	SecopPtr secop = this->SecopFromCmd(cmd);

	string token = cmd["token"].asString();

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

	SecopPtr secop = this->SecopFromCmd(cmd);

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

	SecopPtr secop = this->clients[token].secop;

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

	if( user == this->UserFromToken( token ) )
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

	/*
	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	string token =	cmd["token"].asString();

	SecopPtr secop = this->clients[token];

*/

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

	SecopPtr secop = this->clients[token].secop;

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
		MailAliasFile mf( VIRTUAL_ALIASES );

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

	SecopPtr secop = this->clients[token].secop;

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

	SecopPtr secop = this->clients[token].secop;

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

	SecopPtr secop = this->clients[token].secop;

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
		MailAliasFile mf( VIRTUAL_ALIASES );

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

	if( ( group == "admin" ) && ( member == this->UserFromToken( token ) ) )
	{
		this->SendErrorMessage(client, cmd, 403, "Not allowed");
		return;
	}

	SecopPtr secop = this->clients[token].secop;

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

	if( ! this->CheckLoggedIn(client,cmd)  || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	if( File::FileExists(UPDATE_CONFIG))
	{
		ConfigFile c(UPDATE_CONFIG);
		res["update"] = c.ValueOrDefault("update");
		this->SendOK(client, cmd, res);
	}
	else
	{
		this->SendErrorMessage(client, cmd, 400, "No config file present");
	}
}

void OpiBackendServer::DoUpdateSetstate(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	Json::Value res(Json::objectValue);

	ScopedLog l("Set update state");
	string doupdates = cmd["state"].asString();

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	string path = File::GetPath( UPDATE_CONFIG );

	if( ! File::DirExists( path ) )
	{
		File::MkPath( path, 0755 );
	}

	ConfigFile c( UPDATE_CONFIG );
	if(doupdates == "1")
	{
		c["update"] = "yes";
	}
	else
	{
		c["update"] = "no";
	}

	c.Sync(true, 0644);
	this->SendOK(client, cmd);

}

void OpiBackendServer::DoBackupGetSettings(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	Json::Value res(Json::objectValue);
	string backend;
	string type;

	ScopedLog l("Get backup settings");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	if( File::FileExists(BACKUP_CONFIG))
	{
		ConfigFile c(BACKUP_CONFIG);
		backend = c.ValueOrDefault("backend");
		if(backend == "s3op://")
		{
			res["enabled"] = true;
			res["location"] = "remote";
		}
		else if (backend == "local://")
		{
			res["enabled"] = true;
			res["location"] = "local";
		}
		else
		{
			res["enabled"] = false;
			res["location"] = "remote";  // Show as default target in UI
		}
		res["type"] = c.ValueOrDefault("type");

		this->SendOK(client, cmd, res);
	}
	else
	{
		this->SendErrorMessage(client, cmd, 400, "No config file present");
	}
}

void OpiBackendServer::DoBackupSetSettings(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	Json::Value res(Json::objectValue);

	ScopedLog l("Set backup settings");
	string type = cmd["type"].asString();
	string backend = cmd["location"].asString();

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	string path = File::GetPath( BACKUP_CONFIG );

	if( ! File::DirExists( path ) )
	{
		File::MkPath( path, 0755 );
	}

	ConfigFile c( BACKUP_CONFIG );
	if(backend == "local")
	{
		c["backend"] = "local://";
	}
	else if (backend == "remote")
	{
		c["backend"] = "s3op://";
	}
	else
	{
		c["backend"] = "none";
	}

	c["type"] = type;

	c.Sync(true, 0644);
	this->SendOK(client, cmd);
	if(backend == "remote" || backend == "local")
	{
		this->ExecCmd((char*) BACKUP_MOUNT_FS);
		this->ExecCmd((char*) BACKUP_LINK);
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

	jsonMessage = ExecCmd((char*) BACKUP_GET_QUOTA );
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

	if( File::FileExists( BACKUP_ALERT ))
	{
		res["backup_status"] = "Failed";
		res["info"] = File::GetContentAsString( BACKUP_ALERT ,true );
		if( File::DirExists( BACKUP_ERRORS ))
		{
			stat( BACKUP_ERRORS , &filestatus );
			res["date"] = to_string(filestatus.st_mtime);
		}
	}
	else
	{
		res["backup_status"] = "Successful";
		res["info"] = "";
		if( File::DirExists( BACKUP_COMPLETE ))
		{
			stat( BACKUP_COMPLETE , &filestatus );
			res["date"] = to_string(filestatus.st_mtime);
		}
		else
		{
			res["date"] = "";
		}
	}

	this->SendOK(client, cmd, res);

}

void OpiBackendServer::DoSmtpGetDomains(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do smtp get domains");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
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

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
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

	ret = system( "/usr/sbin/postmap " ALIASES );

	if( (ret < 0) || WEXITSTATUS(ret) != 0 )
	{
		return false;
	}

	ret = system( "/usr/sbin/postmap " SASLPASSWD );

	if( (ret < 0) || WEXITSTATUS(ret) != 0 )
	{
		return false;
	}

	ret = system( "/usr/sbin/postmap " LOCAL_MAILFILE );

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
	if( ! File::FileExists( ALIASES ) )
	{
		File::Write( ALIASES, "", 0600);
	}

	if( ! File::FileExists( SASLPASSWD ) )
	{
		File::Write( SASLPASSWD, "", 0600);
	}

	if( ! File::FileExists( DOMAINFILE ) )
	{
		File::Write( DOMAINFILE, "", 0600);
	}

	if( ! File::FileExists( LOCAL_MAILFILE ) )
	{
		File::Write( LOCAL_MAILFILE, "", 0600);
	}

	if( chown( ALIASES, User::UserToUID("postfix"), Group::GroupToGID("postfix") ) != 0)
	{
		logg << Logger::Error << "Failed to change owner on aliases file"<<lend;
	}

	if( chown( SASLPASSWD, User::UserToUID("postfix"), Group::GroupToGID("postfix") ) != 0)
	{
		logg << Logger::Error << "Failed to change owner on saslpasswd file"<<lend;
	}

	if( chown( DOMAINFILE, User::UserToUID("postfix"), Group::GroupToGID("postfix") ) != 0)
	{
		logg << Logger::Error << "Failed to change owner on domain file"<<lend;
	}

	if( chown( File::GetPath(DOMAINFILE).c_str(), User::UserToUID("postfix"), Group::GroupToGID("postfix") ) != 0)
	{
		logg << Logger::Error << "Failed to change owner on config directory"<<lend;
	}

	if( chmod( File::GetPath(DOMAINFILE).c_str(), 0700 ) != 0)
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

	MailConfig mc;

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

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_DMN, cmd) )
	{
		return;
	}

	string domain = cmd["domain"].asString();

	MailConfig mc;

	list<tuple<string,string>> addresses = mc.GetAddresses(domain);

	Json::Value res(Json::objectValue);
	res["addresses"]=Json::arrayValue;
	for( auto address: addresses )
	{
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

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
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

	MailConfig mc;

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

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_DMN | CHK_ADR , cmd) )
	{
		return;
	}

	string domain = cmd["domain"].asString();
	string address = cmd["address"].asString();

	MailConfig mc;

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

	SmtpClientConfig cfg( SASLPASSWD );
	passwdline line = cfg.GetConfig();

	Json::Value ret;
	ret["usecustom"] =	line.host != "";
	ret["relay"] =		line.host;
	ret["username"] =	line.user;
	ret["password"] =	line.pass;
	ret["port"] =		line.port;

	this->SendOK(client, cmd,ret);

}

void OpiBackendServer::DoSmtpSetSettings(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do smtp set settings");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin(client, cmd) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_USR | CHK_PWD | CHK_HST | CHK_PRT , cmd) )
	{
		return;
	}

	if( !cmd.isMember("usecustom") || !cmd["usecustom"].isString() )
	{
		logg << Logger::Debug<< "Failed to parse custom argument"<<lend;
		this->SendErrorMessage(client, cmd, 400, "Missing argument");
		return;
	}

	string usec = cmd["usecustom"].asString();
	string user = cmd["username"].asString();
	string pass = cmd["password"].asString();
	string host = cmd["hostname"].asString();
	string port = cmd["port"].asString();

	bool usecustom = ( usec == "true" );

	passwdline cfg;
	cfg.enabled = ( (user != "") || ( pass != "") );
	if( usecustom )
	{
		cfg.host = host;
		cfg.pass = pass;
		cfg.port = port;
		cfg.user = user;
	}

	SmtpClientConfig scli( SASLPASSWD );
	scli.SetConfig( cfg );

	scli.WriteConfig();

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

	string email = cmd["email"].asString();
	string host = cmd["hostname"].asString();
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

	fc.UpdateAccount(email, host, id, pwd, user, ssl == "true" );
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

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin( client, cmd ) )
	{
		return;
	}
	string port = "ports["+cmd["port"].asString()+"]";

	if( File::FileExists(ACCESS_CONFIG))
	{
		ConfigFile c(ACCESS_CONFIG);
		res["is_open"] = c.ValueOrDefault(port,"no");
		this->SendOK(client, cmd, res);
	}
	else
	{
		res["is_open"] = "no";
		this->SendOK(client, cmd, res);
	}
}

void OpiBackendServer::DoNetworkSetPortStatus(UnixStreamClientSocketPtr &client, Json::Value &cmd) {
	Json::Value res(Json::objectValue);

	ScopedLog l("Set port state");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin( client, cmd ) )
	{
		return;
	}

	string port = "ports["+cmd["port"].asString()+"]";
	string state;
	if(cmd["set_open"].asBool())
	{
		state = "yes";
	}
	else
	{
		state = "no";
	}

	string access_path = File::GetPath( ACCESS_CONFIG );
	if( ! File::DirExists( access_path ) )
	{
		File::MkPath( access_path, 0755);
	}

	ConfigFile c(ACCESS_CONFIG);
	c[port] = state;
	c.Sync(true, 0644);
	this->SendOK(client, cmd);
}

void OpiBackendServer::DoNetworkGetOpiName(UnixStreamClientSocketPtr &client, Json::Value &cmd) {
	Json::Value res(Json::objectValue);

	ScopedLog l("Get OPI name");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	if( File::FileExists(SYS_INFO))
	{
		ConfigFile c(SYS_INFO);
		res["opiname"] = c.ValueOrDefault("opi_name");
		this->SendOK(client, cmd, res);
	}
	else
	{
		this->SendErrorMessage( client, cmd, 500, "Failed to read sysinfo file");
	}
}

void OpiBackendServer::DoNetworkSetOpiName(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Set OPI name");

	if( ! this->CheckLoggedIn(client,cmd) || !this->CheckIsAdmin( client, cmd ) )
	{
		return;
	}

	if( ! this->CheckArguments(client, CHK_HST , cmd) )
	{
		return;
	}

	if( ! File::FileExists( SYS_INFO ) )
	{
		this->SendErrorMessage( client, cmd, 500, "Failed to read sysinfo file");
		return;
	}

	ConfigFile c(SYS_INFO);
	string unit_id = c.ValueOrDefault("unit_id");

	string oldopiname = c.ValueOrDefault("opi_name");
	string hostname = cmd["hostname"].asString();

	if( unit_id == "" )
	{
		this->SendErrorMessage( client, cmd, 500, "Failed to retrieve unit id");
		return;
	}

	/* Try update DNS, i.e. reserve name */
	OPI::DnsServer dns;

	if( !dns.UpdateDynDNS(unit_id, hostname) )
	{
		this->SendErrorMessage( client, cmd, 400, "Failed to set opi name");
		return;
	}

	/* Get a signed certificate for the new name */
	string token = this->BackendLogin( unit_id );
	if( token == "" )
	{
		this->SendErrorMessage( client, cmd, 400, "Failed to authenticate");
		return;
	}

	if( ! CryptoHelper::MakeCSR(DNS_PRIV_PATH, CSR_PATH, hostname+".op-i.me", "OPI") )
	{
		this->SendErrorMessage( client, cmd, 500, "Failed create CSR");
		return;
	}

	string csr = File::GetContentAsString(CSR_PATH, true);

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
	unlink( CERT_PATH );

	File::Write( CERT_PATH, ret["cert"].asString(), 0644);

	/* Update postfix with new "hostname" */
	File::Write("/etc/mailname", hostname+".op-i.me", 0644);

	MailConfig mc;
	mc.ReadConfig();
	mc.ChangeDomain(oldopiname,hostname);
	mc.WriteConfig();

	this->SendOK(client, cmd);

	/* Restart related services */
	update_postfix();

	ServiceHelper::Stop("nginx");
	ServiceHelper::Start("nginx");
}


bool OpiBackendServer::CheckLoggedIn(const string &username)
{
	bool found = this->users.find(username) != this->users.end();
	if( ! found )
	{
		return false;
	}

	// Check session
	string token = this->TokenFromUser( username );

	if( this->clients[token].lastaccess+SESSION_TIMEOUT  < time(nullptr) )
	{
		return false;
	}

	return true;
}

bool OpiBackendServer::CheckLoggedIn(UnixStreamClientSocketPtr &client, Json::Value &req)
{
	if( !req.isMember("token") && !req["token"].isString() )
	{
		this->SendErrorMessage(client, req, 400, "Missing argument");
		return false;
	}

	string token = req["token"].asString();

	if( this->clients.find( token ) == this->clients.end() )
	{
		this->SendErrorMessage(client, req, 401, "Unauthorized");
		return false;
	}

	if( this->clients[token].lastaccess+SESSION_TIMEOUT  < time(nullptr) )
	{
		this->SendErrorMessage(client, req, 401, "Unauthorized");
		return false;
	}

	this->TouchCLient( token );

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
	return this->clients[token].isadmin;
}

bool OpiBackendServer::isAdminOrUser(const string &token, const string &user)
{
	return this->isAdmin( token ) || ( this->users[user] == token );
}

string OpiBackendServer::BackendLogin(const string &unit_id)
{
	AuthServer s( unit_id);

	CryptoHelper::RSAWrapper c;
	Secop secop;
	secop.SockAuth();

	list<map<string,string>> ids =  secop.AppGetIdentifiers("op-backend");

	if( ids.size() == 0 )
	{
		logg << Logger::Error << "Failed to get keys from secop"<<lend;
		return "";
	}

	bool found = false;
	for(auto id : ids )
	{
		if( id.find("type") != id.end() )
		{
			if( id["type"] == "backendkeys" )
			{
				// Key found
				c.LoadPrivKeyFromDER( CryptoHelper::Base64Decode( id["privkey"]) );
				c.LoadPubKeyFromDER( CryptoHelper::Base64Decode( id["pubkey"]) );
				found = true;
				break;
			}
		}
	}

	if( ! found )
	{
		logg << Logger::Error << "failed to load keys from secop"<<lend;
		return "";
	}

	string challenge;
	int resultcode;
	tie(resultcode,challenge) = s.GetChallenge();

	if( resultcode != 200 )
	{
		logg << Logger::Error << "Unknown reply of server "<<resultcode<< lend;
		return "";
	}

	string signedchallenge = CryptoHelper::Base64Encode( c.SignMessage( challenge ) );

	Json::Value rep;
	tie(resultcode, rep) = s.SendSignedChallenge( signedchallenge );

	if( resultcode != 200 )
	{
		logg << Logger::Error << "Unexpected reply from server "<< resultcode <<lend;
		return "";
	}

	if( rep.isMember("token") && rep["token"].isString() )
	{
		return rep["token"].asString();
	}

	return "";

}

void OpiBackendServer::TouchCLient(const string &token)
{
	if( this->clients.find(token) != this->clients.end() )
	{
		this->clients[token].lastaccess = time(nullptr);
	}
}

void OpiBackendServer::ReapClient(const string &token)
{
	string user = this->UserFromToken( token );

	if( this->users.find(user) == this->users.end() )
	{
		logg << Logger::Error << "User token not found to delete"<<lend;
		return;
	}

	if( this->clients.find(token) == this->clients.end() )
	{
		logg << Logger::Error << "Client to delete not found"<<lend;
		return;
	}

	this->users.erase(user);
	this->clients.erase(token);
}

void OpiBackendServer::ReapClients()
{
	// Only reap once a minute
	if( this->lastreap + 60 > time(NULL) )
	{
		return;
	}

	logg << Logger::Debug << "Reap clients"<<lend;

	list <string> toreap;

	for( auto client: this->clients )
	{
		string token = client.first;
		userdata data = client.second;

		if( data.lastaccess + SESSION_TIMEOUT < time(NULL) )
		{
			// Reap this client
			toreap.push_back( token );
		}

	}

	logg << Logger::Debug << "About to reap "<<toreap.size() << " clients of "<< this->clients.size() << " active"<<lend;

	for( const string& client: toreap )
	{
		this->ReapClient( client );
	}

	this->lastreap = time(NULL);
}

Json::Value OpiBackendServer::GetUser(const string &token, const string &user)
{
	SecopPtr secop = this->clients[token].secop;

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

string OpiBackendServer::UserFromToken(const string &token)
{
	for( auto usertoken: this->users)
	{
		if( usertoken.second == token )
		{
			return usertoken.first;
		}
	}
	return "";
}

const string &OpiBackendServer::TokenFromUser(const string &user)
{
	return this->users[user];
}

SecopPtr OpiBackendServer::SecopFromCmd(Json::Value &cmd)
{
	return  this->clients[ cmd["token"].asString() ].secop;
}

string OpiBackendServer::AddUser(const string &username, SecopPtr secop)
{
	//TODO: Perhaps something a bit more elaborate token?
	string token = String::UUID();


	vector<string> members = secop->GetGroupMembers( "admin" );
	bool isadmin = find(members.begin(), members.end(), username ) != members.end();

	this->users[username] = token;
	this->clients[token].secop = secop;
	this->clients[token].isadmin = isadmin;
	this->clients[token].lastaccess = time(nullptr);

	return token;
}

// Local helper functions

string OpiBackendServer::ExecCmd(const char* cmd)
{
	FILE* pipe = popen(cmd, "r");
	if (!pipe) return "ERROR";
	char buffer[128];
	std::string result = "";
	while(!feof(pipe))
	{
		if(fgets(buffer, 128, pipe) != NULL)
			result += buffer;
	}
	pclose(pipe);
	return result;
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

