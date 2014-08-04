#include "OpiBackendServer.h"

#include <libutils/Logger.h>
#include <libutils/String.h>
#include <libutils/FileUtils.h>
#include <libutils/ConfigFile.h>

#include <algorithm>

/*
 * Bit patterns for argument checks
 * (A bit uggly but effective)
 */
#define CHK_USR	0x01	// Check username
#define CHK_PWD	0x02	// Check password
#define CHK_DSP	0x04	// Check displayname
#define CHK_NPW 0x08	// Check new password

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
			if( reader.parse(buf, req) )
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
		SecopPtr secop = this->clients[this->users[ username ] ];

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

	if( ! this->CheckLoggedIn(client,cmd) )
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

	this->TouchCLient( token );

	SecopPtr secop = this->clients[token];

	if( ! secop->CreateUser( user, pass,display ) )
	{
		this->SendErrorMessage(client, cmd, 400, "Failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoDeleteUser(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do Delete user");

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

	this->TouchCLient( token );

	SecopPtr secop = this->clients[token];

	if( ! secop->RemoveUser( user ) )
	{
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

	this->TouchCLient( token );

	SecopPtr secop = this->clients[token];

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


	string token =		cmd["token"].asString();
	string user =		cmd["username"].asString();
	string disp =		cmd["displayname"].asString();

	this->TouchCLient( token );

	SecopPtr secop = this->clients[token];

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

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	string token =		cmd["token"].asString();

	SecopPtr secop = this->clients[token];

	this->TouchCLient( token );

	vector<string> usernames = secop->GetUsers();
	Json::Value ret;
	ret["users"]=Json::arrayValue;
	for(auto user: usernames)
	{
		ret["users"].append( this->GetUser(token, user) );
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

	string token =		cmd["token"].asString();
	string user =		cmd["username"].asString();
	string passw =		cmd["password"].asString();
	string newps =		cmd["newpassword"].asString();

	SecopPtr secop = this->clients[token];

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

	this->TouchCLient( token );
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

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	string token =	cmd["token"].asString();
	string group =	cmd["group"].asString();

	SecopPtr secop = this->clients[token];

	this->TouchCLient( token );

	if( !secop->AddGroup(group) )
	{
		this->SendErrorMessage(client, cmd, 400, "Operation failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoAddGroupMember(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do add group member");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	string token =	cmd["token"].asString();
	string group =	cmd["group"].asString();
	string member =	cmd["member"].asString();

	SecopPtr secop = this->clients[token];

	this->TouchCLient( token );

	if( !secop->AddGroupMember(group, member) )
	{
		this->SendErrorMessage(client, cmd, 400, "Operation failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoGetGroupMembers(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do add group member");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	string token =	cmd["token"].asString();
	string group =	cmd["group"].asString();

	SecopPtr secop = this->clients[token];

	this->TouchCLient( token );

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
	ScopedLog l("Do add group member");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	string token =	cmd["token"].asString();
	string group =	cmd["group"].asString();

	SecopPtr secop = this->clients[token];

	this->TouchCLient( token );

	if( !secop->RemoveGroup(group) )
	{
		this->SendErrorMessage(client, cmd, 400, "Operation failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoRemoveGroupMember(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do group remove member");

	if( ! this->CheckLoggedIn(client,cmd) )
	{
		return;
	}

	string token =	cmd["token"].asString();
	string group =	cmd["group"].asString();
	string member =	cmd["member"].asString();

	SecopPtr secop = this->clients[token];

	this->TouchCLient( token );

	if( !secop->RemoveGroupMember(group, member) )
	{
		this->SendErrorMessage(client, cmd, 400, "Operation failed");
		return;
	}

	this->SendOK(client, cmd);
}

void OpiBackendServer::DoShutdown(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Do shutdown");

	if( ! this->CheckLoggedIn(client,cmd) )
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

	if( ! this->CheckLoggedIn(client,cmd) )
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

	if( ! this->CheckLoggedIn(client,cmd) )
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

	if( ! this->CheckLoggedIn(client,cmd) )
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

	if( ! this->CheckLoggedIn(client,cmd) )
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

}

void OpiBackendServer::DoBackupGetQuota(UnixStreamClientSocketPtr &client, Json::Value &cmd)
{
	ScopedLog l("Get Quota");

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
	}

	this->SendOK(client, cmd, res);

}


bool OpiBackendServer::CheckLoggedIn(const string &username)
{
	return this->users.find(username) != this->users.end();
}

bool OpiBackendServer::CheckLoggedIn(UnixStreamClientSocketPtr &client, Json::Value &req)
{
	if( !req.isMember("token") && !req["token"].isString() )
	{
		this->SendErrorMessage(client, req, 400, "Missing argument");
		return false;
	}

	string token = req["token"].asString();

	if( this->clientaccess.find( token ) == this->clientaccess.end() )
	{
		this->SendErrorMessage(client, req, 401, "Unauthorized");
		return false;
	}

	if( this->clientaccess[token]+SESSION_TIMEOUT  < time(nullptr) )
	{
		this->SendErrorMessage(client, req, 401, "Unauthorized");
		return false;
	}

	return true;
}

void OpiBackendServer::TouchCLient(const string &token)
{
	if( this->clientaccess.find(token) != this->clientaccess.end() )
	{
		this->clientaccess[token]=time(nullptr);
	}
}

Json::Value OpiBackendServer::GetUser(const string &token, const string &user)
{
	SecopPtr secop = this->clients[token];

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

string OpiBackendServer::AddUser(const string &username, SecopPtr secop)
{
	//TODO: Perhaps something a bit more elaborate token?
	string token = String::UUID();
	this->users[username] = token;
	this->clients[token] = secop;
	this->clientaccess[token] = time(nullptr);

	return token;
}

// Local helper functions

string OpiBackendServer::ExecCmd(char* cmd)
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
CheckUsername(const Json::Value& cmd)
{
	return !cmd.isNull() &&	cmd.isMember("username") && cmd["username"].isString();
}

static inline bool
CheckPassword(const Json::Value& cmd)
{
	return !cmd.isNull() &&	cmd.isMember("password") && cmd["password"].isString();
}

static inline bool
CheckNewPassword(const Json::Value& cmd)
{
	return !cmd.isNull() &&	cmd.isMember("newpassword") && cmd["newpassword"].isString();
}

static inline bool
CheckDisplayname(const Json::Value& cmd)
{
	return !cmd.isNull() &&	cmd.isMember("displayname") && cmd["displayname"].isString();
}


bool OpiBackendServer::CheckArguments(UnixStreamClientSocketPtr& client, int what,const Json::Value& cmd)
{
	if( ( what & CHK_USR) && !CheckUsername(cmd) )
	{
		this->SendErrorMessage(client, cmd, 400, "Missing argument");
		return false;
	}

	if( ( what & CHK_PWD) && !CheckPassword(cmd) )
	{
		this->SendErrorMessage(client, cmd, 400, "Missing argument");
		return false;
	}

	if( ( what & CHK_NPW) && !CheckNewPassword(cmd) )
	{
		this->SendErrorMessage(client, cmd, 400, "Missing argument");
		return false;
	}

	if( ( what & CHK_DSP) && !CheckDisplayname(cmd) )
	{
		this->SendErrorMessage(client, cmd, 400, "Missing argument");
		return false;
	}


	return true;
}

