#include "OpiBackendServer.h"

#include <libutils/Logger.h>
#include <libutils/String.h>

/*
 * Bit patterns for argument checks
 * (A bit uggly but effective)
 */
#define CHK_USR	0x01	// Check username
#define CHK_PWD	0x02	// Check password
#define CHK_DSP	0x04	// Check displayname

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
	this->actions["createuser"]=&OpiBackendServer::DoCreateUser;
	this->actions["updateuser"]=&OpiBackendServer::DoUpdateUser;
	this->actions["deleteuser"]=&OpiBackendServer::DoDeleteUser;
	this->actions["getuser"]=&OpiBackendServer::DoGetUser;
	this->actions["getusers"]=&OpiBackendServer::DoGetUsers;

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
	ret["displayname"] = secop->GetAttribute(user,"displayname");

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
			logg << Logger::Error << "Failed to execute command "<< action << ": "<<err.what()<<lend;
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

	if( ( what & CHK_DSP) && !CheckDisplayname(cmd) )
	{
		this->SendErrorMessage(client, cmd, 400, "Missing argument");
		return false;
	}


	return true;
}

