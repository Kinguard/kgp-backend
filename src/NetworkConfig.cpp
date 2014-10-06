
#include <iostream>
#include <sstream>

#include <stdlib.h>

#include "NetworkConfig.h"

#include <libutils/String.h>
#include <libutils/FileUtils.h>

namespace NetUtils
{

using namespace Utils;

NetworkConfig::NetworkConfig(const string &path): path(path)
{
	if( ! File::FileExists( this->path ) )
	{
		throw std::runtime_error("Network configfile not found");
	}
	this->parse();
}

Json::Value NetworkConfig::GetInterfaces()
{
	return this->cfg;
}

Json::Value NetworkConfig::GetInterface(const string &iface)
{
	if( ! this->cfg.isMember( iface ) )
	{
		throw std::runtime_error("Interface not found");
	}
	return this->cfg[iface];
}

void NetworkConfig::SetInterface(const string& iface, const Json::Value &v)
{
	this->cfg[iface]=v;
}

void NetworkConfig::SetDHCP(const string &iface)
{
	if( ! this->cfg.isMember( iface ) )
	{
		throw std::runtime_error("Interface not found");
	}
	Json::Value v;
	v["addressing"]="dhcp";
	v["auto"]=true;

	this->cfg[iface] = v;
}

void NetworkConfig::SetStatic(const string &iface, const string &ip, const string &nm, const string &gw)
{
	if( ! this->cfg.isMember( iface ) )
	{
		throw std::runtime_error("Interface not found");
	}
	Json::Value v;
	v["addressing"]="static";
	v["auto"]=true;
	v["options"]["address"].append(ip);
	v["options"]["netmask"].append(nm);
	if( gw != "" )
	{
		v["options"]["gateway"].append(gw);
	}

	this->cfg[iface] = v;
}

void NetworkConfig::Dump()
{
	cout << this->cfg.toStyledString()<<endl;
}

void NetworkConfig::WriteConfig()
{
	stringstream ss;

	Json::Value::Members mems = this->cfg.getMemberNames();

	for( auto iface: mems)
	{
		Json::Value ifc = this->cfg[iface];
		if( ifc["auto"].asBool() )
		{
			ss << "auto " << iface<<endl;
		}
		ss << "iface " << iface << " inet "<< ifc["addressing"].asString()<<endl;

		Json::Value::Members opts = ifc["options"].getMemberNames();
		for( auto opt: opts )
		{
			ss << "\t"<<opt;
			for( auto optval: ifc["options"][opt])
			{
				ss << " " << optval.asString();
			}
			ss << endl;
		}
		ss<< endl;
	}
	File::Write( this->path, ss.str(), 0644 );
}

NetworkConfig::~NetworkConfig()
{

}

void NetworkConfig::parse()
{
	list<string> lines = File::GetContent( this->path );
	list<string> autoifs;

	string cif; // Current interface;
	for( string line: lines)
	{
		line = String::Trimmed(line, " \t");
		if( line == "" || line[0]=='#')
		{
			continue;
		}

		list<string> words = String::Split(line, " ");
		if( words.size() > 1 )
		{
			if( words.front() == "auto")
			{
				words.pop_front();
				autoifs.insert(autoifs.end(), words.begin(), words.end() );
			}
			else if( words.front() == "iface" )
			{
				words.pop_front();
				cif = words.front();
				this->cfg[cif]["addressing"] = words.back();
				// Asume no auto for the time being
				this->cfg[cif]["auto"]=false;
			}
			else
			{
				// asume option to iface
				string key = words.front();
				words.pop_front();
				for( auto option: words)
				{
					this->cfg[cif]["options"][key].append(option);
				}
			}
		}

	}
	// Add auto on ifs using it
	for( auto ifs: autoifs)
	{
		this->cfg[ifs]["auto"]=true;
	}
}


ResolverConfig::ResolverConfig(const string &path): path(path)
{
	this->parse();
}

ResolverConfig::~ResolverConfig()
{

}
string ResolverConfig::getDomain() const
{
	return this->domain;
}

void ResolverConfig::setDomain(const string &value)
{
	this->domain = value;
}
string ResolverConfig::getSearch() const
{
	return this->search;
}

void ResolverConfig::setSearch(const string &value)
{
	this->search = value;
}
list<string> ResolverConfig::getNameservers() const
{
	return this->nss;
}

void ResolverConfig::setNameservers(const list<string> &value)
{
	this->nss = value;
}

void ResolverConfig::WriteConfig()
{
	stringstream ss;

	if( this->domain != "")
	{
		ss << "domain "<< this->domain<<endl;
	}

	if( this->search != "")
	{
		ss << "search "<< this->search<<endl;
	}

	for( auto ns: this->nss )
	{
		ss << "nameserver "<< ns<<endl;
	}

	File::Write( this->path, ss.str(), 0644 );

}

void ResolverConfig::Dump()
{
	cout << "Search : "<< this->search<<endl;
	cout << "Domain : "<< this->domain<<endl;
	for( auto x: this->nss )
	{
		cout << "Nameserver: "<<x<<endl;
	}
}




void ResolverConfig::parse()
{
	list<string> lines = File::GetContent( this->path );

	for( string line: lines)
	{
		line = String::Trimmed(line, " \t");
		if( line == "" || line[0]=='#')
		{
			continue;
		}

		list<string> words = String::Split(line, " ");
		if( words.size() > 1 )
		{
			if( words.front() == "nameserver")
			{
				this->nss.push_back( words.back() );
			}
			else if( words.front() == "search" )
			{
				this->search = words.back();
			}
			else if( words.front() == "domain" )
			{
				this->domain = words.back();
			}
		}

	}

}


#include <endian.h>

static int hextoval(char a, char b){
		a=toupper(a)>57?a-55:a-48;
		b=toupper(b)>57?b-55:b-48;
		return a*16+b;
}

static string addresstostring(const string& address){

		char buf[128];
#if __BYTE_ORDER == __LITTLE_ENDIAN
		sprintf(buf,"%d.%d.%d.%d",
								hextoval(address[6],address[7]),
								hextoval(address[4],address[5]),
								hextoval(address[2],address[3]),
								hextoval(address[0],address[1]));
#elif __BYTE_ORDER == __BIG_ENDIAN
		sprintf(buf,"%d.%d.%d.%d",
								hextoval(address[0],address[1]),
								hextoval(address[2],address[3]),
								hextoval(address[4],address[5]),
								hextoval(address[6],address[7]));
#else
		#error "No endian defined"
#endif


		return string(buf);
}


string GetDefaultRoute()
{
	string defgateway;
	list<string> fil = File::GetContent("/proc/net/route");
	fil.pop_front();
	for(auto row: fil){
		list<string> line= String::Split( row, "\t");
		if(line.size()==11){
			list<string>::iterator lIt=line.begin();
			string iface = *lIt++;
			string destination = addresstostring(*lIt++);
			string gateway = addresstostring(*lIt++);

			if( destination == "0.0.0.0" )
			{
				defgateway = gateway;
			}

		}
	}
	return defgateway;
}
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>

static string sockaddrtostring(struct sockaddr* address)
{
	string ret;
	switch( address->sa_family ){
	case AF_UNIX :
		throw runtime_error("Currently unsupported network class AF_UNIX");
		break;
	case AF_INET:
	{
		struct sockaddr_in *addr = ( struct sockaddr_in* ) address;
		return inet_ntoa( addr->sin_addr );
		break;
	}
	case AF_INET6:
		throw runtime_error("Currently unsupported network class AF_INET6");
		break;
	case AF_UNSPEC:
		throw runtime_error("Currently unsupported network class AF_UNSPEC");
		break;
	default:
		throw runtime_error("Unknown network class");
	}
	return ret;
}

string GetNetmask(const string& ifname)
{
	int ret;
	struct ifreq req;

	bzero( &req, sizeof(struct ifreq) );
	sprintf( req.ifr_name, "%s",ifname.c_str() );

	int sock = socket( AF_INET,SOCK_DGRAM, 0 );

	if( ( ret = ioctl( sock, SIOCGIFNETMASK, &req ) ) < 0 )
	{
		return "";
	}

	return sockaddrtostring( &req.ifr_netmask );
}

string GetAddress(const string& ifname)
{
		int ret;
		struct ifreq req;

		bzero( &req, sizeof( struct ifreq ) );
		sprintf( req.ifr_name, "%s", ifname.c_str() );

		int sock = socket( AF_INET,SOCK_DGRAM, 0 );

		if( ( ret = ioctl( sock, SIOCGIFADDR, &req ) ) < 0 )
		{
				return "";
		}

		return sockaddrtostring(&req.ifr_addr);
}


static bool exec(const string& cmd)
{
	int ret = system( cmd.c_str() );

	if( (ret < 0) || WEXITSTATUS(ret) != 0 )
	{
		return false;
	}

	return true;
}

bool RestartInterface(const string &ifname)
{
	const string upcmd("/sbin/ifup ");
	const string downcmd("/sbin/ifdown ");

	bool ret = exec(downcmd + ifname );

	return exec( upcmd + ifname ) && ret;
}

} // End namespace
