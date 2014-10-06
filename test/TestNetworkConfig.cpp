#include "TestNetworkConfig.h"

#include "NetworkConfig.h"

#include <fstream>
#include <unistd.h>

#include <libutils/FileUtils.h>

CPPUNIT_TEST_SUITE_REGISTRATION ( TestNetworkConfig );

#define IFFILE "interfaces"

using namespace Utils;
using namespace NetUtils;

void TestNetworkConfig::setUp()
{
	{
		ofstream of(IFFILE ".1");
		of << "# This is a comment\n"
			  "  auto lo eth0\n"
			  "iface eth0 inet dhcp  \n"
			  "iface eth1 inet static \n"
			  "\taddress 192.168.1.122\n"
			  "\tgateway 192.168.1.1\n"
			  "\tnetmask 255.255.255.0\n"
			  "iface lo inet loopback\n"<< endl;
		of.close();
	}

	{
		ofstream of(IFFILE ".2");
		of << "# This is a comment\n"
			  "  auto lo eth0\n"
			  "iface eth0 inet static  \n"
			  "\taddress 192.168.1.122\n"
			  "\tgateway 192.168.1.1\n"
			  "\tnetmask 255.255.255.0\n"
			  "iface lo inet loopback\n"<< endl;
		of.close();
	}
}

void TestNetworkConfig::tearDown()
{
	if( unlink(IFFILE ".1") != 0)
	{
		cerr << "Failed to file"<<endl;
	}

	if( unlink(IFFILE ".2") != 0)
	{
		cerr << "Failed to erase file"<<endl;
	}
}

void TestNetworkConfig::Test()
{
	CPPUNIT_ASSERT_THROW( NetworkConfig(IFFILE), std::runtime_error );

	CPPUNIT_ASSERT_NO_THROW( NetworkConfig(IFFILE ".1") );
	CPPUNIT_ASSERT_NO_THROW( NetworkConfig(IFFILE ".2") );

	{
		NetworkConfig nc(IFFILE ".1");
		nc.Dump();
		nc.WriteConfig();

		CPPUNIT_ASSERT_THROW( nc.GetInterface("noifs"), std::runtime_error );

		Json::Value ifs = nc.GetInterfaces();

		CPPUNIT_ASSERT_EQUAL( (unsigned int)3, ifs.size() );

		CPPUNIT_ASSERT( ifs.isMember("lo") );
		CPPUNIT_ASSERT( ifs.isMember("eth0") );
		CPPUNIT_ASSERT( ifs.isMember("eth1") );

		CPPUNIT_ASSERT( ifs["lo"]["auto"].asBool() );
		CPPUNIT_ASSERT( ifs["eth0"]["auto"].asBool() );
		CPPUNIT_ASSERT( ! ifs["eth1"]["auto"].asBool() );

		CPPUNIT_ASSERT_EQUAL( string("192.168.1.122"), ifs["eth1"]["options"]["address"][(uint)0].asString() );

	}


	{
		NetworkConfig nc(IFFILE ".2");
		//nc.Dump();
		nc.WriteConfig();
	}
}

void TestNetworkConfig::TestReload()
{

	{
		NetworkConfig nc(IFFILE ".1");
		Json::Value ifs = nc.GetInterfaces();
		CPPUNIT_ASSERT_EQUAL(string("static"), ifs["eth1"]["addressing"].asString() );
		nc.SetDHCP("eth1");
		nc.WriteConfig();
	}

	{
		NetworkConfig nc(IFFILE ".1");
		Json::Value ifs = nc.GetInterfaces();
		CPPUNIT_ASSERT_EQUAL(string("dhcp"), ifs["eth1"]["addressing"].asString() );
		nc.SetStatic("eth1", "10.0.0.1", "1.2.3.4", "1.1.1.1");
		nc.WriteConfig();
	}


	{
		NetworkConfig nc(IFFILE ".1");
		Json::Value ifs = nc.GetInterfaces();
		CPPUNIT_ASSERT_EQUAL(string("static"), ifs["eth1"]["addressing"].asString() );
		CPPUNIT_ASSERT_EQUAL(string("10.0.0.1"), ifs["eth1"]["options"]["address"][(uint)0].asString() );
		CPPUNIT_ASSERT_EQUAL(string("1.2.3.4"), ifs["eth1"]["options"]["netmask"][(uint)0].asString() );
		CPPUNIT_ASSERT_EQUAL(string("1.1.1.1"), ifs["eth1"]["options"]["gateway"][(uint)0].asString() );

		CPPUNIT_ASSERT( ifs.isMember("lo") );
		CPPUNIT_ASSERT( ifs.isMember("eth0") );
		CPPUNIT_ASSERT( ifs.isMember("eth1") );

		CPPUNIT_ASSERT( ifs["lo"]["auto"].asBool() );
		CPPUNIT_ASSERT( ifs["eth0"]["auto"].asBool() );
		CPPUNIT_ASSERT( ifs["eth1"]["auto"].asBool() );

	}

}

void TestNetworkConfig::TestDefaultRoute()
{
	CPPUNIT_ASSERT( string("") != NetUtils::GetDefaultRoute() );
}

void TestNetworkConfig::TestNetmask()
{
	CPPUNIT_ASSERT_EQUAL( string(""), NetUtils::GetNetmask("NoInterface") );
	CPPUNIT_ASSERT( string("") != NetUtils::GetNetmask("eth0") );
}

void TestNetworkConfig::TestAddress()
{
	CPPUNIT_ASSERT_EQUAL( string(""), NetUtils::GetAddress("NoInterface") );
	CPPUNIT_ASSERT( string("") != NetUtils::GetAddress("eth0") );
}
