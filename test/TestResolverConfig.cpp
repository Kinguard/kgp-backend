#include "TestResolverConfig.h"

#include "NetworkConfig.h"

#include <fstream>
#include <unistd.h>

CPPUNIT_TEST_SUITE_REGISTRATION ( TestResolverConfig );

#define RESFILE "resolv.conf"

using namespace std;
using namespace NetUtils;

void TestResolverConfig::setUp()
{
	{
		ofstream of(RESFILE);
		of << "# A comment!\n"
				"search localdomain\n"
				"nameserver 192.168.1.10\n"
				"nameserver 192.168.1.11\n"<< endl;
		of.close();
	}
}

void TestResolverConfig::tearDown()
{
	if( unlink(RESFILE) != 0)
	{
		cerr << "Failed to file"<<endl;
	}
}

void TestResolverConfig::Test()
{
	CPPUNIT_ASSERT_NO_THROW( ResolverConfig(RESFILE));

	ResolverConfig rc(RESFILE);

	CPPUNIT_ASSERT_EQUAL( string("localdomain"), rc.getSearch());
	CPPUNIT_ASSERT_EQUAL( string(""), rc.getDomain());
	CPPUNIT_ASSERT_EQUAL( (size_t)2, rc.getNameservers().size());

}

void TestResolverConfig::TestReload()
{

	{
		ResolverConfig rc(RESFILE);
		rc.WriteConfig();
	}

	{
		ResolverConfig rc(RESFILE);
		CPPUNIT_ASSERT_EQUAL( string("localdomain"), rc.getSearch());
		CPPUNIT_ASSERT_EQUAL( string(""), rc.getDomain());
		CPPUNIT_ASSERT_EQUAL( (size_t)2, rc.getNameservers().size());

		rc.setDomain("testdomain");
		rc.setSearch("");
		rc.setNameservers( {} );
		rc.WriteConfig();
	}

	{
		ResolverConfig rc(RESFILE);
		CPPUNIT_ASSERT_EQUAL( string(""), rc.getSearch());
		CPPUNIT_ASSERT_EQUAL( string("testdomain"), rc.getDomain());
		CPPUNIT_ASSERT_EQUAL( (size_t)0, rc.getNameservers().size());

		rc.setNameservers({"192.168.1.20"});
		CPPUNIT_ASSERT_EQUAL( (size_t)1, rc.getNameservers().size());
		CPPUNIT_ASSERT_EQUAL( string("192.168.1.20"), rc.getNameservers().front());
	}
}
