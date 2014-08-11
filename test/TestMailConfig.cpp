
#include <fstream>

#include "Config.h"

#include "TestMailConfig.h"

#include "MailConfig.h"

CPPUNIT_TEST_SUITE_REGISTRATION ( TestMailConfig );

void TestMailConfig::setUp()
{
	unlink("domains");
	unlink("vmailbox");

	{
		ofstream of("error.fil");
		of << "Detta är ett test!"<<endl;
		of.close();
	}

	{
		ofstream of("ok.fil");
		of << "test@kalle.com\ttest/mail/\n";
		of.close();
	}

	//exit(0);
}

void TestMailConfig::tearDown()
{
	if( unlink("error.fil") != 0)
	{
		cerr << "Failed to erase error file"<<endl;
	}

	if( unlink("ok.fil") != 0 )
	{
		cerr << "Failed to erase error file"<<endl;
	}
	unlink("domains");
	unlink("vmailbox");
}

void TestMailConfig::TestDomain()
{
	{
		MailConfig* mc;
		CPPUNIT_ASSERT_THROW( mc = new MailConfig("error.fil"), runtime_error );
	}

	{
		MailConfig mc("ok.fil","domains");
		CPPUNIT_ASSERT_NO_THROW( mc.ReadConfig());

		list<string> doms = mc.GetDomains();
		//for(auto x: doms) cout << x<<endl;
		CPPUNIT_ASSERT_EQUAL( (size_t)1, doms.size() );

		CPPUNIT_ASSERT_EQUAL( doms.front(), string("kalle.com"));

		mc.AddDomain("test.com");
		CPPUNIT_ASSERT_EQUAL( (size_t)2, mc.GetDomains().size() );
		CPPUNIT_ASSERT_NO_THROW( mc.AddDomain("test.com"));
		CPPUNIT_ASSERT_EQUAL( (size_t)2, mc.GetDomains().size() );

		CPPUNIT_ASSERT_NO_THROW( mc.AddDomain("test2.com"));
		CPPUNIT_ASSERT_EQUAL( (size_t)3, mc.GetDomains().size() );

		CPPUNIT_ASSERT_NO_THROW( mc.DeleteDomain("test.com"));
		CPPUNIT_ASSERT_EQUAL( (size_t)2, mc.GetDomains().size() );

		CPPUNIT_ASSERT_THROW( mc.DeleteDomain("test.com"), runtime_error);
		CPPUNIT_ASSERT_EQUAL( (size_t)2, mc.GetDomains().size() );

		mc.DeleteDomain("test2.com");
		mc.DeleteDomain("kalle.com");
		CPPUNIT_ASSERT_EQUAL( (size_t)0, mc.GetDomains().size() );

		mc.WriteConfig();
		mc.ReadConfig();
		CPPUNIT_ASSERT_EQUAL( (size_t)0, mc.GetDomains().size() );
		mc.AddDomain("krill.nu");
		mc.WriteConfig();
		mc.ReadConfig();
		mc.AddDomain("krill2.nu");
		mc.WriteConfig();
		CPPUNIT_ASSERT_EQUAL( (size_t)2, mc.GetDomains().size() );
	}
}

void TestMailConfig::TestAddress()
{
	MailConfig mc("ok.fil");
	CPPUNIT_ASSERT_NO_THROW( mc.ReadConfig());

	list<tuple<string,string>> adrs = mc.GetAddresses("kalle.com");
	CPPUNIT_ASSERT_EQUAL( (size_t) 1, adrs.size() );

	CPPUNIT_ASSERT_THROW( mc.GetAddresses("none.domain"), runtime_error);

	CPPUNIT_ASSERT_NO_THROW( mc.SetAddress("kalle.com", "bengt","tor") );
	CPPUNIT_ASSERT_EQUAL( (size_t) 2, mc.GetAddresses("kalle.com").size() );
	CPPUNIT_ASSERT_NO_THROW( mc.SetAddress("kalle.com", "bengt","tor") );
	CPPUNIT_ASSERT_EQUAL( (size_t) 2, mc.GetAddresses("kalle.com").size() );

	CPPUNIT_ASSERT_NO_THROW( mc.SetAddress("kalle.com", "sven","tor") );
	CPPUNIT_ASSERT_EQUAL( (size_t) 3, mc.GetAddresses("kalle.com").size() );

	CPPUNIT_ASSERT_THROW( mc.DeleteAddress("none.domain","noneaddress"), runtime_error);
	CPPUNIT_ASSERT_THROW( mc.DeleteAddress("kalle.com","noneaddress"), runtime_error);
	CPPUNIT_ASSERT_THROW( mc.DeleteAddress("kalle.com",""), runtime_error);
	CPPUNIT_ASSERT_THROW( mc.DeleteAddress("","noneaddress"), runtime_error);
	CPPUNIT_ASSERT_THROW( mc.DeleteAddress("",""), runtime_error);

	CPPUNIT_ASSERT_NO_THROW( mc.DeleteAddress("kalle.com", "sven") );
	CPPUNIT_ASSERT_EQUAL( (size_t) 2, mc.GetAddresses("kalle.com").size() );

	CPPUNIT_ASSERT_NO_THROW( mc.SetAddress("krill.nu", "tor","tor") );

	CPPUNIT_ASSERT_NO_THROW( mc.WriteConfig() );

	CPPUNIT_ASSERT_NO_THROW( mc.ReadConfig() );

	adrs = mc.GetAddresses("kalle.com");
	CPPUNIT_ASSERT_EQUAL( (size_t) 2, adrs.size() );
#if 0
	for( auto adr: adrs)
	{
		string add, usr;
		tie(add,usr) = adr;
		cout << "Adress "<< add << " user "<<usr<<endl;
	}
#endif
	string add, usr;
	tie(add,usr) = adrs.front();
	CPPUNIT_ASSERT_EQUAL(string("bengt"), add);
}
