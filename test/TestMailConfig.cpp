
#include <fstream>
#include <algorithm>

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

	{
		ofstream of("domains");
		of << "kalle.com"<<endl;
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

void TestMailConfig::TestChange()
{
	MailConfig mc("ok.fil","domains");
	CPPUNIT_ASSERT_NO_THROW( mc.ReadConfig());

	if( 0 ){
		list<string> doms = mc.GetDomains();
		for(auto x: doms) cout << x<<endl;
		list<tuple<string, string> > addresses = mc.GetAddresses("kalle.com");
		for(tuple<string,string> adress: addresses )
		{
			cout << get<0>(adress) <<" "<< get<1>(adress)<< endl;
		}
	}

	CPPUNIT_ASSERT_THROW( mc.ChangeDomain("none","none"), runtime_error);
	CPPUNIT_ASSERT_THROW( mc.ChangeDomain("kalle.com","kalle.com"), runtime_error);
	CPPUNIT_ASSERT_THROW( mc.ChangeDomain("",""), runtime_error);
	CPPUNIT_ASSERT_THROW( mc.ChangeDomain("","kalle.com"), runtime_error);
	CPPUNIT_ASSERT_THROW( mc.ChangeDomain("kalle.com",""), runtime_error);

	CPPUNIT_ASSERT_NO_THROW( mc.ChangeDomain("kalle.com","hobbe.com"));
	mc.SetAddress("hobbe.com","kalle","test");
	mc.WriteConfig();
	mc.ReadConfig();
	CPPUNIT_ASSERT_THROW( mc.GetAddresses("kalle.com"), runtime_error );
	CPPUNIT_ASSERT_NO_THROW( mc.GetAddresses("hobbe.com") );
	CPPUNIT_ASSERT_NO_THROW( mc.ChangeDomain("hobbe.com","kalle.com"));
	CPPUNIT_ASSERT_THROW( mc.GetAddresses("hobbe.com"), runtime_error );
	CPPUNIT_ASSERT_NO_THROW( mc.GetAddresses("kalle.com") );
	mc.WriteConfig();
	mc.ReadConfig();
	CPPUNIT_ASSERT_NO_THROW( mc.ChangeDomain("kalle.com","hobbe.com"));

	list<tuple<string, string> > addresses = mc.GetAddresses("hobbe.com");
	CPPUNIT_ASSERT( find( addresses.begin(), addresses.end(), tuple<string,string>("kalle","test")  ) != addresses.end() );
	CPPUNIT_ASSERT( find( addresses.begin(), addresses.end(), tuple<string,string>("test","test")  ) != addresses.end() );

	if(0){
		list<tuple<string, string> > addresses = mc.GetAddresses("hobbe.com");
		for(tuple<string,string> adress: addresses )
		{
			cout << get<0>(adress) <<" "<< get<1>(adress)<< endl;
		}
	}
}

// For bug #114 - Domänfil rensas aldrig
void TestMailConfig::TestRemove()
{
	MailConfig mc("ok.fil");
	CPPUNIT_ASSERT_NO_THROW( mc.ReadConfig());
	mc.WriteConfig();

	list<tuple<string,string>> adrs = mc.GetAddresses("kalle.com");
	CPPUNIT_ASSERT_EQUAL( (size_t) 1, adrs.size() );

	//cout << get<0>(adrs.front()) << get<1>(adrs.front()) <<endl;

	mc.DeleteAddress("kalle.com","test");
	mc.WriteConfig();

	CPPUNIT_ASSERT_EQUAL( string(), File::GetContentAsString("domains") );

}
