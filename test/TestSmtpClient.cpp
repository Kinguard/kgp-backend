#include <unistd.h>
#include <fstream>


#include "TestSmtpClient.h"

#include "SmtpClientConfig.h"

CPPUNIT_TEST_SUITE_REGISTRATION ( TestSmtpClient );

#define SMTPSASL	"smtpsaslpasswd.txt"

void TestSmtpClient::setUp()
{
	ofstream out(SMTPSASL);

	out
			<< "[mail.mysmtp.com]:587   myuser:password\n"
			<< "[my.other.site]   luser:pwd\n"
			<< "my.last.site    lsads:\n"
			<< "one.more  :kalle\n"
			<< "mailcluster.loopia.se:587       totte:secret\n";

	out.close();
}

void TestSmtpClient::tearDown()
{
	unlink(SMTPSASL);
	unlink( SMTPSASL ".db");
}

class TestPostconf: public PostConfInterface
{
public:
	TestPostconf(const string& relay, bool enabled)
	{
		this->relayhost = relay;
		this->enable = enabled;
	}

	virtual void ReadConfig(){}

	virtual void WriteConfig(){}
};

void TestSmtpClient::Test()
{

	CPPUNIT_ASSERT_NO_THROW( SmtpClientConfig scfg(SMTPSASL, PostConfInterfacePtr( new TestPostconf("one.more",true) ) ) );

	SmtpClientConfig scfg(SMTPSASL, PostConfInterfacePtr( new TestPostconf("one.more",true) ) );

	CPPUNIT_ASSERT_NO_THROW( scfg.SetConfig( { true, "myisp.com", "", "user","password"}) );

	CPPUNIT_ASSERT_NO_THROW( scfg.WriteConfig() );

	CPPUNIT_ASSERT_NO_THROW( scfg.ReadConfig() );

	passwdline res = scfg.GetConfig();

	CPPUNIT_ASSERT_EQUAL( true, res.enabled );
	CPPUNIT_ASSERT_EQUAL( string("myisp.com"),	res.host );
	CPPUNIT_ASSERT_EQUAL( string(""),			res.port );
	CPPUNIT_ASSERT_EQUAL( string("user"),		res.user );
	CPPUNIT_ASSERT_EQUAL( string("password"),	res.pass );


	//scfg.dump();

}
