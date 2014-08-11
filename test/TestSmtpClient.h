#ifndef TESTSMTPCLIENT_H_
#define TESTSMTPCLIENT_H_

#include <cppunit/extensions/HelperMacros.h>

class TestSmtpClient: public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE( TestSmtpClient );
	CPPUNIT_TEST( Test );
	CPPUNIT_TEST_SUITE_END();
public:
	void setUp();
	void tearDown();

	void Test();
};

#endif /* TESTSMTPCLIENT_H_ */
