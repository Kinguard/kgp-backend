#ifndef TESTFETCHMAILCONFIG_H_
#define TESTFETCHMAILCONFIG_H_

#include <cppunit/extensions/HelperMacros.h>

class TestFetchmailConfig: public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE( TestFetchmailConfig );
	CPPUNIT_TEST( TestBasicUsage );
	CPPUNIT_TEST( TestErrorCases );
	CPPUNIT_TEST_SUITE_END();
public:
	void setUp();
	void tearDown();

	void TestBasicUsage();
	void TestErrorCases();
};

#endif /* TESTFETCHMAILCONFIG_H_ */
