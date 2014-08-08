#ifndef TESTFETCHMAILCONFIG_H_
#define TESTFETCHMAILCONFIG_H_

#include <cppunit/extensions/HelperMacros.h>

class TestFetchmailConfig: public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE( TestFetchmailConfig );
	CPPUNIT_TEST( Test );
	CPPUNIT_TEST_SUITE_END();
public:
	void setUp();
	void tearDown();

	void Test();
};

#endif /* TESTFETCHMAILCONFIG_H_ */
