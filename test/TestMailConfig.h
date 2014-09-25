#ifndef TESTMAILCONFIG_H_
#define TESTMAILCONFIG_H_

#include <cppunit/extensions/HelperMacros.h>

class TestMailConfig: public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE( TestMailConfig );
	CPPUNIT_TEST( TestDomain );
	CPPUNIT_TEST( TestAddress  );
	CPPUNIT_TEST( TestChange  );
	CPPUNIT_TEST( TestRemove );
	CPPUNIT_TEST_SUITE_END();
public:
	void setUp();
	void tearDown();

	void TestDomain();
	void TestAddress();
	void TestChange();
	void TestRemove();
};

#endif /* TESTMAILCONFIG_H_ */
