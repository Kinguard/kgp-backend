#ifndef TESTMAILALIASFILE_H_
#define TESTMAILALIASFILE_H_

#include <cppunit/extensions/HelperMacros.h>

class TestMailAliasFile: public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE( TestMailAliasFile );
	CPPUNIT_TEST( Test );
	CPPUNIT_TEST_SUITE_END();
public:
	void setUp();
	void tearDown();

	void Test();
};

#endif /* TESTMAILALIASFILE_H_ */
