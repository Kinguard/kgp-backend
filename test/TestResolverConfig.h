#ifndef TESTRESOLVERCONFIG_H_
#define TESTRESOLVERCONFIG_H_

#include <cppunit/extensions/HelperMacros.h>

class TestResolverConfig: public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE( TestResolverConfig );
	CPPUNIT_TEST( Test );
	CPPUNIT_TEST( TestReload );
	CPPUNIT_TEST_SUITE_END();
public:
	void setUp();
	void tearDown();

	void Test();
	void TestReload();
};

#endif /* TESTRESOLVERCONFIG_H_ */
