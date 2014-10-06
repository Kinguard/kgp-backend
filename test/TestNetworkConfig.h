#ifndef TESTNETWORKCONFIG_H_
#define TESTNETWORKCONFIG_H_

#include <cppunit/extensions/HelperMacros.h>

class TestNetworkConfig: public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE( TestNetworkConfig );
	CPPUNIT_TEST( Test );
	CPPUNIT_TEST( TestReload );
	CPPUNIT_TEST( TestNetmask );
	CPPUNIT_TEST( TestAddress );
	CPPUNIT_TEST( TestDefaultRoute );
	CPPUNIT_TEST_SUITE_END();
public:
	void setUp();
	void tearDown();

	void Test();
	void TestReload();
	void TestNetmask();
	void TestAddress();
	void TestDefaultRoute();
};

#endif /* TESTNETWORKCONFIG_H_ */
