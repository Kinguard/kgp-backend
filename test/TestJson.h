#ifndef TESTJSON_H_
#define TESTJSON_H_

#include <cppunit/extensions/HelperMacros.h>

class TestJson: public CppUnit::TestFixture
{
	CPPUNIT_TEST_SUITE( TestJson );
	CPPUNIT_TEST( Test );
	CPPUNIT_TEST_SUITE_END();
public:
	void setUp();
	void tearDown();
	void Test();
};

#endif /* TESTJSON_H_ */
