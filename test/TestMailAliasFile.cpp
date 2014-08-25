#include "TestMailAliasFile.h"

#include "MailConfig.h"

CPPUNIT_TEST_SUITE_REGISTRATION ( TestMailAliasFile );

#define TESTFILE "TMA-test"

void TestMailAliasFile::setUp()
{
	//ofstream out( TESTFILE );

	//out.close();
}

void TestMailAliasFile::tearDown()
{
	unlink( TESTFILE );
}

void TestMailAliasFile::Test()
{
	CPPUNIT_ASSERT_NO_THROW( MailAliasFile(TESTFILE) );

	MailAliasFile mf(TESTFILE);

	CPPUNIT_ASSERT_EQUAL( (size_t) 0 , mf.GetAliases().size() );

	CPPUNIT_ASSERT_THROW( mf.GetUsers("none"), runtime_error );

	CPPUNIT_ASSERT_NO_THROW( mf.AddUser("a1","u1") );
	CPPUNIT_ASSERT_NO_THROW( mf.RemoveUser("a1","u1") );
	CPPUNIT_ASSERT_THROW( mf.RemoveUser("a1","u1"),runtime_error );

	CPPUNIT_ASSERT_EQUAL( (size_t) 0 , mf.GetAliases().size() );

	CPPUNIT_ASSERT_NO_THROW( mf.AddUser("/^postmaster@/","u1@localdomain") );
	CPPUNIT_ASSERT_NO_THROW( mf.AddUser("/^postmaster@/","u2@localdomain") );
	CPPUNIT_ASSERT_NO_THROW( mf.AddUser("/^postmaster@/","u3@localdomain") );

	CPPUNIT_ASSERT_NO_THROW( mf.AddUser("/^root@/","u1@localdomain") );
	CPPUNIT_ASSERT_NO_THROW( mf.AddUser("/^root@/","u2@localdomain") );
	CPPUNIT_ASSERT_NO_THROW( mf.AddUser("/^root@/","u3@localdomain") );

	if(0) mf.Dump();

	CPPUNIT_ASSERT_EQUAL( (size_t) 2 , mf.GetAliases().size() );
	CPPUNIT_ASSERT_EQUAL( (size_t) 3, mf.GetUsers("/^postmaster@/").size() );
	CPPUNIT_ASSERT_EQUAL( (size_t) 3, mf.GetUsers("/^root@/").size() );

	mf.WriteConfig();
	mf.ReadConfig();

	CPPUNIT_ASSERT_EQUAL( (size_t) 2 , mf.GetAliases().size() );
	CPPUNIT_ASSERT_EQUAL( (size_t) 3, mf.GetUsers("/^postmaster@/").size() );
	CPPUNIT_ASSERT_EQUAL( (size_t) 3, mf.GetUsers("/^root@/").size() );

}
