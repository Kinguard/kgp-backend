#include "TestJson.h"

#include <nlohmann/json.hpp>
#include <iostream>

using namespace std;

using json = nlohmann::json;

CPPUNIT_TEST_SUITE_REGISTRATION ( TestJson );

const char *jsstr = "{\"packages\" : {\"keep\":{ \"version\":\"\", \"status\": \"un\"},"
					"\"opi-backend\":{ \"version\":\"1.15.2~test5\", \"status\": \"ii\"},"
					"\"opi-control\":{ \"version\":\"1.1.66~test2\", \"status\": \"ii\"},"
					"\"opi-webfrontend\":{ \"version\":\"1.99~test3\", \"status\": \"ii\"},"""
					"\"opi-webbackend\":{ \"version\":\"1.48\", \"status\": \"ii\"},"
					"\"opi-backup\":{ \"version\":\"2.3.46\", \"status\": \"ii\"},"
					"\"nextcloud\":{ \"version\":\"\", \"status\": \"un\"},"
					"\"nextcloud16\":{ \"version\":\"16.0.5-1\", \"status\": \"ii\"},"
					"\"roundcubemail\":{ \"version\":\"1.3.10-1\", \"status\": \"ii\"},"
					"\"nc-calendar\":{ \"version\":\"1.5.8-3\", \"status\": \"rc\"},"
					"\"nc-calendar14\":{ \"version\":\"1.6.6-1\", \"status\": \"rc\"},"
					"\"nc-contacts\":{ \"version\":\"2.1.5-3\", \"status\": \"rc\"},"
					"\"nc-contacts14\":{ \"version\":\"2.1.8-1\", \"status\": \"rc\"},"
					"\"nc-tasks\":{ \"version\":\"0.9.6-4\", \"status\": \"rc\"},"
					"\"nc-tasks14\":{ \"version\":\"0.9.8-1\", \"status\": \"rc\"}}}";

void TestJson::setUp()
{
}

void TestJson::tearDown()
{
}

void TestJson::Test()
{
	json v, ret;

	CPPUNIT_ASSERT_NO_THROW( v = json::parse(jsstr) );

	CPPUNIT_ASSERT(v.contains("packages"));
	CPPUNIT_ASSERT( v["packages"].is_object() );

	for( const auto& member: v["packages"].items() )
	{
		json pkg = member.value();
		cout << "pkg:" << pkg.dump(4) << endl;

		if(pkg["status"].get<string>() == "un" )
		{
			// Skip all uninstalled packages
			continue;
		}
		ret["packages"][member.key()] = pkg["version"].get<string>() + string(" (")+pkg["status"].get<string>()+string(")");

	}



	// std::cout << ret.toStyledString() << std::endl;
}


