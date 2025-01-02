#include <gtest/gtest.h>

#include <map>
#include <unordered_map>
#include <login/accountdb/accountdbsql.hpp>

class AccountDbSqlTest : public ::testing::Test {
 protected:
  AccountDbSqlTest() {
    // You can do set-up work for each test here.
  }

  AccountDbSql accountDbSql;
};

TEST_F(AccountDbSqlTest, setProperties) {
    ASSERT_TRUE(accountDbSql.setProperty("login_server_ip", "127.0.0.1"));
    ASSERT_TRUE(accountDbSql.setProperty("login_server_port", "3306"));
    ASSERT_TRUE(accountDbSql.setProperty("login_server_id", "root"));
    ASSERT_TRUE(accountDbSql.setProperty("login_server_pw", "password"));
    ASSERT_TRUE(accountDbSql.setProperty("login_server_db", "rathena"));
    ASSERT_TRUE(accountDbSql.setProperty("login_server_account_db", "account"));
    ASSERT_TRUE(accountDbSql.setProperty("login_server_global_acc_reg_str_table", "global_acc_reg_str"));
    ASSERT_TRUE(accountDbSql.setProperty("login_server_global_acc_reg_num_table", "global_acc_reg_num"));
    ASSERT_TRUE(accountDbSql.setProperty("login_codepage", "UTF-8"));
    ASSERT_TRUE(accountDbSql.setProperty("login_case_sensitive", "true"));

    ASSERT_FALSE(accountDbSql.setProperty("invalid_key", "invalid_value"));
    ASSERT_FALSE(accountDbSql.setProperty("login_server__key", "invalid_value"));
    ASSERT_FALSE(accountDbSql.setProperty("login_invalid_key", "invalid_value"));

    // Test override (e.g. import)
    ASSERT_TRUE(accountDbSql.setProperty("login_server_ip", "db"));

}
