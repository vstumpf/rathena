#include <gtest/gtest.h>

#include <map>
#include <unordered_map>
#include <common/utilities.hpp>

class UtilitiesTest : public ::testing::Test {
 protected:
  // You can remove any or all of the following functions if its body
  // is empty.

  UtilitiesTest() {
    // You can do set-up work for each test here.
    map[1] = 2;
    map[2] = 4;
    map[3] = 6;
    map[4] = 8;

    umap[1] = 2;
    umap[2] = 4;
    umap[3] = 6;
    umap[4] = 8;

    map_ptr[1] = std::make_shared<int>(2);
    map_ptr[2] = std::make_shared<int>(4);
    map_ptr[3] = std::make_shared<int>(6);
    map_ptr[4] = std::make_shared<int>(8);

    umap_ptr[1] = std::make_shared<int>(2);
    umap_ptr[2] = std::make_shared<int>(4);
    umap_ptr[3] = std::make_shared<int>(6);
    umap_ptr[4] = std::make_shared<int>(8);
  }

  // Objects declared here can be used by all tests in the test case for Foo.
  std::map<int, int> map;
  std::unordered_map<int, int> umap;

  std::map<int, std::shared_ptr<int>> map_ptr;
  std::unordered_map<int, std::shared_ptr<int>> umap_ptr;

  std::vector<int> vec{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
};

using namespace rathena::util;

// Demonstrate some basic assertions.
TEST_F(UtilitiesTest, MapFunctions) {
  EXPECT_EQ(map_exists(map, 1), true);
  EXPECT_EQ(map_exists(map, 10), false);

  auto res = map_find(map, 1);
  EXPECT_NE(res, nullptr);
  EXPECT_EQ(*res, 2);
  EXPECT_EQ(map_find(map, 10), nullptr);

  auto res_ptr = map_find(map_ptr, 1);
  EXPECT_NE(res_ptr, nullptr);
  EXPECT_EQ(*res_ptr, 2);
  EXPECT_EQ(map_find(map_ptr, 10), nullptr);

  EXPECT_EQ(map_get(map, 1, 0), 2);
  EXPECT_EQ(map_get(map, 10, 0), 0);
}

TEST_F(UtilitiesTest, UMapFunctions) {
  auto res = umap_find(umap, 1);
  EXPECT_NE(res, nullptr);
  EXPECT_EQ(*res, 2);
  EXPECT_EQ(umap_find(umap, 10), nullptr);

  auto res_ptr = umap_find(umap_ptr, 1);
  EXPECT_NE(res_ptr, nullptr);
  EXPECT_EQ(*res_ptr, 2);
  EXPECT_EQ(umap_find(umap_ptr, 10), nullptr);

  EXPECT_EQ(umap_get(umap, 1, 0), 2);
  EXPECT_EQ(umap_get(umap, 10, 0), 0);

  auto random = umap_random(umap);
  auto it = std::find_if(umap.begin(), umap.end(), [random](const auto& pair) {
    return pair.second == random;
  });

  EXPECT_NE(it, umap.end());
}

TEST_F(UtilitiesTest, VectorFunctions) {
  auto random = vector_random(vec);
  auto it = std::find(vec.begin(), vec.end(), random);
  EXPECT_NE(it, vec.end());

  EXPECT_NE(vector_get(vec, 1), vec.end());
  EXPECT_EQ(vector_get(vec, 11), vec.end());

  EXPECT_EQ(vector_exists(vec, 1), true);
  EXPECT_EQ(vector_exists(vec, 11), false);

  vector_erase_if_exists(vec, 1);
  EXPECT_EQ(vec.size(), 9);
  EXPECT_EQ(vector_get(vec, 1), vec.end());
  
  vector_erase_if_exists(vec, 11);
  EXPECT_EQ(vec.size(), 9);
  EXPECT_EQ(vector_get(vec, 11), vec.end());
}