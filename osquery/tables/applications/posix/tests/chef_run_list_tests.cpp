/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "osquery/tables/applications/posix/chef_run_list.h"

namespace osquery {
namespace tables {

class ChefRunListTest : public ::testing::Test {};

TEST_F(ChefRunListTest, is_role_happy_path) {
  struct testCase {
    std::string inputItem;
    std::string expectedName;
  };

  std::vector<testCase> happyPathTests = {
      {"role[foobar]", "foobar"},
      {"role[testing123]", "testing123"},
      {"role[recipe_fake]", "recipe_fake"},
  };

  for (const auto& test : happyPathTests) {
    std::string name = "";
    bool found = isRole(test.inputItem, name);

    EXPECT_TRUE(found);
    EXPECT_EQ(name, test.expectedName);
  }
}

TEST_F(ChefRunListTest, is_recipe_happy_path) {
  struct testCase {
    std::string inputItem;
    std::string expectedName;
  };

  std::vector<testCase> happyPathTests = {
      {"recipe[foobar]", "foobar"},
      {"Foo::Bar", "Foo::Bar"},
      {"recipe[Bar::Foo]", "Bar::Foo"},
      {"blah123", "blah123"},
      {"role123", "role123"},
  };

  for (const auto& test : happyPathTests) {
    std::string name = "";
    bool found = isRecipe(test.inputItem, name);

    EXPECT_TRUE(found);
    EXPECT_EQ(name, test.expectedName);
  }
}

TEST_F(ChefRunListTest, is_role_negative_path) {
  std::vector<std::string> negativeTests = {
      "recipe[foobar]", "recipe[role[foobar]]", "Some::Recipe", "some_recipe",
  };

  for (const auto& test : negativeTests) {
    std::string _ = "";
    bool found = isRole(test, _);

    EXPECT_FALSE(found);
  }
}

TEST_F(ChefRunListTest, is_recipe_negative_path) {
  std::vector<std::string> negativeTests = {
      "role[foobar]", "role[recipe[foobar]]", "role[Some::Recipe]",
  };

  for (const auto& test : negativeTests) {
    std::string _ = "";
    bool found = isRecipe(test, _);

    EXPECT_FALSE(found);
  }
}

bool operator!=(const ChefRunListItem& lhs, const ChefRunListItem& rhs) {
  if (lhs.seqNum != rhs.seqNum || lhs.name != rhs.name) {
    return true;
  }

  return false;
}

bool operator==(const ChefRunList& lhs, const ChefRunList& rhs) {
  if (lhs.roles.size() != rhs.roles.size() ||
      lhs.recipes.size() != rhs.recipes.size()) {
    return false;
  }

  for (size_t i = 0; i < lhs.roles.size(); i++) {
    if (lhs.roles[i] != rhs.roles[i]) {
      return false;
    }
  }

  for (size_t i = 0; i < lhs.recipes.size(); i++) {
    if (lhs.recipes[i] != rhs.recipes[i]) {
      return false;
    }
  }

  return true;
}

TEST_F(ChefRunListTest, parse_run_list) {
  struct testCase {
    const char* inputJSON;
    ChefRunList expected;
  };

  std::vector<testCase> tests = {
      {
          // inputJSON
          "{\"run_list\": [\"role[foo]\"]}",
          // ChefRunList
          {
              {{"foo", 0}}, // roles
              {}, // recipes
          },
      },

      {
          // inputJSON
          "{\"run_list\":[\"role[foo]\", \"recipe[bar]\", "
          "\"Foo::Bar\"]}",
          // ChefRunList
          {
              {{"foo", 0}}, // roles
              {{"bar", 1}, {"Foo::Bar", 2}}, // recipes
          },
      },

      {
          // inputJSON
          "{\"run_list\":[\"role[foo]\", \"recipe[bar]\", "
          "\"Foo::Bar\", \"role[oof]\", \"Rab::Oof\"]}",
          // ChefRunList
          {
              {{"foo", 0}, {"oof", 3}}, // roles
              {{"bar", 1}, {"Foo::Bar", 2}, {"Rab::Oof", 4}}, // recipes
          },
      },
      // Tests that expect empty ChefRunList.
      // No "run_list" member.
      {
          // inputJSON
          "{\"not_run_list\":[\"role[foo]\", \"recipe[bar]\", "
          "\"Foo::Bar\", \"role[oof]\", \"Rab::Oof\"]}",
          // ChefRunList
          {
              {}, // roles
              {}, // recipes
          },
      },
      // "run_list" is not an array type.
      {
          // inputJSON
          "{\"run_list\":{\"foo\": \"bar\"}}",
          // ChefRunList
          {
              {}, // roles
              {}, // recipes
          },
      },
      // "run_list" members are not strings.
      {
          // inputJSON
          "{\"run_list\":[1, 2, 3, 4, 5]}",
          // ChefRunList
          {
              {}, // roles
              {}, // recipes
          },
      },
  };

  for (const auto& test : tests) {
    rapidjson::Document d;
    d.Parse(test.inputJSON);
    ChefRunList rl;

    parseRunList(d, rl);

    EXPECT_EQ(rl, test.expected);
  }
}

} // namespace tables
} // namespace osquery
