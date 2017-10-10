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

#include "osquery/core/json.h"

namespace osquery {
namespace tables {

/// Text that can identify a Chef role in a run list item.
extern const std::string kChefRoleSearchTerm;

/// Text that can identify a Chef recipe in a run list item.
extern const std::string kChefRecipeSearchTerm;

/// Structural representation of a Chef run list item.
struct ChefRunListItem {
  std::string name;
  rapidjson::SizeType seqNum;
};

/// Structural representation of a Chef run list.
struct ChefRunList {
  std::vector<ChefRunListItem> roles;
  std::vector<ChefRunListItem> recipes;
};

/**
 * @brief checks if run list item is a Chef role and extracts the role name.
 *
 * @param item std::string of run list item; should be white space stripped.
 * @param name ref to std::string container for storing the parsed name.
 *
 * @return bool indicating whether item was a Chef role.
 */
bool isRole(const std::string& item, std::string& name);

/**
 * @brief checks if run list item is a recipe and extracts the recipe name.
 *
 * @param item std::string of run list item; should be white space stripped.
 * @param name ref to std::string container for storing the parsed name.
 *
 * @return bool indicating whether item was a Chef recipe.
 */
bool isRecipe(const std::string& item, std::string& name);

/**
 * @brief parses a rapidjson::Document of first-boot-json into ChefRunList.
 *
 * @param doc rapidjson::Document representation of first-boot-json.
 * @param runlist ref to ChefRunList struct where results will be stored.
 *
 * @return bool indicating whether item was a Chef role.
 */
void parseRunList(rapidjson::Document& doc, ChefRunList& runlist);
} // namespace tables
} // namespace osquery
