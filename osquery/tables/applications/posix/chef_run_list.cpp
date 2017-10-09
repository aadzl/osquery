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

#include <boost/algorithm/string/trim.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/json.h"

namespace osquery {
namespace tables {

static const std::string kChefFirstBootJSON = "/etc/chef/first-boot.json";

static const std::string kChefRoleSearchTerm = "role[";
static const std::string kChefRecipeSearchTerm = "recipe[";

struct ChefRunListItem {
  std::string name;
  rapidjson::SizeType seqNum;
};

struct ChefRunList {
  std::vector<ChefRunListItem> roles;
  std::vector<ChefRunListItem> recipes;
};

static inline rapidjson::Document getFirstBootJson(const std::string& path) {
  rapidjson::Document d;

  if (!pathExists(path).ok()) {
    return d;
  }

  std::string content;
  if (!readFile(path, content).ok()) {
    return d;
  }

  d.Parse(content.c_str());

  return d;
}

static inline bool isRole(const std::string& item, std::string& name) {
  if (item.find(kChefRoleSearchTerm) != 0) {
    return false;
  }

  name = item.substr(kChefRoleSearchTerm.length(),
                     item.length() - kChefRoleSearchTerm.length() - 1);
  return true;
}

static inline bool isRecipe(const std::string& item, std::string& name) {
  if (item.find(kChefRecipeSearchTerm) == 0) {
    name = item.substr(kChefRecipeSearchTerm.length(),
                       item.length() - kChefRecipeSearchTerm.length() - 1);
    return true;
  }

  if (item.find(kChefRoleSearchTerm) != 0) {
    name = item;
    return true;
  }

  return false;
}

static void parseRunList(rapidjson::Document&& doc, ChefRunList& runlist) {
  if (!doc.HasMember("run_list")) {
    return;
  }

  if (!doc["run_list"].IsArray()) {
    LOG(WARNING)
        << "Did not get array type for 'run_list' field of 'first-boot.json'";
    return;
  }

  auto rl = doc["run_list"].GetArray();
  for (rapidjson::SizeType i = 0; i < rl.Size(); i++) {
    if (!rl[i].IsString()) {
      LOG(WARNING) << "Did not get string type for Chef run_list member number "
                   << i;
      continue;
    }

    std::string item = rl[i].GetString();
    boost::algorithm::trim(item);
    ChefRunListItem rlItem = {"", i};

    if (isRole(item, rlItem.name)) {
      runlist.roles.push_back(rlItem);

    } else if (isRecipe(item, rlItem.name)) {
      runlist.recipes.push_back(rlItem);
    }
  }
}

QueryData genChefRunList(QueryContext& context) {
  QueryData results;

  ChefRunList rl;
  parseRunList(getFirstBootJson(kChefFirstBootJSON), rl);

  for (const auto& role : rl.roles) {
    Row r;
    r["seq_no"] = INTEGER(role.seqNum);
    r["role"] = role.name;
    results.push_back(std::move(r));
  }

  for (const auto& recipe : rl.recipes) {
    Row r;
    r["seq_no"] = INTEGER(recipe.seqNum);
    r["role"] = recipe.name;
    results.push_back(std::move(r));
  }

  return results;
}
} // namespace tables
} // namespace osquery
