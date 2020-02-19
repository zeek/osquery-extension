#include "zeekconfiguration.h"
#include "configurationchecker.h"
#include "zeekconfigurationtableplugin.h"

#include <cassert>
#include <fstream>
#include <sstream>

#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>

namespace zeek {
namespace {
#if defined(ZEEK_AGENT_ENABLE_OSQUERY_SUPPORT)
#define REQUIRE_OSQUERY_EXTENSIONS_SOCKET true
#else
#define REQUIRE_OSQUERY_EXTENSIONS_SOCKET false
#endif

// clang-format off
const ConfigurationChecker::Constraints kConfigurationConstraints = {
  {
    "server_address",

    {
      ConfigurationChecker::MemberConstraint::Type::String,
      false,
      "",
      true
    }
  },

  {
    "server_port",

    {
      ConfigurationChecker::MemberConstraint::Type::UInt16,
      false,
      "",
      true
    }
  },

  {
    "log_folder",

    {
      ConfigurationChecker::MemberConstraint::Type::String,
      false,
      "",
      true
    }
  },

  {
    "group_list",

    {
      ConfigurationChecker::MemberConstraint::Type::String,
      true,
      "",
      true
    }
  },

  {
    "certificate_authority",

    {
      ConfigurationChecker::MemberConstraint::Type::String,
      false,
      "authentication",
      false
    }
  },

  {
    "certificate",

    {
      ConfigurationChecker::MemberConstraint::Type::String,
      false,
      "authentication",
      false
    }
  },

  {
    "key",

    {
      ConfigurationChecker::MemberConstraint::Type::String,
      false,
      "authentication",
      false
    }
  },

  {
    "max_queued_row_count",

    {
      ConfigurationChecker::MemberConstraint::Type::UInt32,
      false,
      "",
      false
    }
  },

  {
    "osquery_extensions_socket",

    {
      ConfigurationChecker::MemberConstraint::Type::String,
      false,
      "",
      REQUIRE_OSQUERY_EXTENSIONS_SOCKET
    }
  }
};
// clang-format on
} // namespace

struct ZeekConfiguration::PrivateData final {
  PrivateData(IVirtualDatabase &virtual_database_)
      : virtual_database(virtual_database_) {}

  IVirtualDatabase &virtual_database;

  ZeekConfigurationTablePlugin::Ref config_table;

  Context context;
};

ZeekConfiguration::~ZeekConfiguration() {
  auto status = unregisterTables();

  assert(status.succeeded() &&
         "Failed to unregister the logger tables from the virtual database");
}

const std::string &ZeekConfiguration::serverAddress() const {
  return d->context.server_address;
}

std::uint16_t ZeekConfiguration::serverPort() const {
  return d->context.server_port;
}

const std::vector<std::string> &ZeekConfiguration::groupList() const {
  return d->context.group_list;
}

const std::string &ZeekConfiguration::getLogFolder() const {
  return d->context.log_folder;
}

const std::string &ZeekConfiguration::certificateAuthority() const {
  return d->context.certificate_authority;
}

const std::string &ZeekConfiguration::clientCertificate() const {
  return d->context.client_certificate;
}

const std::string &ZeekConfiguration::clientKey() const {
  return d->context.client_key;
}

const std::string &ZeekConfiguration::osqueryExtensionsSocket() const {
  return d->context.osquery_extensions_socket;
}

std::size_t ZeekConfiguration::maxQueuedRowCount() const {
  return d->context.max_queued_row_count;
}

ZeekConfiguration::ZeekConfiguration(IVirtualDatabase &virtual_database,
                                     const std::string &configuration_file_path)
    : d(new PrivateData(virtual_database)) {

  auto status = registerTables();
  if (!status.succeeded()) {
    throw status;
  }

  status = loadConfigurationFile(configuration_file_path);
  if (!status.succeeded()) {
    throw status;
  }
}

Status ZeekConfiguration::registerTables() {
  auto status = ZeekConfigurationTablePlugin::create(d->config_table, *this);
  if (!status.succeeded()) {
    return status;
  }

  status = d->virtual_database.registerTable(d->config_table);
  if (!status.succeeded()) {
    d->config_table.reset();
    return status;
  }

  return Status::success();
}

Status ZeekConfiguration::unregisterTables() {
  auto status = d->virtual_database.unregisterTable(d->config_table->name());
  if (!status.succeeded()) {
    return status;
  }

  d->config_table.reset();
  return Status::success();
}

Status ZeekConfiguration::loadConfigurationFile(
    const std::string &configuration_file_path) {
  std::ifstream stream(configuration_file_path);
  if (stream.fail()) {
    return Status::failure("Failed to open the configuration file");
  }

  std::stringstream buffer;
  buffer << stream.rdbuf();

  if (stream.fail()) {
    return Status::failure("Failed to read the configuration file");
  }

  auto status = parseConfigurationData(d->context, buffer.str());
  if (!status.succeeded()) {
    return status;
  }

  return Status::success();
}

Status ZeekConfiguration::parseConfigurationData(Context &context,
                                                 const std::string &json) {
  context = {};

  rapidjson::Document document;
  document.Parse(json.c_str());

  ConfigurationChecker::Ref config_checker;
  auto status =
      ConfigurationChecker::create(config_checker, kConfigurationConstraints);

  if (!status.succeeded()) {
    return status;
  }

  status = config_checker->validate(document);
  if (!status.succeeded()) {
    return status;
  }

  context.server_address = document["server_address"].GetString();

  if (document.HasMember("osquery_extensions_socket")) {
    context.osquery_extensions_socket =
        document["osquery_extensions_socket"].GetString();

  } else {
    context.osquery_extensions_socket = "";
  }

  context.server_port =
      static_cast<std::uint16_t>(document["server_port"].GetInt());

  context.log_folder = document["log_folder"].GetString();

  const auto &group_list = document["group_list"];

  for (auto i = 0U; i < group_list.Size(); ++i) {
    const auto &group = group_list[i].GetString();
    context.group_list.push_back(group);
  }

  if (document.HasMember("max_queued_row_count")) {
    context.max_queued_row_count =
        static_cast<std::uint32_t>(document["max_queued_row_count"].GetInt());

  } else {
    context.max_queued_row_count = 50000U;
  }

  if (document.HasMember("authentication")) {
    const auto &auth_object = document["authentication"];
    std::vector<std::string> auth_file_list;

    if (auth_object.HasMember("certificate_authority")) {
      context.certificate_authority =
          auth_object["certificate_authority"].GetString();

      auth_file_list.push_back(context.certificate_authority);
    }

    if (auth_object.HasMember("client_certificate")) {
      context.client_certificate =
          auth_object["client_certificate"].GetString();

      auth_file_list.push_back(context.client_certificate);
    }

    if (auth_object.HasMember("client_key")) {
      context.client_key = auth_object["client_key"].GetString();

      auth_file_list.push_back(context.client_key);
    }

    for (const auto &path : auth_file_list) {
      bool valid_path = false;

      {
        std::ifstream s(path);
        valid_path = s.good();
      }

      if (!valid_path) {
        return Status::failure(
            "The following path is either not valid or not accessible: " +
            path);
      }
    }
  }

  return Status::success();
}

Status IZeekConfiguration::create(Ref &ref, IVirtualDatabase &virtual_database,
                                  const std::string &configuration_file_path) {
  try {
    ref.reset();

    auto ptr = new ZeekConfiguration(virtual_database, configuration_file_path);
    ref.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}
} // namespace zeek
