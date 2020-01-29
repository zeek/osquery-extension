cmake_minimum_required(VERSION 3.14)
project("broker")

function(zeekAgentLibrariesBroker)
  # The actor framework library is imported directly from the
  # submodule found inside the broker repository

  # There are a couple of generated files (config.hh and build_config.hpp)
  # that we have pinned to a known state. We don't want any kind of automatic
  # detection that could interfere with reproducible builds and possibly
  # introduce redistribution problems.
  #
  # Additionally, there's a make_unique re-implementation that causes
  # build issues with recent C++ versions. We have removed it by providing
  # an empty make_unique.hh header that will get included instead of the
  # original one.

  generateActorFramework()
  generateBroker()
endfunction()

function(generateActorFramework)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/3rdparty/caf")

  set(caf_core_root "${library_root}/libcaf_core")

  add_library(thirdparty_caf_core
    "${caf_core_root}/src/abstract_actor.cpp"
    "${caf_core_root}/src/abstract_channel.cpp"
    "${caf_core_root}/src/abstract_composable_behavior.cpp"
    "${caf_core_root}/src/abstract_coordinator.cpp"
    "${caf_core_root}/src/abstract_group.cpp"
    "${caf_core_root}/src/actor_addr.cpp"
    "${caf_core_root}/src/actor_clock.cpp"
    "${caf_core_root}/src/actor_companion.cpp"
    "${caf_core_root}/src/actor_config.cpp"
    "${caf_core_root}/src/actor_control_block.cpp"
    "${caf_core_root}/src/actor.cpp"
    "${caf_core_root}/src/actor_ostream.cpp"
    "${caf_core_root}/src/actor_pool.cpp"
    "${caf_core_root}/src/actor_proxy.cpp"
    "${caf_core_root}/src/actor_registry.cpp"
    "${caf_core_root}/src/actor_system_config.cpp"
    "${caf_core_root}/src/actor_system.cpp"
    "${caf_core_root}/src/append_hex.cpp"
    "${caf_core_root}/src/atom.cpp"
    "${caf_core_root}/src/attachable.cpp"
    "${caf_core_root}/src/behavior.cpp"
    "${caf_core_root}/src/behavior_impl.cpp"
    "${caf_core_root}/src/behavior_stack.cpp"
    "${caf_core_root}/src/blocking_actor.cpp"
    "${caf_core_root}/src/blocking_behavior.cpp"
    "${caf_core_root}/src/chars.cpp"
    "${caf_core_root}/src/concatenated_tuple.cpp"
    "${caf_core_root}/src/config_option_adder.cpp"
    "${caf_core_root}/src/config_option.cpp"
    "${caf_core_root}/src/config_option_set.cpp"
    "${caf_core_root}/src/config_value.cpp"
    "${caf_core_root}/src/decorated_tuple.cpp"
    "${caf_core_root}/src/default_attachable.cpp"
    "${caf_core_root}/src/defaults.cpp"
    "${caf_core_root}/src/deserializer.cpp"
    "${caf_core_root}/src/downstream_manager_base.cpp"
    "${caf_core_root}/src/downstream_manager.cpp"
    "${caf_core_root}/src/downstream_messages.cpp"
    "${caf_core_root}/src/duration.cpp"
    "${caf_core_root}/src/dynamic_message_data.cpp"
    "${caf_core_root}/src/error.cpp"
    "${caf_core_root}/src/event_based_actor.cpp"
    "${caf_core_root}/src/execution_unit.cpp"
    "${caf_core_root}/src/exit_reason.cpp"
    "${caf_core_root}/src/forwarding_actor_proxy.cpp"
    "${caf_core_root}/src/get_mac_addresses.cpp"
    "${caf_core_root}/src/get_process_id.cpp"
    "${caf_core_root}/src/get_root_uuid.cpp"
    "${caf_core_root}/src/group.cpp"
    "${caf_core_root}/src/group_manager.cpp"
    "${caf_core_root}/src/group_module.cpp"
    "${caf_core_root}/src/inbound_path.cpp"
    "${caf_core_root}/src/ini_consumer.cpp"
    "${caf_core_root}/src/invoke_result_visitor.cpp"
    "${caf_core_root}/src/ipv4_address.cpp"
    "${caf_core_root}/src/ipv4_subnet.cpp"
    "${caf_core_root}/src/ipv6_address.cpp"
    "${caf_core_root}/src/ipv6_subnet.cpp"
    "${caf_core_root}/src/local_actor.cpp"
    "${caf_core_root}/src/logger.cpp"
    "${caf_core_root}/src/mailbox_element.cpp"
    "${caf_core_root}/src/make_config_option.cpp"
    "${caf_core_root}/src/match_case.cpp"
    "${caf_core_root}/src/memory_managed.cpp"
    "${caf_core_root}/src/merged_tuple.cpp"
    "${caf_core_root}/src/message_builder.cpp"
    "${caf_core_root}/src/message.cpp"
    "${caf_core_root}/src/message_data.cpp"
    "${caf_core_root}/src/message_handler.cpp"
    "${caf_core_root}/src/message_view.cpp"
    "${caf_core_root}/src/monitorable_actor.cpp"
    "${caf_core_root}/src/node_id.cpp"
    "${caf_core_root}/src/outbound_path.cpp"
    "${caf_core_root}/src/pec.cpp"
    "${caf_core_root}/src/pretty_type_name.cpp"
    "${caf_core_root}/src/private_thread.cpp"
    "${caf_core_root}/src/proxy_registry.cpp"
    "${caf_core_root}/src/raise_error.cpp"
    "${caf_core_root}/src/raw_event_based_actor.cpp"
    "${caf_core_root}/src/ref_counted.cpp"
    "${caf_core_root}/src/replies_to.cpp"
    "${caf_core_root}/src/response_promise.cpp"
    "${caf_core_root}/src/resumable.cpp"
    "${caf_core_root}/src/ripemd_160.cpp"
    "${caf_core_root}/src/runtime_settings_map.cpp"
    "${caf_core_root}/src/scheduled_actor.cpp"
    "${caf_core_root}/src/scoped_actor.cpp"
    "${caf_core_root}/src/scoped_execution_unit.cpp"
    "${caf_core_root}/src/sec.cpp"
    "${caf_core_root}/src/sequencer.cpp"
    "${caf_core_root}/src/serializer.cpp"
    "${caf_core_root}/src/set_thread_name.cpp"
    "${caf_core_root}/src/shared_spinlock.cpp"
    "${caf_core_root}/src/simple_actor_clock.cpp"
    "${caf_core_root}/src/skip.cpp"
    "${caf_core_root}/src/splitter.cpp"
    "${caf_core_root}/src/stream_aborter.cpp"
    "${caf_core_root}/src/stream_manager.cpp"
    "${caf_core_root}/src/stream_priority.cpp"
    "${caf_core_root}/src/stringification_inspector.cpp"
    "${caf_core_root}/src/string_view.cpp"
    "${caf_core_root}/src/sync_request_bouncer.cpp"
    "${caf_core_root}/src/term.cpp"
    "${caf_core_root}/src/test_actor_clock.cpp"
    "${caf_core_root}/src/test_coordinator.cpp"
    "${caf_core_root}/src/thread_hook.cpp"
    "${caf_core_root}/src/thread_safe_actor_clock.cpp"
    "${caf_core_root}/src/tick_emitter.cpp"
    "${caf_core_root}/src/timestamp.cpp"
    "${caf_core_root}/src/try_match.cpp"
    "${caf_core_root}/src/type_erased_tuple.cpp"
    "${caf_core_root}/src/type_erased_value.cpp"
    "${caf_core_root}/src/uniform_type_info_map.cpp"
    "${caf_core_root}/src/unprofiled.cpp"
    "${caf_core_root}/src/uri_builder.cpp"
    "${caf_core_root}/src/uri.cpp"
    "${caf_core_root}/src/uri_impl.cpp"
    "${caf_core_root}/src/work_sharing.cpp"
    "${caf_core_root}/src/work_stealing.cpp"
    "${caf_core_root}/src/string_algorithms.cpp"
  )

  target_include_directories(thirdparty_caf_core
    PRIVATE
      "${caf_core_root}"
      "${CMAKE_CURRENT_SOURCE_DIR}/generated"
  )

  target_include_directories(thirdparty_caf_core
    SYSTEM INTERFACE
      "${caf_core_root}"
      "${CMAKE_CURRENT_SOURCE_DIR}/generated"
  )

  target_link_libraries(thirdparty_caf_core
    PUBLIC
      zeek_agent_cxx_settings

    PRIVATE
      zeek_agent_libraries_settings
  )

  set(caf_io_root "${library_root}/libcaf_io")

  add_library(thirdparty_caf_io
    "${caf_io_root}/src/abstract_broker.cpp"
    "${caf_io_root}/src/acceptor.cpp"
    "${caf_io_root}/src/acceptor_manager.cpp"
    "${caf_io_root}/src/basp_broker.cpp"
    "${caf_io_root}/src/broker.cpp"
    "${caf_io_root}/src/connection_helper.cpp"
    "${caf_io_root}/src/datagram_handler.cpp"
    "${caf_io_root}/src/datagram_manager.cpp"
    "${caf_io_root}/src/datagram_servant.cpp"
    "${caf_io_root}/src/datagram_servant_impl.cpp"
    "${caf_io_root}/src/default_multiplexer.cpp"
    "${caf_io_root}/src/doorman.cpp"
    "${caf_io_root}/src/doorman_impl.cpp"
    "${caf_io_root}/src/event_handler.cpp"
    "${caf_io_root}/src/header.cpp"
    "${caf_io_root}/src/hook.cpp"
    "${caf_io_root}/src/instance.cpp"
    "${caf_io_root}/src/interfaces.cpp"
    "${caf_io_root}/src/ip_endpoint.cpp"
    "${caf_io_root}/src/manager.cpp"
    "${caf_io_root}/src/message_type.cpp"
    "${caf_io_root}/src/middleman_actor.cpp"
    "${caf_io_root}/src/middleman_actor_impl.cpp"
    "${caf_io_root}/src/middleman.cpp"
    "${caf_io_root}/src/multiplexer.cpp"
    "${caf_io_root}/src/native_socket.cpp"
    "${caf_io_root}/src/pipe_reader.cpp"
    "${caf_io_root}/src/protocol.cpp"
    "${caf_io_root}/src/receive_buffer.cpp"
    "${caf_io_root}/src/routing_table.cpp"
    "${caf_io_root}/src/scribe.cpp"
    "${caf_io_root}/src/scribe_impl.cpp"
    "${caf_io_root}/src/socket_guard.cpp"
    "${caf_io_root}/src/stream.cpp"
    "${caf_io_root}/src/stream_manager.cpp"
    "${caf_io_root}/src/tcp.cpp"
    "${caf_io_root}/src/test_multiplexer.cpp"
    "${caf_io_root}/src/udp.cpp"
  )

  target_include_directories(thirdparty_caf_io
    PRIVATE
      "${caf_io_root}"
      "${CMAKE_CURRENT_SOURCE_DIR}/generated"
  )

  target_include_directories(thirdparty_caf_io
    SYSTEM INTERFACE
      "${caf_io_root}"
  )

  target_link_libraries(thirdparty_caf_io
    PUBLIC
      zeek_agent_cxx_settings
      thirdparty_caf_core

    PRIVATE
      zeek_agent_libraries_settings
  )

  set(caf_openssl_root "${library_root}/libcaf_openssl")

  add_library(thirdparty_caf_openssl
    "${caf_openssl_root}/src/manager.cpp"
    "${caf_openssl_root}/src/middleman_actor.cpp"
    "${caf_openssl_root}/src/publish.cpp"
    "${caf_openssl_root}/src/remote_actor.cpp"
    "${caf_openssl_root}/src/session.cpp"
  )

  target_include_directories(thirdparty_caf_openssl
    PRIVATE
      "${caf_openssl_root}"
      "${CMAKE_CURRENT_SOURCE_DIR}/generated"
  )

  target_include_directories(thirdparty_caf_openssl
    SYSTEM INTERFACE
      "${caf_openssl_root}"
  )

  target_link_libraries(thirdparty_caf_openssl
    PUBLIC
      zeek_agent_cxx_settings
      thirdparty_caf_core
      thirdparty_caf_io
      thirdparty_openssl

    PRIVATE
      zeek_agent_libraries_settings
  )

  add_library(thirdparty_actorframework INTERFACE)

  target_link_libraries(thirdparty_actorframework INTERFACE
    thirdparty_caf_core
    thirdparty_caf_io
    thirdparty_caf_openssl
  )
endfunction()

function(generateBroker)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_broker
    "${library_root}/src/address.cc"
    "${library_root}/src/configuration.cc"
    "${library_root}/src/core_actor.cc"
    "${library_root}/src/data.cc"
    "${library_root}/src/endpoint.cc"
    "${library_root}/src/error.cc"
    "${library_root}/src/status_subscriber.cc"
    "${library_root}/src/internal_command.cc"
    "${library_root}/src/mailbox.cc"
    "${library_root}/src/network_info.cc"
    "${library_root}/src/peer_status.cc"
    "${library_root}/src/port.cc"
    "${library_root}/src/publisher.cc"
    "${library_root}/src/status.cc"
    "${library_root}/src/store.cc"
    "${library_root}/src/subnet.cc"
    "${library_root}/src/subscriber.cc"
    "${library_root}/src/time.cc"
    "${library_root}/src/topic.cc"
    "${library_root}/src/version.cc"

    "${library_root}/src/detail/abstract_backend.cc"
    "${library_root}/src/detail/clone_actor.cc"
    "${library_root}/src/detail/core_policy.cc"
    "${library_root}/src/detail/filesystem.cc"
    "${library_root}/src/detail/flare.cc"
    "${library_root}/src/detail/flare_actor.cc"
    "${library_root}/src/detail/make_backend.cc"
    "${library_root}/src/detail/master_actor.cc"
    "${library_root}/src/detail/master_resolver.cc"
    "${library_root}/src/detail/memory_backend.cc"
    "${library_root}/src/detail/network_cache.cc"
    "${library_root}/src/detail/prefix_matcher.cc"
    "${library_root}/src/detail/sqlite_backend.cc"
  )

  target_link_libraries(thirdparty_broker
    PUBLIC
      zeek_agent_cxx_settings
      thirdparty_actorframework
      thirdparty_sqlite

    PRIVATE
      zeek_agent_libraries_settings
  )

  target_include_directories(thirdparty_broker PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/generated"
    "${library_root}/src/detail"
    "${library_root}"
  )

  target_include_directories(thirdparty_broker SYSTEM INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/generated"
    "${library_root}"
  )

  # Also attempt to turn off the make_unique reimplementation that upstream
  # has added inside the std namespace
  target_compile_definitions(thirdparty_broker PRIVATE
    BROKER_LINUX=1
    BROKER_DETAIL_MAKE_UNIQUE_HH
  )
endfunction()

zeekAgentLibrariesBroker()
