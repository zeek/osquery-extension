cmake_minimum_required(VERSION 3.14)
project("broker")

function(zeekAgentLibrariesBroker)
  # The actor framework library is imported directly from the
  # submodule found inside the broker repository

  # There are a couple of generated files (config.hh and build_config.hpp)
  # that we have pinned to a known state. We don't want any kind of automatic
  # detection that could interfere with reproducible builds and possibly
  # introduce redistribution problems.

  generateActorFramework()
  generateBroker()
endfunction()

function(generateActorFramework)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src/3rdparty/caf")

  set(caf_core_root "${library_root}/libcaf_core")
  add_library(thirdparty_caf_core
    "${caf_core_root}/src/scoped_actor.cpp"
    "${caf_core_root}/src/ipv6_endpoint.cpp"
    "${caf_core_root}/src/ipv6_address.cpp"
    "${caf_core_root}/src/stream_manager.cpp"
    "${caf_core_root}/src/policy/work_sharing.cpp"
    "${caf_core_root}/src/policy/work_stealing.cpp"
    "${caf_core_root}/src/policy/downstream_messages.cpp"
    "${caf_core_root}/src/policy/unprofiled.cpp"
    "${caf_core_root}/src/config_option.cpp"
    "${caf_core_root}/src/local_actor.cpp"
    "${caf_core_root}/src/actor_system_config.cpp"
    "${caf_core_root}/src/ipv6_subnet.cpp"
    "${caf_core_root}/src/downstream_manager.cpp"
    "${caf_core_root}/src/behavior.cpp"
    "${caf_core_root}/src/mailbox_element.cpp"
    "${caf_core_root}/src/ipv4_subnet.cpp"
    "${caf_core_root}/src/rtti_pair.cpp"
    "${caf_core_root}/src/abstract_group.cpp"
    "${caf_core_root}/src/ipv4_address.cpp"
    "${caf_core_root}/src/binary_deserializer.cpp"
    "${caf_core_root}/src/uri_builder.cpp"
    "${caf_core_root}/src/attachable.cpp"
    "${caf_core_root}/src/config_option_adder.cpp"
    "${caf_core_root}/src/deserializer.cpp"
    "${caf_core_root}/src/execution_unit.cpp"
    "${caf_core_root}/src/blocking_actor.cpp"
    "${caf_core_root}/src/runtime_settings_map.cpp"
    "${caf_core_root}/src/downstream_manager_base.cpp"
    "${caf_core_root}/src/defaults.cpp"
    "${caf_core_root}/src/timestamp.cpp"
    "${caf_core_root}/src/response_promise.cpp"
    "${caf_core_root}/src/abstract_channel.cpp"
    "${caf_core_root}/src/actor_config.cpp"
    "${caf_core_root}/src/thread_hook.cpp"
    "${caf_core_root}/src/abstract_actor.cpp"
    "${caf_core_root}/src/serializer.cpp"
    "${caf_core_root}/src/actor_pool.cpp"
    "${caf_core_root}/src/replies_to.cpp"
    "${caf_core_root}/src/scheduler/abstract_coordinator.cpp"
    "${caf_core_root}/src/scheduler/test_coordinator.cpp"
    "${caf_core_root}/src/type_erased_tuple.cpp"
    "${caf_core_root}/src/group_manager.cpp"
    "${caf_core_root}/src/message_handler.cpp"
    "${caf_core_root}/src/sec.cpp"
    "${caf_core_root}/src/node_id.cpp"
    "${caf_core_root}/src/uniform_type_info_map.cpp"
    "${caf_core_root}/src/logger.cpp"
    "${caf_core_root}/src/exit_reason.cpp"
    "${caf_core_root}/src/monitorable_actor.cpp"
    "${caf_core_root}/src/abstract_composable_behavior.cpp"
    "${caf_core_root}/src/message_view.cpp"
    "${caf_core_root}/src/inbound_path.cpp"
    "${caf_core_root}/src/message.cpp"
    "${caf_core_root}/src/uri.cpp"
    "${caf_core_root}/src/pec.cpp"
    "${caf_core_root}/src/actor_profiler.cpp"
    "${caf_core_root}/src/string_algorithms.cpp"
    "${caf_core_root}/src/proxy_registry.cpp"
    "${caf_core_root}/src/atom.cpp"
    "${caf_core_root}/src/group_module.cpp"
    "${caf_core_root}/src/duration.cpp"
    "${caf_core_root}/src/stream_aborter.cpp"
    "${caf_core_root}/src/error.cpp"
    "${caf_core_root}/src/ipv4_endpoint.cpp"
    "${caf_core_root}/src/actor_registry.cpp"
    "${caf_core_root}/src/make_config_option.cpp"
    "${caf_core_root}/src/config_option_set.cpp"
    "${caf_core_root}/src/event_based_actor.cpp"
    "${caf_core_root}/src/actor.cpp"
    "${caf_core_root}/src/actor_companion.cpp"
    "${caf_core_root}/src/actor_clock.cpp"
    "${caf_core_root}/src/raise_error.cpp"
    "${caf_core_root}/src/ref_counted.cpp"
    "${caf_core_root}/src/group.cpp"
    "${caf_core_root}/src/memory_managed.cpp"
    "${caf_core_root}/src/skip.cpp"
    "${caf_core_root}/src/scoped_execution_unit.cpp"
    "${caf_core_root}/src/type_erased_value.cpp"
    "${caf_core_root}/src/settings.cpp"
    "${caf_core_root}/src/config_value.cpp"
    "${caf_core_root}/src/forwarding_actor_proxy.cpp"
    "${caf_core_root}/src/string_view.cpp"
    "${caf_core_root}/src/actor_system.cpp"
    "${caf_core_root}/src/resumable.cpp"
    "${caf_core_root}/src/scheduled_actor.cpp"
    "${caf_core_root}/src/detail/simple_actor_clock.cpp"
    "${caf_core_root}/src/detail/fnv_hash.cpp"
    "${caf_core_root}/src/detail/append_hex.cpp"
    "${caf_core_root}/src/detail/stringification_inspector.cpp"
    "${caf_core_root}/src/detail/blocking_behavior.cpp"
    "${caf_core_root}/src/detail/sync_request_bouncer.cpp"
    "${caf_core_root}/src/detail/behavior_stack.cpp"
    "${caf_core_root}/src/detail/concatenated_tuple.cpp"
    "${caf_core_root}/src/detail/serialized_size.cpp"
    "${caf_core_root}/src/detail/ripemd_160.cpp"
    "${caf_core_root}/src/detail/dynamic_message_data.cpp"
    "${caf_core_root}/src/detail/message_data.cpp"
    "${caf_core_root}/src/detail/try_match.cpp"
    "${caf_core_root}/src/detail/abstract_worker_hub.cpp"
    "${caf_core_root}/src/detail/pretty_type_name.cpp"
    "${caf_core_root}/src/detail/invoke_result_visitor.cpp"
    "${caf_core_root}/src/detail/get_root_uuid.cpp"
    "${caf_core_root}/src/detail/thread_safe_actor_clock.cpp"
    "${caf_core_root}/src/detail/abstract_worker.cpp"
    "${caf_core_root}/src/detail/get_process_id.cpp"
    "${caf_core_root}/src/detail/get_mac_addresses.cpp"
    "${caf_core_root}/src/detail/ini_consumer.cpp"
    "${caf_core_root}/src/detail/test_actor_clock.cpp"
    "${caf_core_root}/src/detail/decorated_tuple.cpp"
    "${caf_core_root}/src/detail/append_percent_encoded.cpp"
    "${caf_core_root}/src/detail/shared_spinlock.cpp"
    "${caf_core_root}/src/detail/uri_impl.cpp"
    "${caf_core_root}/src/detail/set_thread_name.cpp"
    "${caf_core_root}/src/detail/private_thread.cpp"
    "${caf_core_root}/src/detail/parser/chars.cpp"
    "${caf_core_root}/src/detail/merged_tuple.cpp"
    "${caf_core_root}/src/detail/parse.cpp"
    "${caf_core_root}/src/detail/tick_emitter.cpp"
    "${caf_core_root}/src/detail/behavior_impl.cpp"
    "${caf_core_root}/src/default_attachable.cpp"
    "${caf_core_root}/src/actor_control_block.cpp"
    "${caf_core_root}/src/message_builder.cpp"
    "${caf_core_root}/src/term.cpp"
    "${caf_core_root}/src/match_case.cpp"
    "${caf_core_root}/src/decorator/sequencer.cpp"
    "${caf_core_root}/src/decorator/splitter.cpp"
    "${caf_core_root}/src/actor_proxy.cpp"
    "${caf_core_root}/src/raw_event_based_actor.cpp"
    "${caf_core_root}/src/actor_addr.cpp"
    "${caf_core_root}/src/outbound_path.cpp"
    "${caf_core_root}/src/actor_ostream.cpp"

    "${CMAKE_CURRENT_SOURCE_DIR}/generated/caf/core/exit_reason_strings.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/caf/core/inbox_result_strings.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/caf/core/invoke_msg_result_strings.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/caf/core/message_priority_strings.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/caf/core/pec_strings.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/caf/core/sec_strings.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/caf/core/stream_priority_strings.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/caf/core/task_result_strings.cpp"
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
    "${caf_io_root}/src/policy/udp.cpp"
    "${caf_io_root}/src/policy/tcp.cpp"
    "${caf_io_root}/src/detail/socket_guard.cpp"
    "${caf_io_root}/src/io/middleman.cpp"
    "${caf_io_root}/src/io/scribe.cpp"
    "${caf_io_root}/src/io/datagram_servant.cpp"
    "${caf_io_root}/src/io/middleman_actor_impl.cpp"
    "${caf_io_root}/src/io/network/native_socket.cpp"
    "${caf_io_root}/src/io/network/stream_manager.cpp"
    "${caf_io_root}/src/io/network/test_multiplexer.cpp"
    "${caf_io_root}/src/io/network/datagram_manager.cpp"
    "${caf_io_root}/src/io/network/acceptor.cpp"
    "${caf_io_root}/src/io/network/pipe_reader.cpp"
    "${caf_io_root}/src/io/network/interfaces.cpp"
    "${caf_io_root}/src/io/network/receive_buffer.cpp"
    "${caf_io_root}/src/io/network/stream.cpp"
    "${caf_io_root}/src/io/network/scribe_impl.cpp"
    "${caf_io_root}/src/io/network/acceptor_manager.cpp"
    "${caf_io_root}/src/io/network/protocol.cpp"
    "${caf_io_root}/src/io/network/datagram_servant_impl.cpp"
    "${caf_io_root}/src/io/network/datagram_handler.cpp"
    "${caf_io_root}/src/io/network/event_handler.cpp"
    "${caf_io_root}/src/io/network/ip_endpoint.cpp"
    "${caf_io_root}/src/io/network/doorman_impl.cpp"
    "${caf_io_root}/src/io/network/multiplexer.cpp"
    "${caf_io_root}/src/io/network/default_multiplexer.cpp"
    "${caf_io_root}/src/io/network/manager.cpp"
    "${caf_io_root}/src/io/connection_helper.cpp"
    "${caf_io_root}/src/io/abstract_broker.cpp"
    "${caf_io_root}/src/io/basp_broker.cpp"
    "${caf_io_root}/src/io/doorman.cpp"
    "${caf_io_root}/src/io/basp/routing_table.cpp"
    "${caf_io_root}/src/io/basp/message_queue.cpp"
    "${caf_io_root}/src/io/basp/header.cpp"
    "${caf_io_root}/src/io/basp/worker.cpp"
    "${caf_io_root}/src/io/basp/instance.cpp"
    "${caf_io_root}/src/io/middleman_actor.cpp"
    "${caf_io_root}/src/io/broker.cpp"

    "${CMAKE_CURRENT_SOURCE_DIR}/generated/caf/io/message_type_to_string.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/caf/io/operation_to_string.cpp"
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
    "${caf_openssl_root}/src/openssl/remote_actor.cpp"
    "${caf_openssl_root}/src/openssl/middleman_actor.cpp"
    "${caf_openssl_root}/src/openssl/session.cpp"
    "${caf_openssl_root}/src/openssl/publish.cpp"
    "${caf_openssl_root}/src/openssl/manager.cpp"
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
    "${library_root}/src/subnet.cc"
    "${library_root}/src/time.cc"
    "${library_root}/src/version.cc"
    "${library_root}/src/mailbox.cc"
    "${library_root}/src/peer_status.cc"
    "${library_root}/src/subscriber.cc"
    "${library_root}/src/broker-pipe.cc"
    "${library_root}/src/publisher.cc"
    "${library_root}/src/configuration.cc"
    "${library_root}/src/store.cc"
    "${library_root}/src/internal_command.cc"
    "${library_root}/src/endpoint.cc"
    "${library_root}/src/error.cc"
    "${library_root}/src/topic.cc"
    "${library_root}/src/data.cc"
    "${library_root}/src/broker-node.cc"
    "${library_root}/src/status_subscriber.cc"
    "${library_root}/src/status.cc"
    "${library_root}/src/config.hh.in"
    "${library_root}/src/core_actor.cc"
    "${library_root}/src/network_info.cc"
    "${library_root}/src/defaults.cc"
    "${library_root}/src/detail/master_actor.cc"
    "${library_root}/src/detail/data_generator.cc"
    "${library_root}/src/detail/network_cache.cc"
    "${library_root}/src/detail/generator_file_reader.cc"
    "${library_root}/src/detail/core_scatterer.cc"
    "${library_root}/src/detail/flare.cc"
    "${library_root}/src/detail/sqlite_backend.cc"
    "${library_root}/src/detail/make_backend.cc"
    "${library_root}/src/detail/prefix_matcher.cc"
    "${library_root}/src/detail/clone_actor.cc"
    "${library_root}/src/detail/meta_command_writer.cc"
    "${library_root}/src/detail/abstract_backend.cc"
    "${library_root}/src/detail/flare_actor.cc"
    "${library_root}/src/detail/memory_backend.cc"
    "${library_root}/src/detail/meta_data_writer.cc"
    "${library_root}/src/detail/generator_file_writer.cc"
    "${library_root}/src/detail/core_policy.cc"
    "${library_root}/src/detail/filesystem.cc"
    "${library_root}/src/detail/master_resolver.cc"
    "${library_root}/src/address.cc"
    "${library_root}/src/port.cc"
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
    "${library_root}/include"
    "${library_root}"
  )

  target_include_directories(thirdparty_broker SYSTEM INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/generated"
    "${library_root}/include"
  )

  if(ZEEK_AGENT_ENABLE_SANITIZERS)
    target_compile_definitions(thirdparty_broker PRIVATE
      BROKER_ASAN
      __SANITIZE_ADDRESS__
    )
  endif()
endfunction()

zeekAgentLibrariesBroker()
