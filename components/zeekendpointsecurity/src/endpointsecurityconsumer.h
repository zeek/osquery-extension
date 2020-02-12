#pragma once

#include <memory>
#include <optional>
#include <vector>

#include <zeek/iendpointsecurityconsumer.h>

namespace zeek {
class EndpointSecurityConsumer final : public IEndpointSecurityConsumer {
public:
  /// \brief Destructor
  virtual ~EndpointSecurityConsumer() override;

  /// \brief Returns a list of processed events
  /// \param event_list Where the event list is stored
  /// \return A Status object
  virtual Status getEvents(EventList &event_list) override;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  /// \brief Constructor
  EndpointSecurityConsumer(IZeekLogger &logger,
                           IZeekConfiguration &configuration);

  /// \brief Event callback used by EndpointSecurity
  void endpointSecurityCallback(const void *message_ptr);

public:
  /// \brief Initializes the event header from the given message
  /// \param event_header The event header object to initialize
  /// \param message_ptr a valid pointer to an EndpointSecurity es_message_t
  /// \return A Status object
  static Status initializeEventHeader(Event::Header &event_header,
                                      const void *message_ptr);

  /// \brief Process execution event handler
  /// \param event the generated event object
  /// \param message_ptr a valid pointer to an EndpointSecurity es_message_t
  /// \return A Status object
  static Status processExecNotification(Event &event, const void *message_ptr);

  /// \brief Process forking event handler
  /// \param event the generated event object
  /// \param message_ptr a valid pointer to an EndpointSecurity es_message_t
  /// \return A Status object
  static Status processForkNotification(Event &event, const void *message_ptr);

  friend class IEndpointSecurityConsumer;
};
} // namespace zeek
