#pragma once

#include <functional>

#include "DisconnectReasons.hpp"
#include "MessageProperties.hpp"

namespace AsyncMqttClientInternals {
// user callbacks
typedef std::function<void(bool sessionPresent)> OnConnectUserCallback;
typedef std::function<void(AsyncMqttClientDisconnectReason reason)> OnDisconnectUserCallback;
typedef std::function<void(uint16_t packetId, uint8_t qos)> OnSubscribeUserCallback;
typedef std::function<void(uint16_t packetId)> OnUnsubscribeUserCallback;
typedef std::function<void(char const *topic, char const *payload, AsyncMqttClientMessageProperties properties, size_t len, size_t index, size_t total)> OnMessageUserCallback;
typedef std::function<void(uint16_t packetId)> OnPublishUserCallback;

#if ASYNC_TCP_SSL_ENABLED
#if ASYNC_TCP_SSL_BEARSSL
typedef std::function<int(void *dn_hash, size_t dn_hash_len, uint8_t **buf)> OnSSLCertLookupCallback;
#endif
#endif

// internal callbacks
typedef std::function<void(bool sessionPresent, uint8_t connectReturnCode)> OnConnAckInternalCallback;
typedef std::function<void()> OnPingRespInternalCallback;
typedef std::function<void(uint16_t packetId, char status)> OnSubAckInternalCallback;
typedef std::function<void(uint16_t packetId)> OnUnsubAckInternalCallback;
typedef std::function<void(char const *topic, char const *payload, uint8_t qos, bool dup, bool retain, size_t len, size_t index, size_t total, uint16_t packetId)> OnMessageInternalCallback;
typedef std::function<void(uint16_t packetId, uint8_t qos)> OnPublishInternalCallback;
typedef std::function<void(uint16_t packetId)> OnPubRelInternalCallback;
typedef std::function<void(uint16_t packetId)> OnPubAckInternalCallback;
typedef std::function<void(uint16_t packetId)> OnPubRecInternalCallback;
typedef std::function<void(uint16_t packetId)> OnPubCompInternalCallback;
}  // namespace AsyncMqttClientInternals
