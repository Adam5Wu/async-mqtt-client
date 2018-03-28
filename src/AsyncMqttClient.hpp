#pragma once

#include <functional>
#include <vector>

#include "Arduino.h"

#ifdef ESP32
#include <AsyncTCP.h>
#elif defined(ESP8266)
#include <ESPAsyncTCP.h>
#else
#error Platform not supported
#endif

#if ASYNC_TCP_SSL_ENABLED

#ifndef SSL_VERIFY_BY_FINGERPRINT
#define SSL_VERIFY_BY_FINGERPRINT 0
#endif

#if ASYNC_TCP_SSL_AXTLS
#include <tcp_axtls.h>
#if SSL_VERIFY_BY_FINGERPRINT
#define SHA1_SIZE 20
#endif
#endif

#endif

#include "AsyncMqttClient/Flags.hpp"
#include "AsyncMqttClient/ParsingInformation.hpp"
#include "AsyncMqttClient/MessageProperties.hpp"
#include "AsyncMqttClient/Helpers.hpp"
#include "AsyncMqttClient/Callbacks.hpp"
#include "AsyncMqttClient/DisconnectReasons.hpp"
#include "AsyncMqttClient/Storage.hpp"

#include "AsyncMqttClient/Packets/Packet.hpp"
#include "AsyncMqttClient/Packets/ConnAckPacket.hpp"
#include "AsyncMqttClient/Packets/PingRespPacket.hpp"
#include "AsyncMqttClient/Packets/SubAckPacket.hpp"
#include "AsyncMqttClient/Packets/UnsubAckPacket.hpp"
#include "AsyncMqttClient/Packets/PublishPacket.hpp"
#include "AsyncMqttClient/Packets/PubRelPacket.hpp"
#include "AsyncMqttClient/Packets/PubAckPacket.hpp"
#include "AsyncMqttClient/Packets/PubRecPacket.hpp"
#include "AsyncMqttClient/Packets/PubCompPacket.hpp"

class AsyncMqttClient {
 public:
  AsyncMqttClient();
  ~AsyncMqttClient();

  AsyncMqttClient& setKeepAlive(uint16_t keepAlive);
  AsyncMqttClient& setClientId(String const &clientId);
  AsyncMqttClient& setCleanSession(bool cleanSession);
  AsyncMqttClient& setMaxTopicLength(uint16_t maxTopicLength);
  AsyncMqttClient& setCredentials(String const &username, String const &password = String::EMPTY);
  AsyncMqttClient& setWill(String const &topic, uint8_t qos, bool retain, String const &payload = String::EMPTY);
  AsyncMqttClient& setServer(IPAddress ip, uint16_t port);
  AsyncMqttClient& setServer(String const &host, uint16_t port);
#if ASYNC_TCP_SSL_ENABLED
  AsyncMqttClient& setSecure(bool secure);
#if ASYNC_TCP_SSL_AXTLS && SSL_VERIFY_BY_FINGERPRINT
  AsyncMqttClient& addServerFingerprint(const uint8_t* fingerprint);
#endif
#if ASYNC_TCP_SSL_BEARSSL
  AsyncMqttClient& onSSLCertLookup(AsyncMqttClientInternals::OnSSLCertLookupCallback const &callback);
#endif
#endif

  AsyncMqttClient& onConnect(AsyncMqttClientInternals::OnConnectUserCallback const &callback);
  AsyncMqttClient& onDisconnect(AsyncMqttClientInternals::OnDisconnectUserCallback const &callback);
  AsyncMqttClient& onSubscribe(AsyncMqttClientInternals::OnSubscribeUserCallback const &callback);
  AsyncMqttClient& onUnsubscribe(AsyncMqttClientInternals::OnUnsubscribeUserCallback const &callback);
  AsyncMqttClient& onMessage(AsyncMqttClientInternals::OnMessageUserCallback const &callback);
  AsyncMqttClient& onPublish(AsyncMqttClientInternals::OnPublishUserCallback const &callback);

  bool connected() const;
  void connect();
  void disconnect(bool force = false);
  uint16_t subscribe(String const &topic, uint8_t qos);
  uint16_t unsubscribe(String const &topic);
  uint16_t publish(String const &topic, uint8_t qos, bool retain, String const &payload = String::EMPTY,
    bool dup = false, uint16_t message_id = 0);

 private:
  AsyncClient _client;

  bool _connected;
  bool _connectPacketNotEnoughSpace;
  bool _disconnectFlagged;
  uint32_t _lastClientActivity;
  uint32_t _lastServerActivity;
  uint32_t _lastPingRequestTime;

  IPAddress _ip;
  String _host;
#if ASYNC_TCP_SSL_ENABLED
  bool _secure;
#if ASYNC_TCP_SSL_AXTLS && SSL_VERIFY_BY_FINGERPRINT
  bool _tlsVerifyFailed;
#endif
#endif
  uint16_t _port;
  uint16_t _keepAlive;
  bool _cleanSession;
  String _clientId;
  String _username;
  String _password;
  String _willTopic;
  String _willPayload;
  uint8_t _willQos;
  bool _willRetain;

#if ASYNC_TCP_SSL_ENABLED
#if ASYNC_TCP_SSL_AXTLS && SSL_VERIFY_BY_FINGERPRINT
  std::vector<std::array<uint8_t, SHA1_SIZE>> _secureServerFingerprints;
#endif
#if ASYNC_TCP_SSL_BEARSSL
  AsyncMqttClientInternals::OnSSLCertLookupCallback _onSSLCertLookupCallback;
  int _onSSLCertLookup(AsyncClient* client, void *dn_hash, size_t dn_hash_len, uint8_t **buf);
#endif
#endif

  AsyncMqttClientInternals::OnConnectUserCallback _onConnectUserCallback;
  AsyncMqttClientInternals::OnDisconnectUserCallback _onDisconnectUserCallback;
  AsyncMqttClientInternals::OnSubscribeUserCallback _onSubscribeUserCallback;
  AsyncMqttClientInternals::OnUnsubscribeUserCallback _onUnsubscribeUserCallback;
  AsyncMqttClientInternals::OnMessageUserCallback _onMessageUserCallback;
  AsyncMqttClientInternals::OnPublishUserCallback _onPublishUserCallback;

  AsyncMqttClientInternals::ParsingInformation _parsingInformation;
  AsyncMqttClientInternals::Packet* _currentParsedPacket;
  uint8_t _remainingLengthBufferPosition;
  char _remainingLengthBuffer[4];

  uint16_t _nextPacketId;

  std::vector<AsyncMqttClientInternals::PendingPubRel> _pendingPubRels;
  std::vector<AsyncMqttClientInternals::PendingAck> _toSendAcks;

  void _clear();
  void _freeCurrentParsedPacket();

  // TCP
  void _onConnect(AsyncClient* client);
  void _onDisconnect(AsyncClient* client);
  static void _onError(AsyncClient* client, err_t error);
  void _onTimeout(AsyncClient* client, uint32_t time);
  static void _onAck(AsyncClient* client, size_t len, uint32_t time);
  void _onData(AsyncClient* client, char* data, size_t len);
  void _onPoll(AsyncClient* client);

  // MQTT
  void _onPingResp();
  void _onConnAck(bool sessionPresent, uint8_t connectReturnCode);
  void _onSubAck(uint16_t packetId, char status);
  void _onUnsubAck(uint16_t packetId);
  void _onMessage(char const *topic, char const *payload, uint8_t qos, bool dup, bool retain, size_t len, size_t index, size_t total, uint16_t packetId);
  void _onPublish(uint16_t packetId, uint8_t qos);
  void _onPubRel(uint16_t packetId);
  void _onPubAck(uint16_t packetId);
  void _onPubRec(uint16_t packetId);
  void _onPubComp(uint16_t packetId);

  bool _sendPing();
  void _sendAcks();
  bool _sendDisconnect();

  uint16_t _getNextPacketId();
};
