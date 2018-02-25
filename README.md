# Async MQTT client for ESP8266 and ESP32
[![Build Status](https://travis-ci.org/Adam5Wu/async-mqtt-client.svg?branch=adam5wu/master)](https://travis-ci.org/Adam5Wu/async-mqtt-client)
[![GitHub issues](https://img.shields.io/github/issues/Adam5Wu/async-mqtt-client.svg)](https://github.com/Adam5Wu/async-mqtt-client/issues)
[![GitHub forks](https://img.shields.io/github/forks/Adam5Wu/async-mqtt-client.svg)](https://github.com/Adam5Wu/async-mqtt-client/network)
[![License](https://img.shields.io/github/license/Adam5Wu/async-mqtt-client.svg)](./LICENSE)

An Arduino for ESP8266 and ESP32 asynchronous [MQTT](http://mqtt.org/) client implementation.
Works with BearSSL port, which brings compatiblility with brokers using ECDSA certificates, and supports SNI and [maximum fragment length negotiation](https://tools.ietf.org/html/rfc6066#page-8).

* [Upstream Project](https://github.com/marvinroger/async-mqtt-client)
* [Modifications of this fork](MODIFICATIONS.md)
* Requires:
	- [ESP8266 Arduino Core fork](https://github.com/Adam5Wu/Arduino-esp8266)
  - [ESPAsyncTCP fork](https://github.com/Adam5Wu/ESPAsyncTCP)
* Potentially interesting:
	- [ESP8266 BearSSL Port fork](https://github.com/Adam5Wu/bearssl-esp8266)
