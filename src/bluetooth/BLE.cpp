#include "BLE.hpp"

#include "esp_bt_main.h"
#include "esp_bt_device.h"
#include "esp32-hal-bt.h"
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include <BLE2902.h>

#include <EEPROM.h>
#include "../../MD5.h"
#include <SPI.h>
#include "../../Boards.h"
#include <cstddef>

// These UUIDs emulate the nordic BLE UART service
#define SERVICE_UUID "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
#define RX_UUID "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
#define TX_UUID "6e400003-b5a3-f393-e0a9-e50e24dcca9e"

// Bluetooth variables
// Todo, clean this up, it's a total mess
extern bool bt_enabled;
extern bool bt_ready;
extern bool bt_allow_pairing;
extern uint8_t bt_state;
extern uint8_t cable_state;
extern portMUX_TYPE update_lock;
extern void kiss_indicate_btpin();
extern BLESerial SerialBT;
#define BT_DEV_ADDR_LEN 6
#define BT_DEV_HASH_LEN 16
	#define BT_STATE_NA        0xff
	#define BT_STATE_OFF       0x00
	#define BT_STATE_ON        0x01
	#define BT_STATE_PAIRING   0x02
	#define BT_STATE_CONNECTED 0x03
	#define CABLE_STATE_DISCONNECTED 0x00
	#define CABLE_STATE_CONNECTED    0x01
  #define FEND            0xC0
extern char bt_da[BT_DEV_ADDR_LEN];
extern char bt_dh[BT_DEV_HASH_LEN];
extern char bt_devname[11];
extern uint32_t bt_ssp_pin;
#define eeprom_addr(a) (a+EEPROM_OFFSET)

bool BLECallbacks::onConfirmPIN(uint32_t passkey){
    return false;
}

bool BLECallbacks::onSecurityRequest(){
    return true;
}

void BLECallbacks::onPassKeyNotify(uint32_t passkey) {
    bt_ssp_pin = passkey;
    kiss_indicate_btpin();
}

uint32_t BLECallbacks::onPassKeyRequest() { return 0; }

void BLECallbacks::onAuthenticationComplete(esp_ble_auth_cmpl_t cmpl){
    bt_state = BT_STATE_CONNECTED;
    cable_state = CABLE_STATE_DISCONNECTED;
}

void BLECallbacks::onConnect(BLEServer *server) {
}

void BLECallbacks::onDisconnect(BLEServer *server) {
    bt_state = BT_STATE_ON;
    SerialBT.Advertising->start();
}

void BLECallbacks::onWrite(BLECharacteristic* chr) {
    if (chr->getUUID().toString() == RX_UUID) {
        std::string data = chr->getValue();
        
        for (int i = 0; i < data.length(); i++) {
            fifo_push(&SerialBT.rxFIFO, data[i]);
            SerialBT.rxFIFOLength++;
        }
    }
}

bool BLESerial::bt_setup_hw() {
  if (!bt_ready) {
    if (EEPROM.read(eeprom_addr(ADDR_CONF_BT)) == BT_ENABLE_BYTE) {
      bt_enabled = true;
    } else {
      bt_enabled = false;
    }
    if (btStart()) {
      if (esp_bluedroid_init() == ESP_OK) {
        if (esp_bluedroid_enable() == ESP_OK) {
          const uint8_t* bda_ptr = esp_bt_dev_get_address();
          char *data = (char*)malloc(BT_DEV_ADDR_LEN+1);
          for (int i = 0; i < BT_DEV_ADDR_LEN; i++) {
              data[i] = bda_ptr[i];
          }
          data[BT_DEV_ADDR_LEN] = EEPROM.read(eeprom_addr(ADDR_SIGNATURE));
          unsigned char *hash = MD5::make_hash(data, BT_DEV_ADDR_LEN);
          memcpy(bt_dh, hash, BT_DEV_HASH_LEN);
          sprintf(bt_devname, "RNode %02X%02X", bt_dh[14], bt_dh[15]);
          free(data);

          BLEDevice::init(bt_devname);
          BLEDevice::setEncryptionLevel(ESP_BLE_SEC_ENCRYPT);

          _security = new BLESecurity();
          _security->setKeySize();
          _security->setAuthenticationMode(ESP_LE_AUTH_REQ_SC_MITM_BOND); // Secure Connections with MITM Protection and bonding enabled.
          _security->setCapability(ESP_IO_CAP_OUT); // Display only
          _security->setInitEncryptionKey(ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK);

          // This ensures the remote device has actually entered the pin from
          // the device by forcing the set authentication mode (MITM_BOND).
          // This is because it is possible to bypass passkey entry in BLE by
          // simply changing the reported capabilities of your device
          // otherwise. Therefore, devices which have not authenticated
          // properly should not be allowed to pair in the first place.
          uint8_t own_auth_cfg_only = ESP_BLE_ONLY_ACCEPT_SPECIFIED_AUTH_ENABLE;
          esp_ble_gap_set_security_param(ESP_BLE_SM_ONLY_ACCEPT_SPECIFIED_SEC_AUTH, &own_auth_cfg_only, sizeof(uint8_t));

          _server = BLEDevice::createServer();
          _service = _server->createService(SERVICE_UUID);
          _txchr = _service->createCharacteristic(TX_UUID, BLECharacteristic::PROPERTY_NOTIFY);
          _rxchr = _service->createCharacteristic(RX_UUID, BLECharacteristic::PROPERTY_WRITE);
          _txchr->setAccessPermissions(ESP_GATT_PERM_READ_ENCRYPTED);
          _rxchr->setAccessPermissions(ESP_GATT_PERM_WRITE_ENCRYPTED);

          _txchr->addDescriptor(new BLE2902());
          _rxchr->addDescriptor(new BLE2902());

          _txchr->setReadProperty(true);
          _rxchr->setWriteProperty(true);

          BLECallbacks* callbacks = new BLECallbacks();

          _rxchr->setCallbacks(callbacks);
          _server->setCallbacks(callbacks);
          BLEDevice::setSecurityCallbacks(callbacks);
          Advertising = _server->getAdvertising();

          memset(_rxBuffer, 0, sizeof(_rxBuffer));
          fifo_init(&rxFIFO, _rxBuffer, BLE_RX_BUFFER_SIZE);
          memset(_txBuffer, 0, sizeof(_txBuffer));
          fifo_init(&_txFIFO, _txBuffer, BLE_TX_BUFFER_SIZE);

          rxFIFOLength = 0;

          bt_ready = true;
          return true;

        } else { return false; }
      } else { return false; }
    } else { return false; }
  } else { return false; }
}

void BLESerial::bt_start() {
    _service->start();
    Advertising->start();
}

void BLESerial::stop() {
    _service->stop();
    Advertising->stop();
}

size_t BLESerial::write(uint8_t byte) {
    bool endcmd = false;
    if ((!fifo_isempty(&_txFIFO)) && byte == FEND) {
        endcmd = true;
    }

    if (fifo_isfull(&_txFIFO)) {
        flush();
    }

    fifo_push(&_txFIFO, byte);

    if (endcmd) {
        flush();
    }
    return 1;
}

/*size_t BLESerial::write(const uint8_t *buffer, size_t size) {
    uint16_t written = 0;
    for (int i = 0; i < size; i++) {
        fifo_push(&_txFIFO, buffer[i]);
        written++;
    }
    flush();
    return written;
}*/

// todo, this can be removed once fifo_len function works as intended
int BLESerial::available() {
    return rxFIFOLength;
}

int BLESerial::read() {
    rxFIFOLength--;
    uint8_t byte = fifo_pop(&rxFIFO);
    delay(5);
    return byte;
}
int BLESerial::peek() {
    // doesn't work for the moment. todo, remove?
    return 0;
}
void BLESerial::flush() {
    uint8_t tx_buffer[BLE_TX_BUFFER_SIZE];
    uint16_t index = 0;
    while (!fifo_isempty(&_txFIFO)) {
        if (index == BLE_TX_BUFFER_SIZE) {
            _txchr->setValue(tx_buffer, index);
            _txchr->notify(true);
            index = 0;
        }

        tx_buffer[index] = fifo_pop(&_txFIFO);
        index++;
    }
    if (index > 0) {
        _txchr->setValue(tx_buffer, index);
        _txchr->notify(true);
    }
}
