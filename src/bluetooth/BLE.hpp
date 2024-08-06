#include <BLEDevice.h>
#include <Stream.h>
#include "../misc/FIFOBuffer.h"

#define BLE_RX_BUFFER_SIZE 256
#define BLE_TX_BUFFER_SIZE ESP_GATT_MAX_ATTR_LEN


class BLECallbacks : public BLESecurityCallbacks, public BLEServerCallbacks, public BLECharacteristicCallbacks {
    public:
        bool onConfirmPIN(uint32_t passkey);
        bool onSecurityRequest();
        void onPassKeyNotify(uint32_t passkey);
        uint32_t onPassKeyRequest();
        void onAuthenticationComplete(esp_ble_auth_cmpl_t cmpl);
        void onConnect(BLEServer *server);
        void onDisconnect(BLEServer *server);
        void onWrite(BLECharacteristic *chr);
};

class BLESerial : public Stream {
    public:
        void bt_start();
        bool bt_setup_hw();
        void stop();
        // From Stream & Print
        virtual size_t write(uint8_t byte);
        //virtual size_t write(const uint8_t *buffer, size_t size);
        virtual int available();
        virtual int read();
        virtual int peek();
        virtual void flush();

        BLEAdvertising *Advertising;
        FIFOBuffer rxFIFO;
        volatile uint16_t rxFIFOLength;
    private:
        BLEServer *_server;
        BLEService *_service;
        BLECharacteristic *_txchr;
        BLECharacteristic *_rxchr;
        BLESecurity *_security;
        uint8_t _rxBuffer[BLE_RX_BUFFER_SIZE];
        FIFOBuffer _txFIFO;
        uint8_t _txBuffer[BLE_TX_BUFFER_SIZE];
};
