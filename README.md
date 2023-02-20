# Adafruit BLE file transfer client library

Client-side implementation of the Adafruit BLE file transfer protocol

Provides a client-side interface to interact with a device which exposes files with the
Adafruit BLE file transfer protocol.
The protocol is documented here: <https://github.com/adafruit/Adafruit_CircuitPython_BLE_File_Transfer#protocol>

This library is designed to enable you to bring your own bluetooth handler by implementing the
`adafruit_ble_fs_client::device::Device` trait. Or you can use the implementations in the
`adafruit_ble_fs_client::providers` module.

Example
```rust
use adafruit_ble_fs_client::AdafruitFileTransferClient;
use adafruit_ble_fs_client::providers::btleplug_provider::BtleplugDevice;

#[tokio::main]
async fn main() {
    let client = AdafruitFileTransferClient::<BtleplugDevice>::new_from_device_name("device-name")
        .await
        .unwrap();
    let version = client.get_version().await
        .unwrap();
    println!("Your client is running adafruit ble-fs version {version:?}");
    let files = client.list_directory("/").await.expect("Unable to list directory /");
    println!("Files in /: {files:?}");
}
```
