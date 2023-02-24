use crate::errors::{Error, ResponseError};

// The associated type on the trait requires mockall to have a concrete type specified
#[cfg_attr(test, mockall::automock(type Characteristic=u8;))]
#[async_trait::async_trait]
/// Abstraction for communication with a BLE device
pub trait Device {
    /// A GATT characteristic
    type Characteristic;

    /// Instantiate a new device by looking it up by name
    async fn get_device_by_name(name: &str) -> Result<Self, Error> where Self: Sized;

    /// Read data from a device given a characteristic
    async fn read(&self, characteristic: &Self::Characteristic) -> Result<Vec<u8>, Error>;
    /// Write data to a device given a characteristic
    async fn write(&self, characteristic: &Self::Characteristic, cmd: &[u8]) -> Result<(), ResponseError>;
    /// Read notifications from a device. You most likely need to subscribe to notifications
    /// beforehand.
    async fn get_notifications(&self, n: usize) -> Result<Vec<Vec<u8>>, Error>;
    /// Disconnect the device
    async fn disconnect(&self) -> Result<(), Error>;
    /// Return the specific version characteristic
    fn get_version_characteristic(&self) -> &Self::Characteristic;
    /// Return the characteristic used for raw data transfer
    fn get_raw_transfer_characteristic(&self) -> &Self::Characteristic;
}
