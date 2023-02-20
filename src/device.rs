use crate::errors::{Error, ResponseError};

#[async_trait::async_trait]
pub trait Device {
    type Characteristic;

    async fn get_device_by_name(name: &str) -> Result<Self, Error> where Self: Sized;

    async fn read(&self, characteristic: &Self::Characteristic) -> Result<Vec<u8>, Error>;
    async fn write(&self, characteristic: &Self::Characteristic, cmd: &[u8]) -> Result<(), ResponseError>;
    async fn get_notifications(&self, n: usize) -> Result<Vec<Vec<u8>>, Error>;
    async fn disconnect(&self) -> Result<(), Error>;
    fn get_version_characteristic(&self) -> &Self::Characteristic;
    fn get_raw_transfer_characteristic(&self) -> &Self::Characteristic;
}
