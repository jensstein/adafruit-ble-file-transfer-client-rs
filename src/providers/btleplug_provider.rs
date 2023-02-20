use std::time::Duration;

use futures::stream::StreamExt;

// Import traits as _ to avoid name clashes with the identically named structs
use btleplug::api::{Manager as _, Central as _, Peripheral as _, ScanFilter,
    WriteType, Characteristic as BtleplugCharacteristic};
use btleplug::platform::{Adapter, Manager, Peripheral};

use crate::errors::{Error, ResponseError};
use crate::device::Device;

impl From<btleplug::Error> for Error {
    fn from(error: btleplug::Error) -> Self {
        Self::new(&format!("Error during bluetooth communication: {error}"))
    }
}

impl From<btleplug::Error> for ResponseError {
    fn from(error: btleplug::Error) -> Self {
        Self::new(&format!("Error during bluetooth communication: {error}"))
    }
}

async fn get_device_by_name(adapter: &Adapter, name: &str) -> Result<Option<Peripheral>, Error> {
    for p in adapter.peripherals().await? {
        if let Some(props) = p.properties().await? {
            if props.local_name == Some(name.into()) {
                return Ok(Some(p));
            }
        }
    }
    Ok(None)
}

/// The struct implementing the central [`Device`](crate::device::Device) trait.
/// Available when the `btleplug-provider` feature is selected.
pub struct BtleplugDevice {
    device: Peripheral,
    version_characteristic: BtleplugCharacteristic,
    raw_transfer_characteristic: BtleplugCharacteristic,
}

impl BtleplugDevice {
    /// Subscribe to notifications and find characteristics from a device
    pub async fn new(device: Peripheral) -> Result<Self, Error> {
        device.discover_services().await?;
        let characteristics = device.characteristics();
        let version_characteristic = characteristics
            .iter()
            .find(|c| c.uuid == uuid::uuid!("adaf0100-4669-6c65-5472-616e73666572"))
            .ok_or_else(||Error::new("No characteristic found for adaf0100-4669-6c65-5472-616e73666572"))?
            .to_owned();
        let raw_transfer_characteristic = characteristics
            .iter()
            .find(|c| c.uuid == uuid::uuid!("adaf0200-4669-6c65-5472-616e73666572"))
            .ok_or_else(||Error::new("No characteristic found for adaf0200-4669-6c65-5472-616e73666572"))?
            .to_owned();
        device.subscribe(&raw_transfer_characteristic).await?;
        Ok(Self {
            device,
            version_characteristic,
            raw_transfer_characteristic,
        })
    }
}

#[async_trait::async_trait]
impl Device for BtleplugDevice {
    type Characteristic = BtleplugCharacteristic;

    async fn get_device_by_name(name: &str) -> Result<Self, Error> where Self: Sized {
        let manager = Manager::new().await?;
        let adapter = manager.adapters()
            .await?
            .into_iter()
            .next().ok_or_else(||Error::new("No bluetooth adapter available"))?;
        adapter.start_scan(ScanFilter::default()).await?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        let device = get_device_by_name(&adapter, name).await?
            .ok_or_else(||Error::new(&format!("No device found with name {name}")))?;
        device.connect().await?;
        device.discover_services().await?;
        Self::new(device).await
    }

    async fn read(&self, characteristic: &Self::Characteristic)  -> Result<Vec<u8>, Error> {
        Ok(self.device.read(characteristic).await?)
    }

    async fn write(&self, characteristic: &Self::Characteristic, cmd: &[u8]) -> Result<(), ResponseError> {
        self.device.write(characteristic, cmd, WriteType::WithoutResponse).await?;
        Ok(())
    }

    // https://github.com/deviceplug/btleplug/blob/master/examples/subscribe_notify_characteristic.rs
    async fn get_notifications(&self, n: usize) -> Result<Vec<Vec<u8>>, Error> {
        Ok(self.device.notifications()
            .await?
            .take(n)
            .map(|item| item.value)
            .collect::<Vec<Vec<u8>>>()
            .await)
    }

    async fn disconnect(&self) -> Result<(), Error> {
        Ok(self.device.disconnect().await?)
    }

    fn get_version_characteristic(&self) -> &Self::Characteristic {
        &self.version_characteristic
    }

    fn get_raw_transfer_characteristic(&self) -> &Self::Characteristic {
        &self.raw_transfer_characteristic
    }
}
