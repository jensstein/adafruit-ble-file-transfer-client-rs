mod errors;
mod response_types;

use std::time::{Duration, SystemTime};
use std::pin::Pin;

use futures::{Stream, stream::StreamExt};

// Import traits as _ to avoid name clashes with the identically named structs
use btleplug::api::{Manager as _, Central as _, Peripheral as _, ScanFilter,
    WriteType, Characteristic, ValueNotification};
use btleplug::platform::{Adapter, Manager, Peripheral};

use crate::response_types::{Response, ListDirectoryResponse, ReadFileResponse,
    WriteFileResponse, DeleteFileResponse, MakeDirectoryResponse,
    MoveFileOrDirectoryResponse};
use crate::errors::{Error, ResponseError};

// https://github.com/deviceplug/btleplug/blob/master/examples/subscribe_notify_characteristic.rs
// https://github.com/adafruit/Adafruit_CircuitPython_BLE_File_Transfer
// https://github.com/adafruit/Adafruit_CircuitPython_BLE_File_Transfer/blob/main/examples/ble_file_transfer_simpletest.py
// https://github.com/adafruit/Adafruit_CircuitPython_BLE_File_Transfer/blob/main/examples/ble_file_transfer_stub_server.py

enum StatusType {
    Success,
    MissingFile,
    ReadOnly,
    Unknown(u8)
}

impl From<u8> for StatusType {
    fn from(value: u8) -> Self {
        match value {
            0x01 => Self::Success,
            0x02 => Self::MissingFile,
            0x05 => Self::ReadOnly,
            _ => Self::Unknown(value),
        }
    }
}

#[allow(clippy::from_over_into)] // It doesn't make sense to convert from a string to a status type
impl Into<String> for StatusType {
    fn into(self) -> String {
        match self {
            Self::Success => "OK".to_string(),
            Self::MissingFile => "Missing file".to_string(),
            Self::ReadOnly => "Read-only filesystem".to_string(),
            Self::Unknown(value) => format!("Unknown error: {value:#04x}"),
        }
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

pub struct AdafruitFileTransferClient {
    device: Peripheral,
    version_characteristic: Characteristic,
    raw_transfer_characteristic: Characteristic,
}

impl AdafruitFileTransferClient {
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

    pub async fn new_from_device_name(name: &str) -> Result<Self, Error> {
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

    pub async fn disconnect(&self) -> Result<(), Error> {
        self.device.disconnect().await?;
        Ok(())
    }

    pub async fn get_version(&self) -> Result<Option<u32>, Error> {
        let result = self.device.read(&self.version_characteristic).await?;
        let get_result_str = || {
            result.iter().map(|b| b.to_string()).collect::<Vec<String>>().join(",")
        };
        if result.len() == 4 {
            let version = u32::from_le_bytes(result[..4].try_into()
                .map_err(|error| {
                    let result_str = get_result_str();
                    Error::new(&format!("Error trying to get 32-bit version number from bytes {result_str}: {error}"))
                })?);
            return Ok(Some(version));
        }
        let result_str = get_result_str();
        log::warn!("Version response {result_str} wasn't 32-bit as expected");
        Ok(None)
    }

    async fn write(&self, cmd: &[u8]) -> Result<(), ResponseError> {
        self.device.write(&self.raw_transfer_characteristic, cmd, WriteType::WithoutResponse).await?;
        Ok(())
    }

    pub async fn read_file(&self, filename: &str) -> Result<Vec<u8>, Error> {
        let path_len = u16::to_le_bytes(filename.len() as u16);
        let cmd = [0x10, 0x00];
        // chunk size: 0x0200 = 512
        let cmd = [cmd.as_ref(), path_len.as_ref(), &[0, 0, 0, 0], &[0, 2, 0, 0], filename.as_bytes()].concat();
        self.write(&cmd).await?;
        let response = self.get_response_from_notification::<ReadFileResponse>().await?;
        let mut file_contents = response.contents;
        if response.chunk_length < response.total_length {
            let mut offset = 0;
            let mut chunk_length = 0;
            while (offset + chunk_length) < response.total_length {
                let offset_bytes = u32::to_le_bytes(offset);
                let subcmd = [&[0x12, 0x01, 0, 0], offset_bytes.as_ref(), &[0, 2, 0, 0]].concat();
                self.write(&subcmd).await?;
                let response2 = self.get_response_from_notification::<ReadFileResponse>().await?;
                file_contents.extend_from_slice(&response2.contents);
                offset = response2.offset;
                chunk_length = response2.chunk_length;
            }
        }
        Ok(file_contents)
    }

    pub async fn write_file<F>(&self, filename: &str, data: &[u8], callback: F) -> Result<(), Error> 
            where F: Fn(&WriteFileResponse) {
        let path_len = u16::to_le_bytes(filename.len() as u16);
        let data_len = u32::to_le_bytes(data.len() as u32);
        let current_time = get_current_time();
        let cmd = [&[0x20, 0], path_len.as_ref(), &u32::to_le_bytes(0),
            current_time.as_ref(), data_len.as_ref(), filename.as_bytes()].concat();
        self.write(&cmd).await?;
        let r = self.get_response_from_notification::<WriteFileResponse>().await?;
        callback(&r);
        if r.status == 0x01 {
            let batch_size = 32;
            for i in (0..data.len()).step_by(batch_size) {
                let end = if (i + batch_size) >= data.len() {
                    data.len()
                } else {
                    i + batch_size
                };
                let data_to_send = &data[i..end];
                let subcmd = [&[0x22, 0x01, 0, 0],
                    u32::to_le_bytes(i as u32).as_ref(),
                    u32::to_le_bytes(data_to_send.len() as u32).as_ref(),
                    data_to_send].concat();
                self.write(&subcmd).await?;
                let subresult = self.get_response_from_notification::<WriteFileResponse>().await?;
                callback(&subresult);
            }
        }
        Ok(())
    }

    pub async fn delete_file_or_directory(&self, path: &str) -> Result<DeleteFileResponse, Error> {
        let cmd = [&[0x30, 0], u16::to_le_bytes(path.len() as u16).as_ref(),
            path.as_bytes()].concat();
        self.write(&cmd).await?;
        let result = self.get_response_from_notification::<DeleteFileResponse>().await?;
        Ok(result)
    }

    pub async fn make_directory(&self, path: &str) -> Result<MakeDirectoryResponse, Error> {
        let current_time = get_current_time();
        let cmd = [&[0x40, 0], u16::to_le_bytes(path.len() as u16).as_ref(),
            &[0, 0, 0, 0], current_time.as_ref(), path.as_bytes()].concat();
        self.write(&cmd).await?;
        let result = self.get_response_from_notification::<MakeDirectoryResponse>().await?;
        Ok(result)
    }

    pub async fn list_directory(&self, directory: &str) -> Result<Vec<ListDirectoryResponse>, Error> {
        let path_len = u16::to_le_bytes(directory.len() as u16);
        let cmd = [0x50, 0x00];
        let cmd = [cmd.as_ref(), path_len.as_ref(), directory.as_bytes()].concat();
        self.write(&cmd).await?;
        let mut responses = vec![];
        let r = self.get_response_from_notification::<ListDirectoryResponse>().await?;
        responses.push(r);
        let mut stream = self.get_notification_stream(responses[0].total_entries as usize).await?;
        while let Some(data) = stream.next().await {
            let r2 = ListDirectoryResponse::from_bytes(&data.value)?;
            check_status(&r2)?;
            responses.push(r2);
        }
        let final_response = &responses[responses.len() - 1];
        if final_response.path_length == 0 && final_response.path.is_none() {
            responses.pop();
        }
        Ok(responses)
    }

    pub async fn move_file_or_directory(&self, src: &str, dest: &str) -> Result<MoveFileOrDirectoryResponse, Error> {
        let cmd = [&[0x60, 0], u16::to_le_bytes(src.len() as u16).as_ref(),
            u16::to_le_bytes(dest.len() as u16).as_ref(), src.as_bytes(),
            &[0], dest.as_bytes()].concat();
        self.write(&cmd).await?;
        let result = self.get_response_from_notification::<MoveFileOrDirectoryResponse>().await?;
        Ok(result)
    }

    async fn get_notification_stream(&self, n: usize) ->
            Result<futures::stream::Take<Pin<Box<dyn Stream<Item = ValueNotification> +
            std::marker::Send>>>, Error> {
        Ok(self.device.notifications()
            .await?
            .take(n))
    }

    async fn get_single_notification(&self) -> Result<ValueNotification, Error> {
        self.get_notification_stream(1).await?.next().await.ok_or_else(||Error::new("No notification found"))
    }

    async fn get_response_from_notification<T>(&self) -> Result<T, Error> where T: Response {
        let result = self.get_single_notification().await?;
        let result = T::from_bytes(&result.value)?;
        check_status(&result)?;
        Ok(result)
    }
}


fn check_status(result: &dyn Response) -> Result<(), Error> {
    let status: StatusType = result.get_status().into();
    match status {
        StatusType::Success => Ok(()),
        _ => {
            let error_string: String = status.into();
            Err(Error::new(&format!("Received error from device: {error_string}")))
        },
    }
}

fn get_current_time() -> [u8; 8] {
    // https://stackoverflow.com/a/70337205
    match SystemTime::now().duration_since(
            SystemTime::UNIX_EPOCH) {
        Ok(duration_since_epoch) => u64::to_le_bytes(duration_since_epoch.as_nanos() as u64),
        Err(error) => {
            log::warn!("Error getting current time: {error}. Returning 0 instead.");
            u64::to_le_bytes(0u64)
        }
    }
}
