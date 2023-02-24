//! Client-side implementation of the Adafruit BLE file transfer protocol
//!
//! Provides a client-side interface to interact with a device which exposes files with the
//! Adafruit BLE file transfer protocol.
//! The protocol is documented here: <https://github.com/adafruit/Adafruit_CircuitPython_BLE_File_Transfer#protocol>
//!
//! This library is designed to enable you to bring your own bluetooth handler by implementing the
//! `adafruit_ble_fs_client::device::Device` trait. Or you can use the implementations in the
//! `adafruit_ble_fs_client::providers` module.
//!
//! Example
//! ```rust,ignore
//! use adafruit_ble_fs_client::AdafruitFileTransferClient;
//! use adafruit_ble_fs_client::providers::btleplug_provider::BtleplugDevice;
//!
//! #[tokio::main]
//! async fn main() {
//!     let client = AdafruitFileTransferClient::<BtleplugDevice>::new_from_device_name("device-name")
//!         .await
//!         .unwrap();
//!     let version = client.get_version().await
//!         .unwrap();
//!     println!("Your client is running adafruit ble-fs version {version:?}");
//!     let files = client.list_directory("/").await.expect("Unable to list directory /");
//!     println!("Files in /: {files:?}");
//! }
//! ```

#![warn(missing_docs)]
#![deny(missing_docs)]
#![deny(rustdoc::missing_doc_code_examples)]

mod device;
mod errors;
mod response_types;

/// Contains implementations of the [`Device`](crate::device::Device) trait for different bluetooth handlers
pub mod providers;

use std::time::SystemTime;

use crate::response_types::{Response, ListDirectoryResponse, ReadFileResponse,
    WriteFileResponse, DeleteFileResponse, MakeDirectoryResponse,
    MoveFileOrDirectoryResponse};
pub use crate::errors::{Error, ResponseError};
/// Abstraction for communication with a BLE device
pub use crate::device::Device;

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

/// The main implementation of the file transfer protocol
#[derive(Debug)]
pub struct AdafruitFileTransferClient<D> where D: Device {
    device: D,
}

impl<D> AdafruitFileTransferClient<D> where D: Device {
    /// Get a client from a [`Device`](crate::device::Device)
    pub async fn new(device: D) -> Result<Self, Error> {
        Ok(Self {
            device,
        })
    }

    /// Instantiate a client by looking the device up by name
    pub async fn new_from_device_name(name: &str) -> Result<Self, Error> {
        Self::new(D::get_device_by_name(name).await?).await
    }

    /// Disconnect the client
    pub async fn disconnect(&self) -> Result<(), Error> {
        self.device.disconnect().await?;
        Ok(())
    }

    /// Get the version of the Adafruit BLE file transfer which the device supports
    pub async fn get_version(&self) -> Result<Option<u32>, Error> {
        let result = self.device.read(self.device.get_version_characteristic()).await?;
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
        self.device.write(self.device.get_raw_transfer_characteristic(), cmd).await?;
        Ok(())
    }

    /// Read the contents of a file
    pub async fn read_file(&self, filename: &str) -> Result<Vec<u8>, Error> {
        let path_len = u16::to_le_bytes(filename.len() as u16);
        let cmd = [0x10, 0x00];
        // chunk size: 0x0200 = 512
        let cmd = [cmd.as_ref(), path_len.as_ref(), &[0, 0, 0, 0], &[0, 2, 0, 0], filename.as_bytes()].concat();
        self.write(&cmd).await?;
        let response = self.get_response_from_notification::<ReadFileResponse>().await?;
        let mut file_contents = response.contents;
        if response.chunk_length < response.total_length {
            let mut offset = response.chunk_length;
            while offset < response.total_length {
                let offset_bytes = u32::to_le_bytes(offset);
                let subcmd = [&[0x12, 0x01, 0, 0], offset_bytes.as_ref(), &[0, 2, 0, 0]].concat();
                self.write(&subcmd).await?;
                let response2 = self.get_response_from_notification::<ReadFileResponse>().await?;
                file_contents.extend_from_slice(&response2.contents);
                offset = response2.offset + response2.chunk_length;
            }
        }
        Ok(file_contents)
    }

    /// Write contents into a file
    pub async fn write_file<F>(&self, filename: &str, data: &[u8], batch_size: usize, mut callback: F) -> Result<(), Error>
            where F: FnMut(&WriteFileResponse) {
        let path_len = u16::to_le_bytes(filename.len() as u16);
        let data_len = u32::to_le_bytes(data.len() as u32);
        let current_time = get_current_time();
        let cmd = [&[0x20, 0], path_len.as_ref(), &u32::to_le_bytes(0),
            current_time.as_ref(), data_len.as_ref(), filename.as_bytes()].concat();
        self.write(&cmd).await?;
        let r = self.get_response_from_notification::<WriteFileResponse>().await?;
        callback(&r);
        if r.status == 0x01 {
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

    /// Delete a file or directory
    pub async fn delete_file_or_directory(&self, path: &str) -> Result<DeleteFileResponse, Error> {
        let cmd = [&[0x30, 0], u16::to_le_bytes(path.len() as u16).as_ref(),
            path.as_bytes()].concat();
        self.write(&cmd).await?;
        let result = self.get_response_from_notification::<DeleteFileResponse>().await?;
        Ok(result)
    }

    /// Create a directory on the device
    pub async fn make_directory(&self, path: &str) -> Result<MakeDirectoryResponse, Error> {
        let current_time = get_current_time();
        let cmd = [&[0x40, 0], u16::to_le_bytes(path.len() as u16).as_ref(),
            &[0, 0, 0, 0], current_time.as_ref(), path.as_bytes()].concat();
        self.write(&cmd).await?;
        let result = self.get_response_from_notification::<MakeDirectoryResponse>().await?;
        Ok(result)
    }

    /// List the contents of the specified directory
    pub async fn list_directory(&self, directory: &str) -> Result<Vec<ListDirectoryResponse>, Error> {
        let path_len = u16::to_le_bytes(directory.len() as u16);
        let cmd = [0x50, 0x00];
        let cmd = [cmd.as_ref(), path_len.as_ref(), directory.as_bytes()].concat();
        self.write(&cmd).await?;
        let mut responses = vec![];
        let r = self.get_response_from_notification::<ListDirectoryResponse>().await?;
        responses.push(r);
        let notifications = self.device.get_notifications(responses[0].total_entries as usize).await?;
        for data in notifications.iter() {
            let r2 = ListDirectoryResponse::from_bytes(data)?;
            check_status(&r2)?;
            responses.push(r2);
        }
        let final_response = &responses[responses.len() - 1];
        if final_response.path_length == 0 && final_response.path.is_none() {
            responses.pop();
        }
        Ok(responses)
    }

    /// Move the specified file or directory to a new path
    pub async fn move_file_or_directory(&self, src: &str, dest: &str) -> Result<MoveFileOrDirectoryResponse, Error> {
        let cmd = [&[0x60, 0], u16::to_le_bytes(src.len() as u16).as_ref(),
            u16::to_le_bytes(dest.len() as u16).as_ref(), src.as_bytes(),
            &[0], dest.as_bytes()].concat();
        self.write(&cmd).await?;
        let result = self.get_response_from_notification::<MoveFileOrDirectoryResponse>().await?;
        Ok(result)
    }

    async fn get_single_notification(&self) -> Result<Vec<u8>, Error> {
        let result = self.device.get_notifications(1).await?;
        if result.is_empty() {
            return Err(Error::new("No notification found"));
        }
        Ok(result[0].to_owned())
    }

    async fn get_response_from_notification<T>(&self) -> Result<T, Error> where T: Response {
        let result = self.get_single_notification().await?;
        let result = T::from_bytes(&result)?;
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::device::MockDevice;
    use mockall::predicate::eq;
    use rand::RngCore;

    #[tokio::test]
    async fn get_version() {
        let mut mock_device = MockDevice::new();
        mock_device.expect_get_version_characteristic()
            .times(1)
            .return_const(1);
        mock_device.expect_read()
            .with(eq(1))
            .times(1)
            .return_const(Ok(vec![4, 0, 0, 0]));
        let client = AdafruitFileTransferClient::<MockDevice>::new(mock_device)
            .await.expect("Unable to get client");
        let version = client.get_version().await.expect("Unable to get version");
        assert_eq!(Some(4), version);
    }

    #[tokio::test]
    async fn read_file() {
        // The file contents are just 1024 random bytes. The point is that reading the file will be
        // cut into two 512 byte chunks.
        let mut rng = rand::thread_rng();
        let file_contents: &mut [u8; 1024] = &mut [0; 1024];
        rng.fill_bytes(file_contents);
        let mut mock_device = MockDevice::new();
        // First chunk:
        mock_device.expect_get_raw_transfer_characteristic()
            .times(2)
            .return_const(2);
        // This command corresponds to sending the filename "Filename"
        let cmd: &[u8] = &[0x10, 0, 8, 0, 0, 0, 0, 0, 0, 2, 0, 0, 70, 105, 108, 101, 110, 97, 109, 101];
        mock_device.expect_write()
            .with(eq(2), eq(cmd))
            .times(1)
            .return_const(Ok(()));
        let response = [&[0x11, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0],
            file_contents[0..512].as_ref()].concat();
        mock_device.expect_get_notifications()
            .with(eq(1))
            .times(1)
            .return_const(Ok(vec![response]));

        // Second chunk:
        let subcmd: &[u8] = &[0x12, 1, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0];
        mock_device.expect_write()
            .with(eq(2), eq(subcmd))
            .times(1)
            .return_const(Ok(()));
        let second_response = [&[0x11, 1, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0],
            file_contents[512..1024].as_ref()].concat();
        mock_device.expect_get_notifications()
            .with(eq(1))
            .times(1)
            .return_const(Ok(vec![second_response]));

        let client = AdafruitFileTransferClient::<MockDevice>::new(mock_device)
            .await.expect("Unable to get client");
        let contents = client.read_file("Filename").await.expect("Unable to read file");
        assert_eq!(file_contents.to_vec(), contents);
    }
}
