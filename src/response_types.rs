use crate::errors::ResponseError;

pub trait Response {
    fn get_status(&self) -> u8;
    fn from_bytes(bytes: &[u8]) -> Result<Self, ResponseError> where Self: Sized;
}

trait NumberFromBytes {
    fn from_bytes_slice(bytes: &[u8]) -> Result<Self, ResponseError> where Self: Sized;
}

impl NumberFromBytes for u32 {
    fn from_bytes_slice(bytes: &[u8]) -> Result<Self, ResponseError> {
        Ok(u32::from_le_bytes(bytes.try_into()?))
    }
}

impl NumberFromBytes for u64 {
    fn from_bytes_slice(bytes: &[u8]) -> Result<Self, ResponseError> {
        Ok(u64::from_le_bytes(bytes.try_into()?))
    }
}

fn validate_header(bytes: &[u8], minimum_length: usize, command: u8) -> Result<(), ResponseError> {
    if bytes.is_empty() {
        return Err(ResponseError::new("Value passed is empty"));
    }
    if bytes.len() < minimum_length {
        return Err(ResponseError::new("Value passed is not long enough"));
    }
    if bytes[0] != command {
        return Err(ResponseError::new(&format!("Response command {:#04x} does not match the expected {:#04x}", bytes[0], command)));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ReadFileResponse {
    pub command: u8,
    pub status: u8,
    pub offset: u32,
    pub total_length: u32,
    pub chunk_length: u32,
    pub contents: Vec<u8>,
}

impl ReadFileResponse {
    fn _from_bytes(bytes: &[u8]) -> Result<Self, ResponseError> {
        validate_header(bytes, 10, 0x11)?;
        let chunk_length = from_slice::<u32>(&bytes[12..16])?;
        let contents = bytes[16..].to_vec();
        Ok(Self {
            command: bytes[0],
            status: bytes[1],
            offset: from_slice::<u32>(&bytes[4..8])?,
            total_length: from_slice::<u32>(&bytes[8..12])?,
            chunk_length,
            contents,
        })
    }
}

#[derive(Debug, Clone)]
pub struct WriteFileResponse {
    pub command: u8,
    pub status: u8,
    pub offset: u32,
    pub time: u64,
    pub free_space: u32,
}

impl WriteFileResponse {
    fn _from_bytes(bytes: &[u8]) -> Result<Self, ResponseError> {
        validate_header(bytes, 20, 0x21)?;
        Ok(Self {
            command: bytes[0],
            status: bytes[1],
            offset: from_slice::<u32>(&bytes[4..8])?,
            time: from_slice::<u64>(&bytes[8..16])?,
            free_space: from_slice::<u32>(&bytes[16..20])?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DeleteFileResponse {
    pub command: u8,
    pub status: u8,
}

impl DeleteFileResponse {
    fn _from_bytes(bytes: &[u8]) -> Result<Self, ResponseError> {
        validate_header(bytes, 2, 0x31)?;
        Ok(Self {
            command: bytes[0],
            status: bytes[1],
        })
    }
}

#[derive(Debug, Clone)]
pub struct MakeDirectoryResponse {
    pub command: u8,
    pub status: u8,
    pub time: u64,
}

impl MakeDirectoryResponse {
    fn _from_bytes(bytes: &[u8]) -> Result<Self, ResponseError> {
        validate_header(bytes, 16, 0x41)?;
        Ok(Self {
            command: bytes[0],
            status: bytes[1],
            time: from_slice::<u64>(&bytes[8..16])?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ListDirectoryResponse {
    pub command: u8,
    pub status: u8,
    pub path_length: u16,
    pub entry_number: u32,
    pub total_entries: u32,
    pub flags: u32,
    pub modification_time: u64,
    pub file_size: u32,
    pub path: Option<String>,
}

impl ListDirectoryResponse {
    fn _from_bytes(bytes: &[u8]) -> Result<Self, ResponseError> {
        validate_header(bytes, 28, 0x51)?;
        let path_length = u16::from_le_bytes([bytes[2], bytes[3]]);
        let expected_bytes_length = 28 + path_length;
        let bytes_len = bytes.len();
        if bytes_len != expected_bytes_length.into() {
            return Err(ResponseError::new(&format!("Length of value doesn't match expected. {bytes_len} != {expected_bytes_length}")));
        }
        let path = if path_length > 0 {
            Some(String::from_utf8(bytes[28..].into())?)
        } else {
            None
        };
        Ok(Self {
            command: bytes[0],
            status: bytes[1],
            path_length,
            entry_number: from_slice::<u32>(&bytes[4..8])?,
            total_entries: from_slice::<u32>(&bytes[8..12])?,
            flags: from_slice::<u32>(&bytes[12..16])?,
            modification_time: from_slice::<u64>(&bytes[16..24])?,
            file_size: from_slice::<u32>(&bytes[24..28])?,
            path,
        })
    }
}

#[derive(Debug, Clone)]
pub struct MoveFileOrDirectoryResponse {
    pub command: u8,
    pub status: u8,
}

impl MoveFileOrDirectoryResponse {
    fn _from_bytes(bytes: &[u8]) -> Result<Self, ResponseError> {
        validate_header(bytes, 2, 0x61)?;
        Ok(Self {
            command: bytes[0],
            status: bytes[1],
        })
    }
}

fn from_slice<T>(slice: &[u8]) -> Result<T, ResponseError>
        where T: NumberFromBytes {
    T::from_bytes_slice(slice)
}

/*
* In order to avoid duplicating the implementation for `get_status` on every struct with the same
* content, this macro handles the implementation for all the structs. But then to avoid E0119 when
* there are multiple implementations of the same trait for a given struct I have to provide an
* implementation for `from_bytes` here also. Since they differ, that implementation just
* references the specific struct's `_from_bytes`.
* https://stackoverflow.com/a/57736922
*/
macro_rules! impl_status {
    ($name:ident) => (
        impl Response for $name {
            fn from_bytes(bytes: &[u8]) -> Result<Self, ResponseError> {
                Self::_from_bytes(bytes)
            }
            fn get_status(&self) -> u8 {
                self.status
            }
        }
    )
}

impl_status!(ReadFileResponse);
impl_status!(WriteFileResponse);
impl_status!(DeleteFileResponse);
impl_status!(MakeDirectoryResponse);
impl_status!(ListDirectoryResponse);
impl_status!(MoveFileOrDirectoryResponse);
