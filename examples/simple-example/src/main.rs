use adafruit_ble_fs_client::AdafruitFileTransferClient;
use adafruit_ble_fs_client::providers::btleplug_provider::BtleplugDevice;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <device-name>", args[0]);
        std::process::exit(1);
    }
    let client = AdafruitFileTransferClient::<BtleplugDevice>::new_from_device_name(&args[1])
        .await
        .expect("Unable to get device");
    let version = client.get_version().await
        .expect("Unable to get adafruit ble-fs version");
    println!("Your client is running adafruit ble-fs version {version:?}");
    let files = client.list_directory("/").await.expect("Unable to list directory /");
    println!("Files in /:");
    for file in files {
        if file.path.is_some() {
            println!("\t{}", file.path.unwrap_or_else(|| "Missing path".into()));
        }
    }
    client.write_file("test-new-file", &[1, 2, 3, 4], |_| {}).await.expect("Unanble to write file");
    println!("Contents of new file: {:?}", client.read_file("/test-new-file").await);
    client.delete_file_or_directory("/test-new-file").await.expect("Unable to delete file");

    client.disconnect().await.expect("Unable to disconnect");
}
