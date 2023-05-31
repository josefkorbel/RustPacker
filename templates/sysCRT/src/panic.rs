use std::panic;

#[panic_handler]
fn panic_handler(info: &panic::PanicInfo) {
    // Perform custom panic handling here
    // You can log the panic information to a file or any other desired output
    // For example, you can use the `log` crate or write to a file directly.
    // Remember to flush the output to ensure logs are written immediately.

    // Example: Writing the panic information to a file named `panic.log`
    if let Some(msg) = info.payload().downcast_ref::<&str>() {
        std::fs::write("panic.log", msg).unwrap();
    } else {
        std::fs::write("panic.log", format!("{:?}", info)).unwrap();
    }

    // Terminate the program after logging the panic
    std::process::exit(1);
}
