use std::{
    fs::OpenOptions,
    io::Write,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn log_path() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("sonetto-runtime.log")))
        .unwrap_or_else(|| PathBuf::from("sonetto-runtime.log"))
}

pub fn event(message: &str) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path())
    {
        let _ = writeln!(file, "{timestamp} {message}");
    }
}
