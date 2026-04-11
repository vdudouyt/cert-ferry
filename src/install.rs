use std::env;
use std::fs;
use std::process::Command;

use anyhow::{Result, ensure};
use log::info;

pub fn install_timer() -> Result<()> {
    let exe = env::current_exe()?;

    let service = include_str!("certferry-renew.service")
        .replace("%CERTFERRY_EXE%", &exe.display().to_string());
    let timer = include_str!("certferry-renew.timer");

    let svc_path = "/etc/systemd/system/certferry-renew.service";
    let tmr_path = "/etc/systemd/system/certferry-renew.timer";

    fs::write(svc_path, &service)?;
    info!("wrote {}", svc_path);

    fs::write(tmr_path, timer)?;
    info!("wrote {}", tmr_path);

    ensure!(
        Command::new("systemctl")
            .arg("daemon-reload")
            .status()?
            .success(),
        "systemctl daemon-reload failed"
    );
    ensure!(
        Command::new("systemctl")
            .args(["enable", "--now", "certferry-renew.timer"])
            .status()?
            .success(),
        "systemctl enable failed"
    );
    info!("certferry-renew.timer enabled and started");

    Ok(())
}
