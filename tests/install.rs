/// These tests verify the systemd unit templates without actually installing them.

#[test]
fn service_template_has_placeholder() {
    let template = include_str!("../src/certferry-renew.service");
    assert!(template.contains("%CERTFERRY_EXE%"));
}

#[test]
fn service_template_substitution_works() {
    let template = include_str!("../src/certferry-renew.service");
    let result = template.replace("%CERTFERRY_EXE%", "/usr/local/bin/certferry");
    assert!(result.contains("ExecStart=/usr/local/bin/certferry --renew"));
    assert!(!result.contains("%CERTFERRY_EXE%"));
}

#[test]
fn service_template_has_required_sections() {
    let template = include_str!("../src/certferry-renew.service");
    assert!(template.contains("[Unit]"));
    assert!(template.contains("[Service]"));
    assert!(template.contains("Type=oneshot"));
}

#[test]
fn timer_template_has_required_sections() {
    let timer = include_str!("../src/certferry-renew.timer");
    assert!(timer.contains("[Unit]"));
    assert!(timer.contains("[Timer]"));
    assert!(timer.contains("[Install]"));
    assert!(timer.contains("WantedBy=timers.target"));
}

#[test]
fn timer_runs_twice_daily() {
    let timer = include_str!("../src/certferry-renew.timer");
    assert!(timer.contains("OnCalendar=*-*-* 00/12:00:00"));
}

#[test]
fn timer_has_randomized_delay() {
    let timer = include_str!("../src/certferry-renew.timer");
    assert!(timer.contains("RandomizedDelaySec=3600"));
}

#[test]
fn timer_is_persistent() {
    let timer = include_str!("../src/certferry-renew.timer");
    assert!(timer.contains("Persistent=true"));
}

#[test]
fn no_placeholder_after_substitution() {
    let template = include_str!("../src/certferry-renew.service");
    let result = template.replace("%CERTFERRY_EXE%", "/usr/bin/certferry");
    assert!(!result.contains('%'), "no placeholders should remain");
}
