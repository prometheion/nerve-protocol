//! The guard against changing the node (nerve_policy::guard), as one table:
//! every line with the shells it is checked in and the rule of the guard
//! that refuses it, or `None` for a line that runs. The forms of #154 are
//! here as they were refused or allowed then, but for the mentions the docs
//! listed as refused by mistake, which run now.

use std::path::Path;

use nerve_policy::command::Shell;
use nerve_policy::guard::Guard;
use nerve_policy::rules::{GUARD, GUARD_OLD, RuleSet, guard_missing, validate};

const SH: &[Shell] = &[Shell::Sh];
const PS: &[Shell] = &[Shell::PowerShell];
const CMD: &[Shell] = &[Shell::Cmd];
const WIN: &[Shell] = &[Shell::PowerShell, Shell::Cmd];
const ALL: &[Shell] = &[Shell::Sh, Shell::PowerShell, Shell::Cmd];

const PROGRAMS: Option<Guard> = Some(Guard::Programs);
const PATHS: Option<Guard> = Some(Guard::Paths);
const SERVICE: Option<Guard> = Some(Guard::Service);

type Case = (&'static str, &'static [Shell], Option<Guard>);

fn home() -> &'static Path {
    Path::new("/home/alice")
}

fn rules(list: &[&str]) -> Vec<String> {
    list.iter().map(|r| r.to_string()).collect()
}

/// Checks every case in each of its shells: refused by the whole guard and
/// by its rule alone, or allowed by the whole guard. Lists every miss.
fn check(cases: &[Case]) {
    let mut wrong = Vec::new();
    for (line, shells, want) in cases {
        for &shell in *shells {
            let all = RuleSet::new(&rules(GUARD), home()).with_shell(shell);
            let got = all.find("exec", "run", line);
            match want {
                None if got.is_some() => wrong.push(format!("{shell:?} refused {line:?}: {got:?}")),
                None => {}
                Some(g) => {
                    let one = RuleSet::new(&rules(&[g.rule()]), home()).with_shell(shell);
                    if one.find("exec", "run", line).is_none() {
                        wrong.push(format!("{shell:?} {g:?} did not refuse {line:?}"));
                    }
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// The forms of #154 that ran the node's programs or named its paths.
const NODE_ITSELF: &[Case] = &[
    ("nerve-node config set machine.user root", SH, PROGRAMS),
    ("nerve-node", SH, PROGRAMS),
    (
        "sudo /usr/local/bin/nerve-node-desktop mode set user",
        SH,
        PROGRAMS,
    ),
    ("sudo nerve-node rule rm deny 'rm *'", SH, PROGRAMS),
    ("cd /tmp && nerve-node status", SH, PROGRAMS),
    ("cd /tmp;nerve-node-desktop status", SH, PROGRAMS),
    ("true | nerve-node audit", SH, PROGRAMS),
    ("(nerve-node.exe panic)", SH, PROGRAMS),
    (
        "./target/release/nerve-node-desktop mode set user",
        SH,
        PROGRAMS,
    ),
    (
        "& 'C:/Program Files/Nerve/nerve-node-desktop.exe' config set node.name x",
        PS,
        PROGRAMS,
    ),
    ("socat - UNIX-CONNECT:/run/nerve-node/owner.sock", SH, PATHS),
    ("ls /run/nerve-node", SH, PATHS),
    ("echo x > //./pipe/nerve-node-owner", SH, PATHS),
    ("cat /etc/nerve/node.toml", SH, PATHS),
    ("rm -rf /var/lib/nerve/state", SH, PATHS),
    ("sed -i s/a/b/ ~/.config/nerve/node.toml", SH, PATHS),
    ("ls $HOME/.local/state/nerve", SH, PATHS),
    ("type %ProgramData%/Nerve/config/node.toml", CMD, PATHS),
    // A line break or a tab ends a command and its name like a space, and a
    // script line may be indented.
    ("cd /tmp\nnerve-node status", SH, PROGRAMS),
    ("cd /tmp\r\nnerve-node status", SH, PROGRAMS),
    ("nerve-node\necho x", SH, PROGRAMS),
    ("nerve-node\r\n", SH, PROGRAMS),
    ("echo hi\n  nerve-node status", SH, PROGRAMS),
    ("echo hi\n\tsudo nerve-node audit", SH, PROGRAMS),
    ("/usr/local/bin/nerve-node\tstatus", SH, PROGRAMS),
    ("/usr/local/bin/nerve-node\nls", SH, PROGRAMS),
    ("ls /run/nerve-node\n", SH, PATHS),
    ("cat /etc/nerve\nls", SH, PATHS),
    ("cat /var/lib/nerve\tx", SH, PATHS),
    ("cat ~/.config/nerve\r\nls", SH, PATHS),
    ("ls $HOME/.local/state/nerve\n", SH, PATHS),
    ("type %ProgramData%/Nerve\r\ndir", CMD, PATHS),
    // sudo and the keywords before a program.
    ("sudo -n nerve-node status", SH, PROGRAMS),
    ("if true; then nerve-node status; fi", SH, PROGRAMS),
    ("if true; then sudo nerve-node status; fi", SH, PROGRAMS),
    (
        "for i in 1; do sudo -u root nerve-node audit; done",
        SH,
        PROGRAMS,
    ),
    ("{ nerve-node status; }", SH, PROGRAMS),
    ("pkill -f /usr/local/bin/nerve-node", SH, SERVICE),
    ("/etc/init.d/nerve-node stop", SH, PROGRAMS),
    // What only mentions the node runs.
    (
        "git commit -m \"use sudo nerve-node audit to see it\"",
        SH,
        None,
    ),
    ("echo \"then run sudo nerve-node service stop\"", SH, None),
    ("ls ~/.config", SH, None),
    ("cargo build -p nerve-node", SH, None),
    ("cargo test -p nerve-node-desktop --test shots", SH, None),
    ("journalctl -u nerve-node", SH, None),
    ("grep -r nerve-node docs/", SH, None),
    ("git commit -m 'run nerve-node status'", SH, None),
    (
        "cargo build --manifest-path crates/nerve-node/Cargo.toml",
        SH,
        None,
    ),
    ("cat ~/.config/nerve-node-desktop/settings.json", SH, None),
    ("ls /etc/nervecenter", SH, None),
    ("git status", ALL, None),
];

/// The forms of #154 that stopped, restarted, disabled or killed the node's
/// service or process, and those that only read it.
const SERVICE_FORMS: &[Case] = &[
    ("systemctl stop nerve-node", SH, SERVICE),
    ("sudo systemctl stop nerve-node", SH, SERVICE),
    ("sudo -n systemctl stop nerve-node.service", SH, SERVICE),
    ("systemctl restart nerve-node", SH, SERVICE),
    ("systemctl try-restart nerve-node", SH, SERVICE),
    (
        "systemctl reload-or-restart nerve-node.service",
        SH,
        SERVICE,
    ),
    ("systemctl disable nerve-node", SH, SERVICE),
    ("systemctl disable --now nerve-node", SH, SERVICE),
    (
        "sudo systemctl --now disable nerve-node.service",
        SH,
        SERVICE,
    ),
    ("systemctl kill nerve-node", SH, SERVICE),
    ("systemctl kill -s KILL nerve-node", SH, SERVICE),
    (
        "systemctl kill --signal=SIGKILL nerve-node.service",
        SH,
        SERVICE,
    ),
    ("systemctl mask nerve-node", SH, SERVICE),
    ("systemctl mask --now nerve-node", SH, SERVICE),
    ("systemctl --no-block stop 'nerve-node'", SH, SERVICE),
    ("systemctl stop nerve-node nerve-center", SH, SERVICE),
    ("/usr/bin/systemctl stop nerve-node", SH, SERVICE),
    (
        "sudo /bin/systemctl restart nerve-node.service",
        SH,
        SERVICE,
    ),
    ("cd /tmp && sudo systemctl stop nerve-node", SH, SERVICE),
    ("true; systemctl stop nerve-node", SH, SERVICE),
    ("(systemctl stop nerve-node)", SH, SERVICE),
    ("sc stop nerve-node", WIN, SERVICE),
    ("sc.exe stop nerve-node", WIN, SERVICE),
    ("sc config nerve-node start= disabled", WIN, SERVICE),
    ("sc.exe config nerve-node start= disabled", WIN, SERVICE),
    ("sc delete nerve-node", WIN, SERVICE),
    ("sc \\\\host stop nerve-node", WIN, SERVICE),
    ("sc stop \"nerve-node\"", WIN, SERVICE),
    (
        "C:\\Windows\\System32\\sc.exe stop nerve-node",
        WIN,
        SERVICE,
    ),
    ("Stop-Service nerve-node", PS, SERVICE),
    ("Stop-Service -Name nerve-node", PS, SERVICE),
    ("Stop-Service -Name nerve-node -Force", PS, SERVICE),
    ("Stop-Service -Name:nerve-node", PS, SERVICE),
    ("Stop-Service -Name \"nerve-node\"", PS, SERVICE),
    ("stop-service nerve-node", PS, SERVICE),
    ("Restart-Service nerve-node", PS, SERVICE),
    ("Restart-Service -Name nerve-node -Force", PS, SERVICE),
    (
        "Set-Service -Name nerve-node -StartupType Disabled",
        PS,
        SERVICE,
    ),
    ("Set-Service nerve-node -StartupType Disabled", PS, SERVICE),
    ("Remove-Service nerve-node", PS, SERVICE),
    ("cd C:\\ ; Stop-Service nerve-node", PS, SERVICE),
    ("& Stop-Service nerve-node", PS, SERVICE),
    ("Get-Service nerve-node | Stop-Service", PS, SERVICE),
    (
        "Get-Service nerve-node | Restart-Service -Force",
        PS,
        SERVICE,
    ),
    (
        "Get-Service -Name nerve-node | Set-Service -StartupType Disabled",
        PS,
        SERVICE,
    ),
    ("Get-Service nerve-node|Stop-Service", PS, SERVICE),
    (
        "Get-Service nerve-node | Select-Object Name | Stop-Service",
        PS,
        SERVICE,
    ),
    ("net stop nerve-node", WIN, SERVICE),
    ("net.exe stop nerve-node", WIN, SERVICE),
    ("net stop \"nerve-node\"", WIN, SERVICE),
    ("taskkill /im nerve-node.exe", WIN, SERVICE),
    ("taskkill /IM nerve-node.exe /F", WIN, SERVICE),
    ("taskkill /f /im nerve-node-desktop.exe", WIN, SERVICE),
    (
        "taskkill.exe /f /im nerve-node-desktop.exe /t",
        WIN,
        SERVICE,
    ),
    ("taskkill /fi \"IMAGENAME eq nerve-node.exe\"", WIN, SERVICE),
    ("Stop-Process -Name nerve-node", PS, SERVICE),
    ("Stop-Process -Name nerve-node-desktop -Force", PS, SERVICE),
    ("Stop-Process -Name nerve-node.exe", PS, SERVICE),
    ("stop-process -name:nerve-node", PS, SERVICE),
    ("Stop-Process -Force -Name \"nerve-node\"", PS, SERVICE),
    ("Get-Process nerve-node | Stop-Process", PS, SERVICE),
    (
        "Get-Process nerve-node-desktop | Stop-Process -Force",
        PS,
        SERVICE,
    ),
    (
        "Get-Process | Where-Object Name -eq nerve-node | Stop-Process",
        PS,
        SERVICE,
    ),
    // A line break or a tab ends a command and its name like a space.
    ("sudo systemctl restart nerve-node\necho done", SH, SERVICE),
    ("sudo systemctl restart nerve-node\n", SH, SERVICE),
    ("sudo systemctl restart nerve-node\t", SH, SERVICE),
    ("systemctl stop nerve-node\r\nsleep 1", SH, SERVICE),
    ("cd /srv\nsystemctl restart nerve-node", SH, SERVICE),
    ("cd /srv\r\nsystemctl restart nerve-node", SH, SERVICE),
    ("echo hi\n    systemctl stop nerve-node", SH, SERVICE),
    ("echo hi\n\tsudo systemctl stop nerve-node", SH, SERVICE),
    (
        "echo hi\n\n  sudo -n systemctl disable nerve-node.service",
        SH,
        SERVICE,
    ),
    ("sc stop nerve-node\nsc query nerve-node", WIN, SERVICE),
    ("Stop-Service nerve-node\nStart-Sleep 2", PS, SERVICE),
    ("Stop-Service nerve-node\r\nStart-Sleep 2", PS, SERVICE),
    ("Start-Sleep 1\nStop-Service nerve-node", PS, SERVICE),
    ("Get-Service nerve-node |\n  Stop-Service", PS, SERVICE),
    ("taskkill /im nerve-node.exe\ntasklist", WIN, SERVICE),
    ("Stop-Process -Name nerve-node\n", PS, SERVICE),
    // sudo with its flags.
    ("sudo -u root systemctl stop nerve-node", SH, SERVICE),
    (
        "cd x && sudo -u root systemctl restart nerve-node",
        SH,
        SERVICE,
    ),
    ("echo ok | sudo -n systemctl stop nerve-node", SH, SERVICE),
    // The SysV wrapper calls systemctl.
    ("service nerve-node stop", SH, SERVICE),
    ("sudo service nerve-node restart", SH, SERVICE),
    (
        "sudo -n service nerve-node.service try-restart",
        SH,
        SERVICE,
    ),
    ("/usr/sbin/service nerve-node force-reload", SH, SERVICE),
    ("service \"nerve-node\" stop", SH, SERVICE),
    ("service nerve-node condrestart; true", SH, SERVICE),
    ("service nerve-node stop\necho done", SH, SERVICE),
    ("cd /srv && service nerve-node restart", SH, SERVICE),
    // Killing the process by its name.
    ("pkill nerve-node", SH, SERVICE),
    ("sudo pkill nerve-node", SH, SERVICE),
    ("sudo killall nerve-node", SH, SERVICE),
    ("sudo pkill -f nerve-node", SH, SERVICE),
    ("pkill -9 -f 'nerve-node --config x'", SH, SERVICE),
    ("pkill -x \"nerve-node\"", SH, SERVICE),
    ("killall -s KILL nerve-node-desktop", SH, SERVICE),
    ("killall -9 nerve-node && echo gone", SH, SERVICE),
    ("pkill -u nerve -x nerve-node", SH, SERVICE),
    ("pkill '^nerve-node$'", SH, SERVICE),
    ("pkill -f nerve-node\nsleep 1", SH, SERVICE),
    ("/usr/bin/pkill nerve-node", SH, SERVICE),
    ("sudo -n killall -9 nerve-node; true", SH, SERVICE),
    // The Windows commands ignore case.
    ("STOP-SERVICE nerve-node", PS, SERVICE),
    ("Stop-service nerve-node", PS, SERVICE),
    ("RESTART-SERVICE -Name NERVE-NODE", PS, SERVICE),
    ("SET-SERVICE Nerve-Node -StartupType Disabled", PS, SERVICE),
    ("SC STOP nerve-node", WIN, SERVICE),
    ("sc stop Nerve-Node", WIN, SERVICE),
    ("SC.EXE CONFIG nerve-node start= disabled", WIN, SERVICE),
    ("Sc Delete NERVE-NODE", WIN, SERVICE),
    ("NET STOP nerve-node", WIN, SERVICE),
    ("Net Stop NERVE-NODE", WIN, SERVICE),
    ("NET.EXE STOP \"Nerve-Node\"", WIN, SERVICE),
    ("TASKKILL /IM NERVE-NODE.EXE /F", WIN, SERVICE),
    ("Taskkill /F /IM nerve-node-desktop.EXE", WIN, SERVICE),
    ("taskkill /im Nerve-Node-Desktop.exe", WIN, SERVICE),
    ("STOP-PROCESS -Name NERVE-NODE", PS, SERVICE),
    ("stop-process -name nerve-node-desktop -force", PS, SERVICE),
    ("get-service nerve-node | stop-service", PS, SERVICE),
    ("GET-SERVICE NERVE-NODE | STOP-SERVICE", PS, SERVICE),
    ("Get-Process Nerve-Node | Stop-Process", PS, SERVICE),
    // A shell keyword or a brace is not a program.
    (
        "if systemctl is-active --quiet nerve-node; then sudo systemctl restart nerve-node; fi",
        SH,
        SERVICE,
    ),
    (
        "if true; then systemctl restart nerve-node; fi",
        SH,
        SERVICE,
    ),
    (
        "for i in 1 2; do sudo systemctl restart nerve-node; done",
        SH,
        SERVICE,
    ),
    (
        "if x; then echo; else sudo systemctl stop nerve-node; fi",
        SH,
        SERVICE,
    ),
    ("{ sudo systemctl stop nerve-node; }", SH, SERVICE),
    ("{sudo systemctl stop nerve-node;}", SH, SERVICE),
    ("! sudo systemctl stop nerve-node", SH, SERVICE),
    ("time sudo systemctl restart nerve-node", SH, SERVICE),
    ("nohup sudo systemctl restart nerve-node &", SH, SERVICE),
    ("if ($true) { Stop-Service nerve-node }", PS, SERVICE),
    ("if ($true) {Stop-Service nerve-node}", PS, SERVICE),
    (
        "try { Restart-Service nerve-node -Force } catch { Write-Error $_ }",
        PS,
        SERVICE,
    ),
    (
        "foreach ($s in 1..2) { Restart-Service nerve-node }",
        PS,
        SERVICE,
    ),
    ("$null = 1; if ($?) { sc stop nerve-node }", PS, SERVICE),
    (
        "f() {\n    if x; then\n        if y; then\n            sudo systemctl restart nerve-node\n        fi\n    fi\n}",
        SH,
        SERVICE,
    ),
    (
        "foreach ($i in 1..2) {\n    if ($i) {\n        if ($i -gt 1) {\n            Restart-Service nerve-node\n        }\n    }\n}",
        PS,
        SERVICE,
    ),
    (
        "f() {\n                sudo systemctl restart nerve-node\n}",
        SH,
        SERVICE,
    ),
    // Reading the service, a process or a log runs.
    ("systemctl status nerve-node", SH, None),
    ("systemctl status nerve-node.service", SH, None),
    ("sudo systemctl status nerve-node", SH, None),
    ("systemctl is-active nerve-node", SH, None),
    ("systemctl is-enabled nerve-node", SH, None),
    ("systemctl show nerve-node", SH, None),
    ("systemctl cat nerve-node", SH, None),
    ("systemctl list-units 'nerve*'", SH, None),
    ("systemctl stop sshd", SH, None),
    ("systemctl restart nerve-center", SH, None),
    ("systemctl stop nerve-node-extra", SH, None),
    ("systemctl stop my-nerve-node", SH, None),
    ("journalctl -u nerve-node", SH, None),
    ("journalctl -u nerve-node -f", SH, None),
    ("sc query nerve-node", WIN, None),
    ("sc.exe query nerve-node", WIN, None),
    ("sc qc nerve-node", WIN, None),
    ("sc stop spooler", WIN, None),
    ("sc queryex nerve-node", WIN, None),
    ("Get-Service nerve-node", PS, None),
    ("Get-Service -Name nerve-node | Format-List", PS, None),
    ("Get-Service nerve-node | Select-Object Status", PS, None),
    ("Stop-Service spooler", PS, None),
    ("Restart-Service -Name spooler", PS, None),
    ("Set-Service -Name spooler -StartupType Disabled", PS, None),
    ("net start spooler", WIN, None),
    ("net stop spooler", WIN, None),
    ("net start nerve-node-other", WIN, None),
    ("taskkill /im notepad.exe", WIN, None),
    ("taskkill /im nerve-center.exe", WIN, None),
    ("tasklist /fi \"IMAGENAME eq nerve-node.exe\"", WIN, None),
    ("Get-Process nerve-node", PS, None),
    ("Get-Process notepad | Stop-Process", PS, None),
    ("Stop-Process -Name notepad", PS, None),
    ("cargo build -p nerve-node", ALL, None),
    ("cargo build -p nerve-node-desktop --release", ALL, None),
    ("cargo test -p nerve-node", ALL, None),
    ("git commit -m 'systemctl stop nerve-node'", SH, None),
    (
        "git commit -m 'Stop-Service nerve-node'",
        &[Shell::Sh, Shell::PowerShell],
        None,
    ),
    ("echo systemctl stop nerve-node", SH, None),
    ("grep -r 'systemctl stop nerve-node' docs/", SH, None),
    // A quoted mention that holds `sudo` is not a command.
    (
        "git commit -m \"Refuse sudo systemctl stop nerve-node in the guard\"",
        SH,
        None,
    ),
    (
        "echo \"then run: sudo systemctl restart nerve-node\"",
        SH,
        None,
    ),
    (
        "grep -rn \"sudo systemctl stop nerve-node\" docs/",
        SH,
        None,
    ),
    ("grep -rn 'sudo service nerve-node restart' docs/", SH, None),
    ("git commit -m 'Docs: sudo pkill nerve-node'", SH, None),
    ("git commit -m 'run sudo Stop-Service nerve-node'", SH, None),
    // Reading, in one line or several.
    ("systemctl status nerve-node\nsleep 1", SH, None),
    (
        "sudo systemctl status nerve-node\r\nsystemctl is-active nerve-node",
        SH,
        None,
    ),
    ("echo ok\nsystemctl stop sshd", SH, None),
    ("Get-Service nerve-node\nGet-Process nerve-node", PS, None),
    ("SC QUERY nerve-node", WIN, None),
    ("NET START nerve-node", WIN, None),
    ("TASKLIST /FI \"IMAGENAME eq nerve-node.exe\"", WIN, None),
    ("STOP-SERVICE spooler", PS, None),
    ("TASKKILL /IM NOTEPAD.EXE", WIN, None),
    ("service nerve-node status", SH, None),
    ("sudo service nerve-node-extra stop", SH, None),
    ("service sshd restart", SH, None),
    ("sudo service ssh restart", SH, None),
    ("pgrep nerve-node", SH, None),
    ("pgrep -a nerve-node", SH, None),
    ("ps aux | grep nerve-node", SH, None),
    ("pkill sshd", SH, None),
    ("pkill -f nginx", SH, None),
    ("sudo killall nginx", SH, None),
    ("pkill nerve-node-extra", SH, None),
    ("pkill -f my-nerve-node", SH, None),
    ("pkill -u nerve sshd", SH, None),
    // Keywords and braces inside quotes are text.
    (
        "git commit -m \"then sudo systemctl stop nerve-node\"",
        SH,
        None,
    ),
    ("echo \"do sudo pkill nerve-node\"", SH, None),
    ("echo then sudo service nerve-node restart", SH, None),
];

/// What the docs listed as refused although it only mentions the node: a
/// mention in quoted text, a here-document, or a `pkill -f` pattern of
/// another program, and a line that stops another service and names the
/// node later. Each of them runs now.
const MENTIONS: &[Case] = &[
    (
        "git commit -m \"Guard the service\n\nnerve-node now refuses systemctl stop\"",
        SH,
        None,
    ),
    (
        "git commit -F - <<'EOF'\nFix it\n\nsystemctl stop nerve-node is refused now\nEOF",
        SH,
        None,
    ),
    (
        "git commit -m \"Docs (Stop-Service nerve-node)\"",
        &[Shell::Sh, Shell::PowerShell],
        None,
    ),
    ("echo \"{ sudo systemctl stop nerve-node }\"", SH, None),
    ("pkill -f \"cargo run -p nerve-node\"", SH, None),
    ("systemctl stop sshd; journalctl -u nerve-node", SH, None),
];

/// What the docs listed as gaps of the text patterns, the issue's examples,
/// and a command at every depth and behind every wrapper the guard reads.
const NESTED: &[Case] = &[
    ("env X=1 sudo systemctl stop nerve-node", SH, SERVICE),
    ("timeout 30 sudo systemctl stop nerve-node", SH, SERVICE),
    ("kill $(pidof nerve-node)", SH, SERVICE),
    ("kill -9 `pgrep -f nerve-node`", SH, SERVICE),
    ("sudo kill -TERM \"$(pgrep -x nerve-node)\"", SH, SERVICE),
    ("pgrep nerve-node | xargs kill", SH, SERVICE),
    ("pidof nerve-node | xargs -r sudo kill -9", SH, SERVICE),
    (
        "ps aux | grep nerve-node | awk '{print $2}' | xargs kill",
        SH,
        SERVICE,
    ),
    ("Stop-Process -Id (Get-Process nerve-node).Id", PS, SERVICE),
    ("bash -c 'systemctl stop nerve-node'", SH, SERVICE),
    (
        "sudo sh -c \"systemctl restart nerve-node && echo ok\"",
        SH,
        SERVICE,
    ),
    (
        "sudo -u root bash -lc 'kill $(pidof nerve-node)'",
        SH,
        SERVICE,
    ),
    ("echo $(systemctl stop nerve-node)", SH, SERVICE),
    ("x=$(nerve-node status)", SH, PROGRAMS),
    ("echo \"`nerve-node status`\"", SH, PROGRAMS),
    (
        "nohup nice -n 5 ionice -c 3 stdbuf -oL systemctl restart nerve-node &",
        SH,
        SERVICE,
    ),
    ("time -p systemctl stop nerve-node", SH, SERVICE),
    ("exec nerve-node status", SH, PROGRAMS),
    (
        "env -u HOME -i PATH=/usr/bin nerve-node status",
        SH,
        PROGRAMS,
    ),
    ("env -S 'systemctl stop nerve-node'", SH, SERVICE),
    ("xargs -0 -n 1 nerve-node", SH, PROGRAMS),
    ("bash <<'EOF'\nsystemctl stop nerve-node\nEOF", SH, SERVICE),
    ("sh <<< 'nerve-node status'", SH, PROGRAMS),
    ("eval \"systemctl stop nerve-node\"", SH, SERVICE),
    ("su -c 'systemctl stop nerve-node' root", SH, SERVICE),
    (
        "powershell -NoProfile -Command \"Stop-Service nerve-node\"",
        ALL,
        SERVICE,
    ),
    ("pwsh -c Restart-Service nerve-node", ALL, SERVICE),
    ("cmd /c \"sc stop nerve-node\"", ALL, SERVICE),
    ("cmd.exe /s /c net stop nerve-node", ALL, SERVICE),
    (
        "Start-Process sc.exe -ArgumentList 'stop','nerve-node' -Verb RunAs",
        PS,
        SERVICE,
    ),
    (
        "Start-Process -FilePath 'C:\\Program Files\\Nerve\\nerve-node.exe' -ArgumentList 'service stop'",
        PS,
        PROGRAMS,
    ),
    (
        "saps powershell '-Command','Stop-Service nerve-node'",
        PS,
        SERVICE,
    ),
    ("Invoke-Expression 'Stop-Service nerve-node'", PS, SERVICE),
    ("iex \"Restart-Service nerve-node\"", PS, SERVICE),
    ("& { Stop-Service nerve-node }", PS, SERVICE),
    ("$s = Stop-Service nerve-node -PassThru", PS, SERVICE),
    (
        "Get-Process | Where-Object { $_.Name -eq 'nerve-node' } | Stop-Process",
        PS,
        SERVICE,
    ),
    ("start \"\" /b sc stop nerve-node", CMD, SERVICE),
    (
        "if exist C:\\ProgramData\\Nerve sc stop nerve-node",
        CMD,
        SERVICE,
    ),
    ("for %i in (1 2) do net stop nerve-node", CMD, SERVICE),
    (
        "case $1 in stop) systemctl stop nerve-node;; esac",
        SH,
        SERVICE,
    ),
    (
        "case \"$x\" in\n  a|b)\n    sudo systemctl restart nerve-node\n    ;;\nesac",
        SH,
        SERVICE,
    ),
    ("cat > /etc/nerve/x.toml <<'EOF'\na = 1\nEOF", SH, PATHS),
    ("echo x | sudo tee /var/lib/nerve/state/x", SH, PATHS),
    ("cd /etc/nerve && ls", SH, PATHS),
    (
        "Get-Content \"$env:ProgramData\\Nerve\\config\\node.toml\"",
        PS,
        PATHS,
    ),
    ("type C:\\PROGRAMDATA\\NERVE\\config\\node.toml", CMD, PATHS),
    (
        "socat - UNIX-CONNECT:/run/nerve-node/owner.sock </dev/null",
        SH,
        PATHS,
    ),
];

/// Lines that only mention the node or its commands, in quotes, in a
/// here-document or as another program's words, and a name the guard
/// leaves alone: each runs.
const DATA: &[Case] = &[
    (
        "git commit -m \"Catch env X=1 sudo systemctl stop nerve-node in the guard\"",
        SH,
        None,
    ),
    ("git commit -m 'Refuse kill $(pidof nerve-node)'", SH, None),
    ("echo 'timeout 30 sudo systemctl stop nerve-node'", SH, None),
    ("git commit -m \"Fix /etc/nerve permissions\"", SH, None),
    (
        "git commit -m \"Note: ~/.config/nerve holds the keys\"",
        SH,
        None,
    ),
    (
        "cat <<'EOF' > notes.md\nsystemctl stop nerve-node\nnerve-node status\nEOF",
        SH,
        None,
    ),
    ("grep -rn 'Stop-Service nerve-node' docs/ | head", SH, None),
    (
        "Write-Output 'Stop-Service nerve-node; nerve-node status'",
        PS,
        None,
    ),
    ("echo Stop-Service nerve-node", CMD, None),
    ("ls -l /usr/local/bin/nerve-node", SH, None),
    ("command -v nerve-node", SH, None),
    ("which nerve-node && nerve-center --version", SH, None),
    ("sh -c 'journalctl -u nerve-node | tail'", SH, None),
    ("bash -c \"echo 'systemctl stop nerve-node'\"", SH, None),
    ("powershell -Command \"Get-Service nerve-node\"", ALL, None),
    ("kill -9 1234", SH, None),
    ("kill $(pidof nginx)", SH, None),
    ("pgrep nerve-node | wc -l", SH, None),
];

/// A line the parser cannot read is checked with the text patterns of
/// before: refused where they refused it, by the rule they stand in for.
const UNPARSED: &[Case] = &[
    ("systemctl stop nerve-node; echo \"open", SH, SERVICE),
    ("nerve-node status; echo 'open", SH, PROGRAMS),
    ("cat /etc/nerve/x; echo `open", SH, PATHS),
    ("Stop-Service nerve-node; echo 'open", PS, SERVICE),
    ("echo \"open", SH, None),
    ("curl https://example.invalid/x | sh", SH, None),
];

#[test]
fn the_guard_reads_every_command_of_a_line() {
    check(NESTED);
}

#[test]
fn what_only_mentions_the_node_runs() {
    check(DATA);
}

#[test]
fn a_line_it_cannot_read_is_checked_with_the_text_patterns() {
    for (line, shells, _) in UNPARSED {
        for &shell in *shells {
            assert!(
                nerve_policy::command::parse(line, shell).is_err(),
                "{line:?} parses"
            );
        }
    }
    check(UNPARSED);
    // Past the nesting bound too.
    let deep = format!(
        "{}systemctl stop nerve-node{}",
        "$(".repeat(20),
        ")".repeat(20)
    );
    assert!(nerve_policy::command::parse(&deep, Shell::Sh).is_err());
    let set = RuleSet::new(&rules(GUARD), home()).with_shell(Shell::Sh);
    assert!(set.find("exec", "run", &deep).is_some());
}

#[test]
fn the_guard_refuses_the_node_itself() {
    check(NODE_ITSELF);
}

#[test]
fn the_guard_refuses_stopping_the_service() {
    check(SERVICE_FORMS);
}

#[test]
fn a_mention_of_the_node_runs() {
    check(MENTIONS);
}

/// The guard's writes stay path rules: a write into the node's folders.
#[test]
fn the_guard_refuses_writes_into_the_nodes_folders() {
    let set = RuleSet::new(&rules(GUARD), home());
    let write = |p: &str| set.find("fs", "write", p).is_some();
    assert!(write("/home/alice/.config/nerve/node.toml"));
    assert!(write("/etc/nerve/keys/home.key"));
    assert!(write("/var/lib/nerve/state/audit.jsonl"));
    assert!(write("/c/ProgramData/Nerve/config/node.toml"));
    assert!(!write("/home/alice/notes.md"));
    assert!(set.find("fs", "read", "/etc/nerve/node.toml").is_none());
    // A rule of the guard covers commands only.
    let only = RuleSet::new(&rules(&[Guard::Paths.rule()]), home());
    assert!(only.find("fs", "write", "/etc/nerve/x").is_none());
    assert!(only.find("exec", "signal", "cat /etc/nerve/x").is_none());
}

/// Every rule of the guard is valid and only its own texts are; the older
/// texts are rules too (a pairing may still have them), but not current.
#[test]
fn the_guard_rules_are_known_rules() {
    for g in GUARD {
        validate(g).unwrap();
    }
    for g in Guard::ALL {
        assert!(GUARD.contains(&g.rule()));
        assert_eq!(Guard::of_rule(g.rule()), Some(g));
    }
    for bad in [
        "guard",
        "guard:",
        "guard:node",
        "guard:*",
        "guard:Node-Programs",
    ] {
        assert!(validate(bad).is_err(), "{bad}");
    }
    for old in GUARD_OLD {
        validate(old).unwrap();
        assert!(!GUARD.contains(old), "{old} is current");
    }
    let have = vec![GUARD[0].to_string(), "exec.run:rm *".to_string()];
    assert_eq!(guard_missing(&have), GUARD[1..].to_vec());
}
