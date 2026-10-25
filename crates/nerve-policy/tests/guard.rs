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
const FISH: &[Shell] = &[Shell::Fish];

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
    (
        "python3 -c \"print(open('/etc/nerve/node.toml').read())\"",
        SH,
        PATHS,
    ),
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
    // Replacing the node's program is changing it; looking at it is not.
    ("cp /usr/local/bin/nerve-node /tmp/n", SH, PROGRAMS),
    ("rm /usr/local/bin/nerve-node", SH, PROGRAMS),
    ("sudo rm -f /usr/local/bin/nerve-node-desktop", SH, PROGRAMS),
    ("ln -s /usr/local/bin/nerve-node /tmp/n", SH, PROGRAMS),
    (
        "install -m755 target/release/nerve-node /usr/local/bin/",
        SH,
        PROGRAMS,
    ),
    ("mv new /usr/local/bin/nerve-node", SH, PROGRAMS),
    ("echo ok && mv -f new $(dirname x)/nerve-node", SH, PROGRAMS),
    (
        "Remove-Item 'C:\\Program Files\\Nerve\\nerve-node.exe'",
        PS,
        PROGRAMS,
    ),
    (
        "Move-Item new.exe -Destination:C:\\Nerve\\nerve-node.exe",
        PS,
        PROGRAMS,
    ),
    ("del C:\\Nerve\\nerve-node.exe", CMD, PROGRAMS),
    ("copy x.exe C:\\Nerve\\NERVE-NODE.EXE", WIN, PROGRAMS),
    // So is writing over it, by a redirection or by a program that writes,
    // downloads into or changes the file.
    ("cat new > /usr/local/bin/nerve-node", SH, PROGRAMS),
    ("echo x 2>> /usr/local/bin/nerve-node-desktop", SH, PROGRAMS),
    (
        "curl -fsSLo /usr/local/bin/nerve-node https://example.invalid/x",
        SH,
        PROGRAMS,
    ),
    (
        "wget -O /usr/local/bin/nerve-node https://example.invalid/x",
        SH,
        PROGRAMS,
    ),
    (
        "curl -fsSL https://example.invalid/x | sudo tee /usr/local/bin/nerve-node",
        SH,
        PROGRAMS,
    ),
    ("dd if=new of=/usr/local/bin/nerve-node", SH, PROGRAMS),
    ("chmod -x /usr/local/bin/nerve-node", SH, PROGRAMS),
    ("sed -i s/a/b/ /usr/local/bin/nerve-node", SH, PROGRAMS),
    ("rsync new /usr/local/bin/nerve-node", SH, PROGRAMS),
    (
        "Invoke-WebRequest https://example.invalid/x -OutFile 'C:\\Program Files\\Nerve\\nerve-node.exe'",
        PS,
        PROGRAMS,
    ),
    (
        "Set-Content -Path 'C:\\Program Files\\Nerve\\nerve-node.exe' x",
        PS,
        PROGRAMS,
    ),
    (
        "Get-Content new.exe | Out-File 'C:\\Program Files\\Nerve\\nerve-node.exe'",
        PS,
        PROGRAMS,
    ),
    (
        "echo x > 'C:\\Program Files\\Nerve\\nerve-node.exe'",
        PS,
        PROGRAMS,
    ),
    (
        "echo x > \"C:\\Program Files\\Nerve\\nerve-node.exe\"",
        CMD,
        PROGRAMS,
    ),
    (
        "curl -o \"C:\\Program Files\\Nerve\\nerve-node.exe\" https://example.invalid/x",
        CMD,
        PROGRAMS,
    ),
    ("curl -o /tmp/x https://example.invalid/y", SH, None),
    ("cat notes.txt > /tmp/nerve-node-notes.txt", SH, None),
    ("rm /tmp/nerve-node-notes.txt", SH, None),
    ("cp notes.md nerve-node.md", SH, None),
    ("rm -rf target/debug/nerve-node.d", SH, None),
    ("sha256sum /usr/local/bin/nerve-node", SH, None),
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
    // A program path with a blank in it, behind `cmd /c`: the install path.
    (
        "cmd /c \"C:\\Program Files\\Nerve\\nerve-node.exe\" status",
        WIN,
        PROGRAMS,
    ),
    (
        "cmd.exe /c \"C:\\Program Files\\Nerve\\nerve-node.exe\" mode set user",
        WIN,
        PROGRAMS,
    ),
    (
        "cmd /c \"C:\\Program Files\\Nerve\\nerve-node-desktop.exe\"",
        WIN,
        PROGRAMS,
    ),
    (
        "cmd /c start \"\" \"C:\\Program Files\\Nerve\\nerve-node.exe\"",
        WIN,
        PROGRAMS,
    ),
    ("cmd /c \"nerve-node status & echo done\"", WIN, PROGRAMS),
    // PowerShell continues a line after a backtick, also before CR LF.
    (
        "& `\r\n  'C:\\Program Files\\Nerve\\nerve-node.exe' status",
        PS,
        PROGRAMS,
    ),
    (
        "Start-Process `\r\n  -FilePath 'C:\\Program Files\\Nerve\\nerve-node.exe'",
        PS,
        PROGRAMS,
    ),
    (
        "Remove-Item `\r\n  'C:\\Program Files\\Nerve\\nerve-node.exe'",
        PS,
        PROGRAMS,
    ),
    (
        "& `\r 'C:\\Program Files\\Nerve\\nerve-node.exe' status",
        PS,
        PROGRAMS,
    ),
    // A CR alone ends a PowerShell statement.
    ("Write-Host a\rnerve-node status", PS, PROGRAMS),
    (
        "Write-Output a\r& 'C:\\Program Files\\Nerve\\nerve-node.exe' status",
        PS,
        PROGRAMS,
    ),
    // A file tool names the program by its value, not by a word of a sentence.
    ("dd if=new of=nerve-node", SH, PROGRAMS),
    (
        "wget --output-document=nerve-node https://example.com/x",
        SH,
        PROGRAMS,
    ),
    (
        "Move-Item new.exe -Destination:nerve-node.exe",
        PS,
        PROGRAMS,
    ),
    (
        "curl -o \"C:\\Program Files\\Nerve\\nerve-node.exe\" https://example.com/x",
        WIN,
        PROGRAMS,
    ),
    // A blank inside a substitution is not a blank before the path.
    ("cat \"$(echo $HOME)/.config/nerve/node.toml\"", SH, PATHS),
    ("cat $(dirname $HOME)/x/.config/nerve/node.toml", SH, PATHS),
    (
        "Get-Content \"$($env:ProgramData)/Nerve/config/node.toml\"",
        PS,
        PATHS,
    ),
    (
        "Get-Content \"$($env:ProgramData)\\Nerve\\config\\node.toml\"",
        PS,
        PATHS,
    ),
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
    // A backtick continues a PowerShell line, before CR LF and CR too.
    ("Stop-Service `\r\n  -Name nerve-node", PS, SERVICE),
    ("Stop-Process `\r\n  -Name nerve-node -Force", PS, SERVICE),
    ("Get-Service nerve-node `\r\n  | Stop-Service", PS, SERVICE),
    // A CR alone ends a PowerShell statement.
    ("Write-Host a\rStop-Service nerve-node", PS, SERVICE),
    ("Write-Host a\rStop-Process -Name nerve-node", PS, SERVICE),
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
    // Brackets after a word and `case` in any place are read.
    (
        "if (( $# > 0 )); then env X=1 sudo systemctl stop nerve-node; fi",
        SH,
        SERVICE,
    ),
    (
        "while (( i < 3 )); do kill $(pidof nerve-node); done",
        SH,
        SERVICE,
    ),
    (
        "for ((i=0;i<3;i++)); do timeout 30 sudo systemctl stop nerve-node; done",
        SH,
        SERVICE,
    ),
    (
        "arr=(a b); timeout 30 sudo systemctl stop nerve-node",
        SH,
        SERVICE,
    ),
    (
        "declare -a a=(1 2); env X=1 systemctl stop nerve-node",
        SH,
        SERVICE,
    ),
    (
        "x=1; [[ $x =~ ^(a|b)$ ]] && timeout 30 sudo systemctl stop nerve-node",
        SH,
        SERVICE,
    ),
    (
        "if (cd /tmp); then env X=1 sudo systemctl stop nerve-node; fi",
        SH,
        SERVICE,
    ),
    ("a=($(nerve-node status))", SH, PROGRAMS),
    ("case $(nerve-node status) in *) echo;; esac", SH, PROGRAMS),
    (
        "case \"$(systemctl stop nerve-node)\" in a) echo;; esac",
        SH,
        SERVICE,
    ),
    (
        "for f in *; do case $f in *.txt) echo;; esac; done; env X=1 sudo systemctl stop nerve-node",
        SH,
        SERVICE,
    ),
    (
        "if true; then case x in a) nerve-node status;; esac; fi",
        SH,
        PROGRAMS,
    ),
    (
        "case x in (x) systemctl stop nerve-node;; esac",
        SH,
        SERVICE,
    ),
    (
        "echo $(case x in a) nerve-node status;; esac)",
        SH,
        PROGRAMS,
    ),
    (
        "case x in a) echo $(nerve-node status);; esac",
        SH,
        PROGRAMS,
    ),
    // A text a shell runs is read by that shell's rules, whatever shell
    // the line around it is for.
    ("powershell -Command \"& nerve-node status\"", ALL, PROGRAMS),
    (
        "powershell -Command \"& 'C:\\Nerve\\nerve-node.exe' status\"",
        ALL,
        PROGRAMS,
    ),
    ("powershell -c \"Start-Process nerve-node\"", ALL, PROGRAMS),
    ("powershell -Command \". nerve-node\"", ALL, PROGRAMS),
    ("cmd /c \"start /b nerve-node\"", ALL, PROGRAMS),
    ("cmd /c \"call nerve-node\"", ALL, PROGRAMS),
    ("cmd /c \"if 1==1 nerve-node\"", ALL, PROGRAMS),
    ("cmd /c \"for %i in (1) do nerve-node\"", ALL, PROGRAMS),
    ("bash -c \"X=1 nerve-node\"", ALL, PROGRAMS),
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
    // In fish `( … )` is a command substitution, and `and`, `or` and `not`
    // start a command, whether the shell is fish or a `fish -c` text.
    ("fish -c 'echo (nerve-node status)'", SH, PROGRAMS),
    (
        "fish -c 'set v (nerve-node --version); echo $v'",
        SH,
        PROGRAMS,
    ),
    ("fish -c 'true; and systemctl stop nerve-node'", SH, SERVICE),
    ("echo (nerve-node status)", FISH, PROGRAMS),
    ("set v (nerve-node --version)", FISH, PROGRAMS),
    ("count (systemctl stop nerve-node)", FISH, SERVICE),
    ("echo (sudo systemctl stop nerve-node)", FISH, SERVICE),
    ("true; and systemctl stop nerve-node", FISH, SERVICE),
    ("not true; or kill (pidof nerve-node)", FISH, SERVICE),
    ("diff =(nerve-node status) x", SH, PROGRAMS),
    ("zsh -c 'diff =(nerve-node status) x'", SH, PROGRAMS),
    // A shell that runs its input runs it with arguments too, and `su`,
    // `sudo -s` and `sudo -i` start one.
    (
        "bash -s x <<'EOF'\nsystemctl stop nerve-node\nEOF",
        SH,
        SERVICE,
    ),
    (
        "bash -s -- --verbose <<'EOF'\nsystemctl stop nerve-node\nEOF",
        SH,
        SERVICE,
    ),
    (
        "sudo bash -s -- x <<'EOF'\nsystemctl stop nerve-node\nEOF",
        SH,
        SERVICE,
    ),
    (
        "su root <<'EOF'\nsystemctl stop nerve-node\nEOF",
        SH,
        SERVICE,
    ),
    (
        "sudo su <<'EOF'\nsystemctl stop nerve-node\nEOF",
        SH,
        SERVICE,
    ),
    (
        "sudo su - <<'EOF'\nsystemctl stop nerve-node\nEOF",
        SH,
        SERVICE,
    ),
    (
        "sudo -s <<'EOF'\nsystemctl stop nerve-node\nEOF",
        SH,
        SERVICE,
    ),
    (
        "sudo -u root -i <<'EOF'\nsystemctl stop nerve-node\nEOF",
        SH,
        SERVICE,
    ),
    ("sudo sh -s x <<< 'systemctl stop nerve-node'", SH, SERVICE),
    // `<<` in arithmetic shifts; it does not open a here-document, so what
    // follows is read as commands.
    (
        "echo $((1 << 4)); timeout 30 sudo systemctl restart nerve-node",
        SH,
        SERVICE,
    ),
    (
        "(( x = 1 << 4 )); timeout 30 sudo systemctl restart nerve-node",
        SH,
        SERVICE,
    ),
    (
        "for ((i=0; i < 1 << 2; i++)); do nerve-node status; done",
        SH,
        PROGRAMS,
    ),
    ("coproc X { nerve-node status; }", SH, PROGRAMS),
    ("coproc nerve-node status", SH, PROGRAMS),
    // In PowerShell `&`, `.` and `Start-Process` run a quoted string.
    (
        "Start-Process -FilePath 'C:\\Program Files\\Nerve\\nerve-node.exe' -ArgumentList 'status'",
        PS,
        PROGRAMS,
    ),
    ("& 'nerve-node' status", PS, PROGRAMS),
    (". 'nerve-node' status", PS, PROGRAMS),
    ("$r = & 'nerve-node' status", PS, PROGRAMS),
    // Start-Process takes an array with commas and blanks, or `@( … )`.
    (
        "Start-Process sc.exe -ArgumentList 'stop', 'nerve-node' -Verb RunAs",
        PS,
        SERVICE,
    ),
    (
        "Start-Process net -ArgumentList 'stop', 'nerve-node' -Wait",
        PS,
        SERVICE,
    ),
    (
        "Start-Process sc.exe -ArgumentList 'stop' ,'nerve-node'",
        PS,
        SERVICE,
    ),
    (
        "Start-Process sc.exe -ArgumentList @('stop','nerve-node') -Verb RunAs",
        PS,
        SERVICE,
    ),
    (
        "Start-Process powershell -ArgumentList @('-Command', 'Stop-Service nerve-node') -Verb RunAs",
        PS,
        SERVICE,
    ),
    (
        "Start-Process powershell -ArgumentList '-NoProfile', '-Command', 'Stop-Service nerve-node'",
        PS,
        SERVICE,
    ),
    // `su` and `runuser` in their other forms, and `env -`.
    ("su -lc 'systemctl stop nerve-node'", SH, SERVICE),
    ("su -c'systemctl stop nerve-node'", SH, SERVICE),
    ("su --command='systemctl stop nerve-node'", SH, SERVICE),
    ("su --command 'systemctl stop nerve-node' root", SH, SERVICE),
    ("env - systemctl stop nerve-node", SH, SERVICE),
    (
        "sudo su -lc 'env X=1 systemctl stop nerve-node'",
        SH,
        SERVICE,
    ),
    (
        "sudo runuser -u root -- systemctl stop nerve-node",
        SH,
        SERVICE,
    ),
    ("runuser -u root systemctl stop nerve-node", SH, SERVICE),
    (
        "runuser -u root -- bash -c 'systemctl stop nerve-node'",
        SH,
        SERVICE,
    ),
    // In fish a single-quoted string may hold `\'`.
    (
        "echo 'don\\'t'; and env X=1 systemctl stop nerve-node",
        FISH,
        SERVICE,
    ),
    (
        "echo 'don\\'t'; and sudo systemctl stop nerve-node",
        FISH,
        SERVICE,
    ),
    // `|` between the patterns of a `case` branch.
    ("case $x in a|b) nerve-node status;; esac", SH, PROGRAMS),
    (
        "case $x in a|b) echo | nerve-node;; c|d) echo;; esac",
        SH,
        PROGRAMS,
    ),
    (
        "case $x in a|b) pgrep nerve-node | xargs kill;; esac",
        SH,
        SERVICE,
    ),
    // A pipe in the body of a `(pattern)` branch.
    (
        "case \"$1\" in (stop) timeout 30 sudo systemctl stop nerve-node 2>&1 | tail -1;; esac",
        SH,
        SERVICE,
    ),
    (
        "case x in (a) systemctl stop nerve-node | cat;; esac",
        SH,
        SERVICE,
    ),
    (
        "case x in (a) pgrep nerve-node | xargs kill;; esac",
        SH,
        SERVICE,
    ),
    (
        "case \"$1\" in (stop) nerve-node status | grep x;; esac",
        SH,
        PROGRAMS,
    ),
    (
        "case $1 in a) echo;; (b) kill $(pidof nerve-node) 2>&1 | tail -1;; esac",
        SH,
        SERVICE,
    ),
    (
        "for f in *; do case $f in (*.txt) systemctl stop nerve-node | cat;; esac; done",
        SH,
        SERVICE,
    ),
    (
        "case \"$1\" in\n  (stop)\n    timeout 30 sudo systemctl stop nerve-node 2>&1 | tail -1\n    ;;\nesac",
        SH,
        SERVICE,
    ),
    (
        "case $1 in (a) /usr/local/bin/nerve-node status | cat;; esac",
        SH,
        PROGRAMS,
    ),
    (
        "case $1 in (a) cat /etc/nerve/node.toml | cat;; esac",
        SH,
        PATHS,
    ),
    // `Start-Process` hands its argument string to the child, which splits
    // it with the C runtime's rules: a quoted group is one word.
    (
        "Start-Process powershell -Verb RunAs -ArgumentList '-Command \"& ''C:\\Program Files\\Nerve\\nerve-node.exe'' status\"'",
        PS,
        PROGRAMS,
    ),
    (
        "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -Command \"Restart-Service nerve-node\"'",
        PS,
        SERVICE,
    ),
    (
        "Start-Process powershell -Verb RunAs -ArgumentList '-Command \"Stop-Service -Name nerve-node -Force\"'",
        PS,
        SERVICE,
    ),
    (
        "Start-Process pwsh -Verb RunAs -ArgumentList '-c \"Stop-Service nerve-node\"'",
        PS,
        SERVICE,
    ),
    (
        "Start-Process powershell -Verb RunAs -ArgumentList \"-NoProfile -Command `\"Stop-Service nerve-node`\"\"",
        PS,
        SERVICE,
    ),
    (
        "Start-Process cmd.exe -ArgumentList '/c \"sc stop nerve-node\"' -Verb RunAs",
        PS,
        SERVICE,
    ),
    (
        "Start-Process sc.exe -ArgumentList 'stop \"nerve-node\"' -Verb RunAs",
        PS,
        SERVICE,
    ),
    // A parameter with a quoted value after its colon is still a parameter.
    (
        "Start-Process -FilePath:'sc.exe' -ArgumentList 'stop','nerve-node'",
        PS,
        SERVICE,
    ),
    (
        "Start-Process -FilePath:sc.exe -ArgumentList:'stop,nerve-node'",
        PS,
        SERVICE,
    ),
    (
        "Start-Process -FilePath:sc.exe -ArgumentList:'stop', 'nerve-node'",
        PS,
        SERVICE,
    ),
    // `runuser` takes more options between the user and the command.
    (
        "runuser -u root -g wheel -- systemctl stop nerve-node",
        SH,
        SERVICE,
    ),
    (
        "runuser --user=root -- systemctl stop nerve-node",
        SH,
        SERVICE,
    ),
    ("runuser -uroot systemctl stop nerve-node", SH, SERVICE),
    (
        "sudo runuser -u root -g wheel -- systemctl stop nerve-node",
        SH,
        SERVICE,
    ),
    // A `u` in the value of another short option (`-s/usr/bin/bash`) names
    // no user, so the text of `-c` is what runs.
    (
        "runuser -s/usr/bin/bash -c 'systemctl stop nerve-node' root",
        SH,
        SERVICE,
    ),
    (
        "runuser -Gaudio -c 'systemctl stop nerve-node' root",
        SH,
        SERVICE,
    ),
    // After a parameter written by name, the next word is the positional
    // parameter that is still unbound: `-FilePath x status` has the
    // argument list `status`.
    (
        "Start-Process -FilePath 'C:\\Program Files\\Nerve\\nerve-node.exe' status",
        PS,
        PROGRAMS,
    ),
    (
        "Start-Process -NoNewWindow -FilePath /usr/local/bin/nerve-node status",
        PS,
        PROGRAMS,
    ),
    (
        "Start-Process status -FilePath C:/Nerve/nerve-node.exe -PassThru",
        PS,
        PROGRAMS,
    ),
    (
        "$p = saps -FilePath C:/Nerve/nerve-node.exe status -PassThru",
        PS,
        PROGRAMS,
    ),
    (
        "pwsh -c \"Start-Process -FilePath /usr/local/bin/nerve-node status\"",
        SH,
        PROGRAMS,
    ),
    (
        "Start-Process -FilePath sc.exe stop,nerve-node -Verb RunAs",
        PS,
        SERVICE,
    ),
    (
        "Start-Process -Verb RunAs -FilePath net.exe 'stop', 'nerve-node'",
        PS,
        SERVICE,
    ),
    (
        "Start-Process -FilePath powershell.exe \"-Command Restart-Service nerve-node\" -Verb RunAs",
        PS,
        SERVICE,
    ),
    (
        "Start-Process -FilePath cmd.exe \"/c net stop nerve-node\" -Verb RunAs",
        PS,
        SERVICE,
    ),
];

/// Lines that only mention the node or its commands, in quotes, in a
/// here-document or as another program's words, and a name the guard
/// leaves alone: each runs.
const DATA: &[Case] = &[
    ("runuser -s/usr/bin/bash -c 'ls' root", SH, None),
    (
        "Start-Process -FilePath notepad.exe nerve-node.txt",
        PS,
        None,
    ),
    ("Start-Process -FilePath sc.exe query,nerve-node", PS, None),
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
    // The words of an array are data, whatever they are called.
    ("bins=(nerve-node nerve-node-desktop); ls", SH, None),
    ("declare -a bins=(nerve-node); echo ${bins[@]}", SH, None),
    ("[[ $x =~ ^(nerve-node|b)$ ]] && echo yes", SH, None),
    ("case $x in nerve-node) echo node;; esac", SH, None),
    ("pgrep nerve-node | wc -l", SH, None),
    // A quoted string that starts a PowerShell statement is a value.
    ("$svc = 'nerve-node'; Get-Service $svc", PS, None),
    ("$n = \"nerve-node\"", PS, None),
    ("'nerve-node' | Set-Content x.txt", PS, None),
    ("\"nerve-node\" -replace 'node','x'", PS, None),
    ("$names = @('nerve-node'); Get-Service $names", PS, None),
    // A shell that runs its input and has no command for it.
    ("bash -s x <<'EOF'\necho hi\nEOF", SH, None),
    ("sudo -s <<'EOF'\nls\nEOF", SH, None),
    ("su root <<'EOF'\nls\nEOF", SH, None),
    ("echo $((1 << 4)); ls", SH, None),
    ("echo (nerve-node-notes)", FISH, None),
    ("echo (date)", FISH, None),
    // A path in the node's folders in a text another program runs is seen
    // when no blank comes before it in the same word, and not otherwise;
    // a folder name with a blank in it is not seen either.
    (
        "python3 -c \"import os; print(open('/etc/nerve/node.toml').read())\"",
        SH,
        None,
    ),
    (
        "perl -e 'open F, \"/etc/nerve/node.toml\"; print <F>'",
        SH,
        None,
    ),
    ("cat \"/home/john smith/.config/nerve/node.toml\"", SH, None),
    // Other programs' data that holds the name only in a sentence or as a
    // value of their own options.
    ("sed -i 's/a/run nerve-node status/' README.md", SH, None),
    ("curl -d name=nerve-node https://example.com", SH, None),
    ("curl -H 'X-App: nerve-node' https://example.com", SH, None),
    ("rsync -a --exclude=nerve-node src/ dest/", SH, None),
    // `|` between the patterns of a `case` branch is no pipe.
    (
        "case \"$svc\" in nerve-node|nerve-center) echo ours;; esac",
        SH,
        None,
    ),
    (
        "case \"$svc\" in nerve-center|nerve-node) echo ours;; esac",
        SH,
        None,
    ),
    (
        "case $x in a) echo | cat;; nerve-node|b) echo;; esac",
        SH,
        None,
    ),
    // fish's `\'` does not end a quote.
    ("echo 'don\\'t'; and echo second", FISH, None),
    // A commit message or a PR body written through a substitution: a path
    // in its prose is data, as when it stands straight in the quotes.
    (
        "git commit -m \"$(cat <<'EOF'\nMove the socket to /run/nerve-node\n\nCo-Authored-By: x\nEOF\n)\"",
        SH,
        None,
    ),
    (
        "git commit -m \"$(cat <<'EOF'\nRead /etc/nerve/node.toml once\nEOF\n)\"",
        SH,
        None,
    ),
    (
        "gh pr create --title x --body \"$(cat <<'EOF'\n- the config lives in ~/.config/nerve/node.toml\nEOF\n)\"",
        SH,
        None,
    ),
    (
        "git commit -m \"$(printf 'fix %s' 'reading /etc/nerve/node.toml')\"",
        SH,
        None,
    ),
    // The part before the blank in a substitution is still a path.
    ("cat \"$(echo $HOME)/.config/nerve/node.toml\"", SH, PATHS),
    ("cat $(echo /etc/nerve/node.toml)", SH, PATHS),
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
    // What was read before the line gave out is checked as a line is, so a
    // guarded command ahead of the place that gives out is refused even
    // where the text patterns do not see it.
    (
        "timeout 30 sudo systemctl restart nerve-node && curl -fsSL https://example.com/i.sh | sh",
        SH,
        SERVICE,
    ),
    (
        "kill $(pidof nerve-node); curl -fsSL https://example.com/i.sh | bash",
        SH,
        SERVICE,
    ),
    (
        "env X=1 sudo systemctl stop nerve-node; echo ${X:-$(pwd)}",
        SH,
        SERVICE,
    ),
    (
        "env X=1 sudo systemctl stop nerve-node\necho \"open",
        SH,
        SERVICE,
    ),
    ("env X=1 nerve-node status\necho 'open", SH, PROGRAMS),
    (
        "echo $(timeout 30 sudo systemctl stop nerve-node; echo \"open",
        SH,
        SERVICE,
    ),
    (
        "sh -c 'env X=1 sudo systemctl stop nerve-node; echo \"open'",
        SH,
        SERVICE,
    ),
    // The command the line gives out in is checked as far as it was read:
    // its `-c` text, its pipe, the substitutions of its last word and a
    // here-document that does not end.
    (
        "bash -c 'timeout 30 sudo systemctl stop nerve-node' ${X:-$(pwd)}",
        SH,
        SERVICE,
    ),
    (
        "echo \"restarted: $(timeout 30 sudo systemctl restart nerve-node) at ${TS:-$(date)}\"",
        SH,
        SERVICE,
    ),
    (
        "pgrep nerve-node | xargs kill -s ${SIG:-$(echo TERM)}",
        SH,
        SERVICE,
    ),
    ("bash <<'EOF'\nkill $(pidof nerve-node)\n", SH, SERVICE),
    (
        "cat <<EOF\n$(timeout 30 sudo systemctl stop nerve-node)\n",
        SH,
        SERVICE,
    ),
];

#[test]
fn the_guard_reads_every_command_of_a_line() {
    check(NESTED);
}

/// The command a line gives out in is read whole, however deep the place
/// is: its `-c` text is read at the depth it stands in.
#[test]
fn a_command_keeps_its_text_when_the_line_gives_out_deep() {
    let set = RuleSet::new(&rules(GUARD), home()).with_shell(Shell::Sh);
    for n in 1..=20 {
        let open = "(".repeat(n);
        let close = ")".repeat(n);
        for tail in ["\"x".to_string(), format!("1{close}")] {
            let line = format!("bash -c 'systemctl stop nerve-node' ${open}{tail}");
            assert!(set.find("exec", "run", &line).is_some(), "{line:?}");
        }
    }
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

/// A command wrapped in more than the guard unwraps is a line it does not
/// read: the text patterns look at it, as at any such line.
#[test]
fn too_many_wrappers_are_a_line_it_cannot_read() {
    let set = RuleSet::new(&rules(GUARD), home()).with_shell(Shell::Sh);
    for wrapper in ["{ ", "sudo ", "nice ", "! "] {
        let line = format!("{}systemctl stop nerve-node", wrapper.repeat(300));
        assert!(
            nerve_policy::command::parse(&line, Shell::Sh).is_err(),
            "{wrapper:?}"
        );
        // The patterns see through the braces and sudo, not the others.
        let refused = set.find("exec", "run", &line).is_some();
        assert_eq!(refused, matches!(wrapper, "{ " | "sudo "), "{wrapper:?}");
    }
    let line = format!("{}systemctl stop nerve-node", "sudo ".repeat(100));
    assert!(set.find("exec", "run", &line).is_some());
}

/// The check of a long pipe costs no more than the pipe is long: every
/// `kill` in it asks whether an earlier command of the pipe names the node.
#[test]
fn a_long_pipe_is_checked_in_linear_time() {
    let set = RuleSet::new(&rules(GUARD), home()).with_shell(Shell::Sh);
    let line = "kill|".repeat(9_990) + "cat";
    let start = std::time::Instant::now();
    assert!(set.find("exec", "run", &line).is_none());
    let both = format!(
        "a {}|{}",
        "nerve-node ".repeat(2_000),
        "kill|".repeat(5_000)
    );
    assert!(set.find("exec", "run", &both).is_some());
    // One long word with thousands of path matches, alone and read again
    // at each level of `eval`.
    let word = "/etc/nervex".repeat(5_900);
    for line in [
        format!("cat {word}"),
        format!("git commit -m \"x {}\"", "/etc/nerve ".repeat(5_900)),
        format!("{}{word}", "eval ".repeat(14)),
    ] {
        set.find("exec", "run", &line);
    }
    let ps = RuleSet::new(&rules(GUARD), home()).with_shell(Shell::PowerShell);
    ps.find(
        "exec",
        "run",
        &format!("{}{}", "iex ".repeat(14), "\\programdatax".repeat(5_000)),
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(3),
        "took {:?}",
        start.elapsed()
    );
}

/// Whatever a line holds, the guard answers: it does not panic on a name
/// with characters of more than one byte, on an option that ends the line,
/// or on any mix of the constructs it reads.
#[test]
fn no_line_makes_the_guard_panic() {
    const PARTS: &[&str] = &[
        "sudo ",
        "env ",
        "-u ",
        "-C ",
        "timeout ",
        "kill ",
        "中文",
        "füße",
        "İ",
        ".exe",
        "'",
        "\"",
        "$(",
        ")",
        "`",
        ";",
        "|",
        "(",
        "((",
        "{ ",
        "} ",
        "case ",
        " in ",
        "esac",
        ";;",
        "nerve-node",
        "Start-Process ",
        "-FilePath:",
        "&",
        "\n",
        " ",
        "<<EOF\n",
        "EOF",
        "=(",
        "sh -c ",
        "cmd /c ",
        "powershell -Command ",
        "xargs ",
        "nice -n ",
        "[[ ",
        "]]",
        "and ",
        "su ",
        "sudo -s ",
        "-s ",
        "<< ",
        "$((",
        "coproc ",
        "> nerve-node ",
        "curl -o ",
    ];
    let sets: Vec<RuleSet> = ALL
        .iter()
        .chain(FISH)
        .map(|&s| RuleSet::new(&rules(GUARD), home()).with_shell(s))
        .collect();
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..6_000 {
        let n = 1 + next() % 12;
        let line: String = (0..n)
            .map(|_| PARTS[(next() % PARTS.len() as u64) as usize])
            .collect();
        for set in &sets {
            let _ = set.find("exec", "run", &line);
        }
    }
}
