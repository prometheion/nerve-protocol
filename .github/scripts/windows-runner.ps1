# The Windows runner the jobs expect: Windows Server 2025 (build 26100 or a
# later one of it). GitHub moves the windows-2025 label to new images; a
# runner of another Windows fails the job instead of testing something else
# than the release is tested on. The machine goes into the job's summary.
$os = Get-CimInstance Win32_OperatingSystem
$line = "$($os.Caption), version $($os.Version), build $($os.BuildNumber), $($env:PROCESSOR_ARCHITECTURE)"
$line
if ($env:GITHUB_STEP_SUMMARY) { $line >> $env:GITHUB_STEP_SUMMARY }
if ($os.Caption -notmatch 'Windows Server 2025' -or [int]$os.BuildNumber -lt 26100) {
    throw "this job runs on Windows Server 2025 (build 26100 or later), not on: $line"
}
