#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Build + deploy the WazabiEDR driver on the current machine.

.DESCRIPTION
    Full pipeline: compile via cargo-make, cleanly uninstall any prior
    version, then load and start the new one.

    Why force CARGO_TARGET_DIR off the project folder? On dev VMs the
    source is typically mounted via a VMware Shared Folder (Y:\). The
    wdk-build crate copies files between ~\.cargo\registry (local
    disk) and target\ (the share). VMware Shared Folders do not
    support some Win32 FSCTLs and fail with an opaque
    "Incorrect function." (Win32 ERROR_INVALID_FUNCTION = 1) -- the
    build never even starts. Pinning target/ to a local path fixes
    that AND speeds up compile (NTFS vs share).

.PARAMETER PackageDir
    If provided, skip the build and install from that directory.
    Otherwise: build via cargo-make, then install from
    <CargoTarget>\debug\WazabiEDR_Driver_package\.

.PARAMETER NoBuild
    Skip the cargo build and install from the resolved PackageDir.

.PARAMETER CargoTarget
    Override CARGO_TARGET_DIR. Default:
    $env:LOCALAPPDATA\WazabiEDR\driver-target (local disk, off share).

.PARAMETER LocalMirror
    When the source is on a shared folder, mirror it to this local
    directory before building. Avoids the wdk-build "Incorrect
    function." failure caused by VMware Shared Folders refusing some
    Win32 FSCTLs that wdk-build performs against <source>/target/
    (it ignores CARGO_TARGET_DIR for that initial copy).
    Default: $env:LOCALAPPDATA\WazabiEDR\driver-src.

.PARAMETER NoLocalMirror
    Disable the automatic local mirror. Useful when the source is
    already local and you want to confirm the build path.

.PARAMETER LibclangPath
    Override LIBCLANG_PATH (required by wdk-build via bindgen).
    Default: C:\Program Files\LLVM\bin.

.PARAMETER CleanPhantomDevices
    Before install, remove the ROOT\ACTIVITYMONITOR\NNNN ghost
    instances left behind by previous pnputil /scan-devices calls.

.PARAMETER Clean
    cargo clean before the build.

.EXAMPLE
    .\build.ps1
    .\build.ps1 -NoBuild
    .\build.ps1 -Clean -CleanPhantomDevices
    .\build.ps1 -NoBuild -PackageDir C:\artifacts\WazabiEDR_Driver_package
#>
[CmdletBinding()]
param(
    [string]$PackageDir,
    [switch]$NoBuild,
    [string]$CargoTarget = (Join-Path $env:LOCALAPPDATA "WazabiEDR\driver-target"),
    [string]$LibclangPath = "C:\Program Files\LLVM\bin",
    [string]$LocalMirror = (Join-Path $env:LOCALAPPDATA "WazabiEDR\driver-src"),
    [switch]$NoLocalMirror,
    [switch]$CleanPhantomDevices,
    [switch]$Clean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ServiceName = "WazabiEDR_Driver"
$InfName     = "WazabiEDR_Driver.inf"
$HardwareId  = "Root\WazabiEDR_Driver"

# Auto-reboot + resume infrastructure. When the loaded driver lacks
# DriverUnload, the only way to swap it for a new build is a reboot.
# We register a scheduled task that re-runs this script at next boot
# under SYSTEM (no UAC prompt), then optionally trigger Restart-Computer.
# The scheduled task is auto-removed once install succeeds.
$ResumeTaskName  = "WazabiEDR-Resume-Build"
$ResumeMarker    = Join-Path $env:LOCALAPPDATA "WazabiEDR\resume-after-reboot.marker"

function Write-Step([string]$msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok  ([string]$msg) { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail([string]$msg) { Write-Host "[-] $msg" -ForegroundColor Red; exit 1 }

# Detect whether we're running as the post-reboot resume.
#
# The artefacts (marker + scheduled task) only mean "we ARE a resume"
# when the **scheduled task launched this script** -- i.e. the current
# process runs as SYSTEM (the principal we registered the task under).
# A manual re-run by the operator after a botched previous attempt
# also sees the same artefacts but should NOT be treated as a resume:
# that mistake triggered the "Stop-Service still failing after reboot"
# bail-out and prevented recovery.
$IsResume = $false
$artefactsPresent = (Test-Path $ResumeMarker) -or `
                    (Get-ScheduledTask -TaskName $ResumeTaskName -ErrorAction SilentlyContinue)
if ($artefactsPresent) {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ($currentUser -eq "NT AUTHORITY\SYSTEM") {
        $IsResume = $true
        Write-Step "Detected post-reboot resume (running as SYSTEM via scheduled task)."
    } else {
        Write-Warn "Stale resume artefacts found (you are $currentUser, not SYSTEM)."
        Write-Step "Cleaning up stale task + marker, continuing as a fresh run..."
        Unregister-ScheduledTask -TaskName $ResumeTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -Force $ResumeMarker -ErrorAction SilentlyContinue
    }
}

# ---- 0. Build (skip with -NoBuild or when -PackageDir is explicit) ----------
$resolvedPackageDir = $PackageDir
if (-not $NoBuild -and -not $PackageDir) {
    $scriptRoot = $PSScriptRoot

    # Detect shared folder. The user-visible drive (Y:\) is a PSDrive
    # whose DisplayRoot starts with \\ when it's a UNC mapping; raw
    # UNC paths also start with \\. Either case = mirror to local.
    $onShare = $false
    try {
        $drive = (Get-Item $scriptRoot).PSDrive
        if ($drive -and $drive.DisplayRoot -and $drive.DisplayRoot.StartsWith("\\")) {
            $onShare = $true
        }
    } catch {}
    if ($scriptRoot.StartsWith("\\")) { $onShare = $true }

    # Pick the build directory: either the original $scriptRoot (when
    # already local) or a local mirror (when on a share). The mirror
    # exists because wdk-build IGNORES CARGO_TARGET_DIR for its
    # initial copy of rust-driver-makefile.toml -- it always writes
    # to <project>/target/, which fails on VMware Shared Folders with
    # ERROR_INVALID_FUNCTION ("Incorrect function.").
    $buildDir = $scriptRoot
    if ($onShare -and -not $NoLocalMirror) {
        Write-Warn "Source on shared folder -- mirroring to local: $LocalMirror"

        # When -Clean is passed, nuke the mirror entirely first.
        # Robocopy's delta-copy detection has bitten us hard on VMware
        # Shared Folders: it saw a stale src/events.rs as "identical"
        # (same size + 2-second-rounded timestamp) and kept the mirror
        # frozen on EVENT_VERSION=4 even though the source said 6.
        # An empty target removes the ambiguity completely.
        if ($Clean -and (Test-Path $LocalMirror)) {
            Write-Step "Nuking existing mirror (-Clean): $LocalMirror"
            Remove-Item -Recurse -Force $LocalMirror -ErrorAction SilentlyContinue
        }
        if (-not (Test-Path $LocalMirror)) {
            New-Item -ItemType Directory -Force -Path $LocalMirror | Out-Null
        }

        # Robocopy options breakdown:
        #   /MIR      mirror exactly (copy + delete extras)
        #   /IT       include "tweaked" files (size matches, attrs differ)
        #   /IS       include "same" files (forces overwrite even when
        #             robocopy thinks they're identical -- the only way
        #             to defeat the VMware Shared Folder timestamp
        #             imprecision that produced the EVENT_VERSION=4
        #             ghost build)
        #   /FFT      FAT file time precision (2s) -- extra safety net
        #             against shared-folder timestamp rounding
        #   /MT:8     8 threads, ~2x faster on a small repo
        #   /XD ...   skip target/ (build output, must stay local-only),
        #             .git, node_modules
        #   /XF *.swp drop editor lock files
        #   /NJH /NJS /NFL /NDL  silence summary + per-file output
        #   /R:1 /W:1 minimal retries -- a transient lock is fine to skip
        $robocopyArgs = @(
            $scriptRoot, $LocalMirror,
            "/MIR", "/IT", "/IS", "/FFT", "/MT:8",
            "/XD", "target", ".git", "node_modules",
            "/XF", "*.swp",
            "/NJH", "/NJS", "/NFL", "/NDL",
            "/R:1", "/W:1"
        )
        & robocopy @robocopyArgs | Out-Null
        # robocopy exit codes: 0..7 = success variants, >=8 = real failure.
        if ($LASTEXITCODE -ge 8) {
            Write-Fail "robocopy mirror to $LocalMirror failed (exit $LASTEXITCODE)."
        }

        # Belt-and-braces: explicit force-copy of the files wdk-build
        # absolutely needs at project root. /IS should already cover
        # this, but Copy-Item is the canonical "I really mean it" path.
        $critical = @("Cargo.toml", "Cargo.lock", "Makefile.toml", "build.rs")
        foreach ($f in $critical) {
            $src = Join-Path $scriptRoot $f
            if (Test-Path $src) {
                Copy-Item -Force -Path $src -Destination (Join-Path $LocalMirror $f)
            }
        }

        # Hard check: refuse to build if Cargo.lock is missing.
        $lockPath = Join-Path $LocalMirror "Cargo.lock"
        if (-not (Test-Path $lockPath)) {
            Write-Fail "Cargo.lock missing from mirror ($lockPath) and no Cargo.lock at source ($scriptRoot). Run 'cargo generate-lockfile' in the source dir first."
        }

        # Sanity check: hash-compare a handful of files we care most
        # about (the ones whose contents shape the wire format and the
        # callbacks). If a hash differs we attempt a force-copy and
        # re-check; still mismatching = the mirror is genuinely broken
        # and the operator must intervene. This is the safety net that
        # catches the "robocopy thinks it's identical but it isn't"
        # scenario, even after /IS.
        $watched = @(
            "src\events.rs",
            "src\lib.rs",
            "src\callbacks\process.rs",
            "src\callbacks\mod.rs",
            "Cargo.toml",
            "Cargo.lock"
        )
        $drift = @()
        foreach ($rel in $watched) {
            $srcFile = Join-Path $scriptRoot $rel
            $mirFile = Join-Path $LocalMirror $rel
            if ((Test-Path $srcFile) -and (Test-Path $mirFile)) {
                $sh = (Get-FileHash -Algorithm MD5 -Path $srcFile).Hash
                $mh = (Get-FileHash -Algorithm MD5 -Path $mirFile).Hash
                if ($sh -ne $mh) {
                    # Last-resort: force-copy then re-hash. If it still
                    # mismatches the underlying FS is hosed.
                    Copy-Item -Force -Path $srcFile -Destination $mirFile
                    $mh = (Get-FileHash -Algorithm MD5 -Path $mirFile).Hash
                    if ($sh -ne $mh) {
                        $drift += "$rel (src=$($sh.Substring(0,8)) mirror=$($mh.Substring(0,8)))"
                    } else {
                        Write-Warn "Mirror drift recovered for $rel via Copy-Item -Force."
                    }
                }
            }
        }
        if ($drift.Count -gt 0) {
            Write-Fail "Mirror is out of sync with source even after force-copy: $($drift -join '; '). Nuke it manually and re-run: Remove-Item -Recurse -Force '$LocalMirror'"
        }

        Write-Ok "Mirror up to date and hash-checked: $LocalMirror"
        $buildDir = $LocalMirror
    } elseif ($onShare -and $NoLocalMirror) {
        Write-Warn "Source on shared folder + -NoLocalMirror set -- build will likely fail with 'Incorrect function.'"
    }

    if (-not (Test-Path (Join-Path $LibclangPath "libclang.dll"))) {
        Write-Warn "libclang.dll not found in $LibclangPath -- bindgen will likely fail."
        Write-Warn "Override with -LibclangPath, or install LLVM (winget install LLVM.LLVM)."
    }
    $env:LIBCLANG_PATH    = $LibclangPath

    # CARGO_TARGET_DIR policy:
    #  - We have a mirror? Don't set it -- cargo defaults to
    #    <buildDir>/target/ which is on a local disk AND has Cargo.lock
    #    as its grand-parent (in <buildDir>/Cargo.lock), which is
    #    exactly what wdk-build's find_top_level_cargo_manifest needs.
    #  - No mirror (source is local)? Same logic -- default is fine.
    #  - User passed -NoLocalMirror and source is on a share? We force
    #    a local target dir as a last resort, but wdk-build's
    #    Cargo.lock check WILL fail because <CargoTarget>/.. has no
    #    Cargo.lock. Print a warning so the operator knows why.
    if ($onShare -and $NoLocalMirror) {
        if (-not (Test-Path $CargoTarget)) {
            New-Item -ItemType Directory -Force -Path $CargoTarget | Out-Null
        }
        $env:CARGO_TARGET_DIR = $CargoTarget
        Write-Warn "Forced CARGO_TARGET_DIR=$CargoTarget. wdk-build will likely complain about missing Cargo.lock (it walks <target>/.. for it). Drop -NoLocalMirror to fix."
    } else {
        # Ensure no stale env var from a previous invocation leaks in.
        if ($env:CARGO_TARGET_DIR) {
            Write-Step "Unsetting inherited CARGO_TARGET_DIR ($env:CARGO_TARGET_DIR) to use cargo default."
            Remove-Item Env:CARGO_TARGET_DIR -ErrorAction SilentlyContinue
        }
    }

    Write-Ok "LIBCLANG_PATH=$env:LIBCLANG_PATH"
    Write-Ok "Build directory:  $buildDir"
    if ($env:CARGO_TARGET_DIR) {
        Write-Ok "CARGO_TARGET_DIR=$env:CARGO_TARGET_DIR (forced)"
    } else {
        Write-Ok "CARGO_TARGET_DIR=<default: $buildDir\target>"
    }

    if ($Clean) {
        Write-Step "cargo clean..."
        Push-Location $buildDir
        try { & cargo clean | Out-Null } finally { Pop-Location }
    }

    # NOTE: `cargo make` (no subtask) runs the default flow, which is
    # build + package-driver-flow (inf2cat + stampinf + signtool, the
    # whole pipeline declared in wdk-build's rust-driver-makefile).
    # `cargo make build` ONLY runs `cargo build` -- no .inf signing,
    # no .cer/.cat produced, no WazabiEDR_Driver_package/ folder. We
    # need the full default flow.
    Write-Step "cargo make (build + package, may take 1-2min depending on cache)..."
    Push-Location $buildDir
    try {
        & cargo make
        $cmExit = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    if ($cmExit -ne 0) {
        Write-Fail "cargo make failed (exit $cmExit). Check LIBCLANG_PATH, WDK install and the output above."
    }

    # The package lands wherever cargo wrote target/. Probe both the
    # default ($buildDir\target) and the forced ($CargoTarget) layout
    # so we resolve correctly regardless of which branch ran above.
    $candidates = @(
        (Join-Path $buildDir "target\debug\WazabiEDR_Driver_package"),
        (Join-Path $CargoTarget "debug\WazabiEDR_Driver_package")
    )
    $resolvedPackageDir = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $resolvedPackageDir) {
        Write-Fail "Build succeeded but no WazabiEDR_Driver_package directory was found in: $($candidates -join ' OR ')"
    }

    $sys = Get-Item (Join-Path $resolvedPackageDir "$ServiceName.sys")
    Write-Ok "Build OK: $($sys.FullName) ($([math]::Round($sys.Length / 1KB)) KB, $($sys.LastWriteTime))"
}

if (-not $resolvedPackageDir) {
    $resolvedPackageDir = Join-Path $PSScriptRoot "target\debug\WazabiEDR_Driver_package"
    Write-Step "Skip build -- using default PackageDir: $resolvedPackageDir"
}

# ---- 1. Package validation --------------------------------------------------
if (-not (Test-Path $resolvedPackageDir)) {
    Write-Fail "Package directory not found: $resolvedPackageDir"
}
$infPath = Join-Path $resolvedPackageDir $InfName
if (-not (Test-Path $infPath)) {
    Write-Fail "$InfName not found in $resolvedPackageDir"
}
$sysPath = Join-Path $resolvedPackageDir "$ServiceName.sys"
if (-not (Test-Path $sysPath)) {
    Write-Fail "$ServiceName.sys not found in $resolvedPackageDir"
}
Write-Ok "Package validated: $resolvedPackageDir"

# ---- 2. Test signing --------------------------------------------------------
$tsEnabled = (bcdedit /enum "{current}") -match "testsigning\s+Yes"
if (-not $tsEnabled) {
    Write-Warn "Test signing disabled. Enabling..."
    bcdedit /set testsigning on | Out-Null
    Write-Warn "Reboot the VM then re-run this script."
    exit 0
}
Write-Ok "Test signing active."

# ---- 2bis. Locate devcon.exe -----------------------------------------------
$arch = if ([Environment]::Is64BitOperatingSystem) {
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "x64" }
} else { "x86" }

$devcon = Get-ChildItem -Path "C:\Program Files (x86)\Windows Kits\10\Tools" `
    -Filter "devcon.exe" -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match "\\$arch\\" } |
    Sort-Object FullName -Descending |
    Select-Object -First 1 -ExpandProperty FullName

if (-not $devcon) {
    Write-Fail "devcon.exe ($arch) not found in the WDK. Install the Windows Driver Kit."
}
Write-Ok "devcon: $devcon"

# ---- 3. Detect and remove any prior install --------------------------------
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Step "Mode: HOT REDEPLOY (existing service found, no reboot needed)."
} else {
    Write-Step "Mode: FIRST INSTALL."
}

$hadOldInstall = $false

if ($svc) {
    $hadOldInstall = $true
    if ($svc.Status -ne "Stopped") {
        Write-Step "Stopping service '$ServiceName' (state: $($svc.Status))..."
        try {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            Write-Ok "Service stopped -- driver unloaded."
        } catch {
            # The currently loaded driver has no DriverUnload routine,
            # so the only way to swap it for our new build is a reboot.
            # We auto-schedule the resume + offer to reboot now.
            if ($IsResume) {
                # We already rebooted once and Stop-Service STILL fails
                # -- that means the disabled-at-boot trick didn't take.
                # Bail out hard rather than loop-rebooting the operator.
                Write-Fail "Stop-Service still failing after reboot. Manual cleanup needed (uninstall driver via Device Manager, or boot to Safe Mode). Scheduled task NOT touched so you can investigate."
            }

            Write-Host ""
            Write-Host "Stop-Service failed: $_" -ForegroundColor Red
            Write-Host "  Cause: the currently loaded driver has no DriverUnload routine." -ForegroundColor Yellow
            Write-Host "  It can only be removed by a reboot." -ForegroundColor Yellow

            # 1. Disable the service so it does NOT load at next boot.
            #    Without this, the v4 driver would re-grab the device on
            #    boot and the resumed script would hit the same wall.
            $disabled = $false
            try {
                & sc.exe config $ServiceName start= disabled | Out-Null
                if ($LASTEXITCODE -eq 0) { $disabled = $true }
            } catch {}
            if (-not $disabled) {
                Write-Fail "sc config $ServiceName start= disabled failed. Cannot safely auto-reboot."
            }
            Write-Ok "Service '$ServiceName' disabled at next boot."

            # 2. Where will the resume script come from? Two options:
            #    - Mirror exists (typical when we just ran the build) ->
            #      use the mirror copy, always reachable, never on a
            #      share that might be unmounted at boot.
            #    - No mirror (-NoBuild without a prior mirror) -> use
            #      $PSCommandPath but ONLY if it's already local;
            #      otherwise we copy the script + package to LOCALAPPDATA.
            $resumeRoot = $LocalMirror
            if (-not (Test-Path (Join-Path $resumeRoot "build.ps1"))) {
                # Mirror didn't happen (or doesn't include the script).
                # Stage the script + the package side-by-side under
                # LOCALAPPDATA so the SYSTEM-run task can read both.
                $resumeRoot = Join-Path $env:LOCALAPPDATA "WazabiEDR\resume-stage"
                New-Item -ItemType Directory -Force -Path $resumeRoot | Out-Null
                Copy-Item -Force $PSCommandPath (Join-Path $resumeRoot "build.ps1")
            }
            $resumeScript = Join-Path $resumeRoot "build.ps1"
            $resumePkg    = $resolvedPackageDir
            # If the package is on a share, mirror it too (SYSTEM can't
            # see network drives at boot before user logon).
            if ($resumePkg.StartsWith("\\") -or `
                ((Get-Item $resumePkg -ErrorAction SilentlyContinue).PSDrive.DisplayRoot -like "\\*")) {
                $stagedPkg = Join-Path $env:LOCALAPPDATA "WazabiEDR\resume-package"
                if (Test-Path $stagedPkg) { Remove-Item -Recurse -Force $stagedPkg }
                Copy-Item -Recurse -Force $resumePkg $stagedPkg
                $resumePkg = $stagedPkg
            }

            # 3. Register the scheduled task that fires on boot under SYSTEM
            #    (no UAC, no user logon required). Force=overwrite if a
            #    stale one is still there.
            Write-Step "Registering scheduled task '$ResumeTaskName' to resume after reboot..."
            Unregister-ScheduledTask -TaskName $ResumeTaskName -Confirm:$false -ErrorAction SilentlyContinue
            $extraArgs = ""
            if ($CleanPhantomDevices) { $extraArgs += " -CleanPhantomDevices" }
            $argLine = "-NoProfile -ExecutionPolicy Bypass -File `"$resumeScript`" -NoBuild -PackageDir `"$resumePkg`"$extraArgs"
            $action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argLine
            # Delay 30s after boot so DriverStore, PnP, SCM are all
            # ready before we touch them. AtStartup + Delay = standard
            # post-reboot bootstrap pattern.
            $trigger = New-ScheduledTaskTrigger -AtStartup
            $trigger.Delay = "PT30S"
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
            $settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable `
                            -DontStopOnIdleEnd -AllowStartIfOnBatteries `
                            -DontStopIfGoingOnBatteries
            Register-ScheduledTask -TaskName $ResumeTaskName `
                -Action $action -Trigger $trigger `
                -Principal $principal -Settings $settings `
                -Description "WazabiEDR: resume driver install after reboot. Auto-removed on success." `
                -Force | Out-Null

            # 4. Marker file: lets the resumed script confirm it's a
            #    resume even if the scheduled task was already removed
            #    by something else.
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ResumeMarker) | Out-Null
            $stamp = (Get-Date).ToString("o")
            Set-Content -Path $ResumeMarker -Value "stamped=$stamp; package=$resumePkg; script=$resumeScript" -Encoding ASCII
            Write-Ok "Resume infrastructure ready (task + marker)."

            # 5. Prompt to reboot. Default = Yes so a no-input keypress
            #    (CR) reboots immediately.
            Write-Host ""
            Write-Host "Reboot now to finish install? [Y/n] " -ForegroundColor Cyan -NoNewline
            $answer = Read-Host
            if ([string]::IsNullOrWhiteSpace($answer) -or $answer -ieq "y" -or $answer -ieq "yes") {
                Write-Warn "Rebooting in 5 seconds (Ctrl+C to abort)..."
                Start-Sleep -Seconds 5
                Restart-Computer -Force
            } else {
                Write-Warn "Reboot skipped. The scheduled task will resume install whenever you reboot."
                Write-Warn "To cancel the auto-resume: Unregister-ScheduledTask -TaskName $ResumeTaskName -Confirm:`$false; Remove-Item '$ResumeMarker'"
            }
            exit 0
        }
    } else {
        Write-Step "Service '$ServiceName' already stopped."
    }
}

$devices = Get-PnpDevice -ErrorAction SilentlyContinue |
    Where-Object { $_.InstanceId -like "Root\$ServiceName*" }
foreach ($d in $devices) {
    $hadOldInstall = $true
    Write-Step "Removing PnP device: $($d.InstanceId)"
    pnputil /remove-device $d.InstanceId | Out-Null
    Start-Sleep -Milliseconds 200
}

if ($CleanPhantomDevices) {
    $phantoms = Get-PnpDevice -ErrorAction SilentlyContinue |
        Where-Object { $_.InstanceId -like "ROOT\ACTIVITYMONITOR\*" }
    if ($phantoms) {
        Write-Step "Cleaning $($phantoms.Count) ghost ROOT\ACTIVITYMONITOR\* instance(s)..."
        foreach ($p in $phantoms) {
            pnputil /remove-device $p.InstanceId | Out-Null
        }
        Write-Ok "Ghost instances removed."
    }
}

$pnpBlocks = ((pnputil /enum-drivers) -join "`n") -split "(?=Published Name:)"
$oldOemNames = $pnpBlocks |
    Where-Object { $_ -match "Original Name:\s+$InfName" } |
    ForEach-Object { if ($_ -match "Published Name:\s+(oem\d+\.inf)") { $Matches[1] } }

foreach ($oem in $oldOemNames) {
    $hadOldInstall = $true
    Write-Step "Removing from Driver Store: $oem"
    pnputil /delete-driver $oem /uninstall /force | Out-Null
}

if ($hadOldInstall) {
    Write-Ok "Prior install removed."
} else {
    Write-Ok "No prior install detected."
}

# ---- 4. Install the test certificate ---------------------------------------
$certFile = Get-ChildItem $resolvedPackageDir -Filter "*.cer" -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($certFile) {
    Write-Step "Installing certificate: $($certFile.Name)"
    certutil -addstore -f "Root"             $certFile.FullName | Out-Null
    certutil -addstore -f "TrustedPublisher" $certFile.FullName | Out-Null
    Write-Ok "Certificate installed (Root + TrustedPublisher)."
} else {
    Write-Warn "No .cer found in $resolvedPackageDir -- install may fail."
}

# ---- 5. Install the new driver ---------------------------------------------
Write-Step "Adding package to Driver Store: $infPath"
pnputil /add-driver $infPath
if ($LASTEXITCODE -ne 0) {
    Write-Fail "pnputil /add-driver failed (exit $LASTEXITCODE)"
}

Write-Step "Creating root device '$HardwareId' via devcon..."
& $devcon install $infPath $HardwareId
if ($LASTEXITCODE -ne 0) {
    Write-Fail "devcon install failed (exit $LASTEXITCODE)"
}
Start-Sleep -Seconds 2

# ---- 6. Start the service ---------------------------------------------------
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Fail "Service '$ServiceName' not detected after devcon install."
}

# Before the reboot, we may have set the service to 'disabled' so the
# old (DriverUnload-less) version wouldn't auto-load at boot. devcon
# install recreates the service entry but on Windows 10/11 it inherits
# the StartType of the existing record -- so 'disabled' sticks unless
# we explicitly flip it back.
#
# We unconditionally force start=demand here (idempotent: no-op when
# already demand). Reading the current StartType via Get-CimInstance is
# unreliable right after devcon install -- the CIM object may not be
# fully populated yet, which trips Set-StrictMode with
# PropertyNotFoundException. Just set + check the sc.exe exit code.
Write-Step "Ensuring service '$ServiceName' StartType = demand (idempotent)..."
& sc.exe config $ServiceName start= demand | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Warn "sc config $ServiceName start= demand failed (exit $LASTEXITCODE). Manual fix: sc.exe config $ServiceName start= demand"
} else {
    Write-Ok "Service '$ServiceName' StartType = demand."
}
$svc.Refresh()

if ($svc.Status -ne "Running") {
    Write-Step "Starting service '$ServiceName'..."
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 2
    $svc.Refresh()
}

Write-Ok "WazabiEDR Driver running. State: $($svc.Status)"

# ---- 7. Final hint: loaded version vs on-disk version ----------------------
$storeSys = Get-ChildItem `
    "C:\Windows\System32\DriverStore\FileRepository\wazabiedr_driver.inf_amd64_*\$ServiceName.sys" `
    -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($storeSys) {
    $localLen = (Get-Item $sysPath).Length
    $storeLen = $storeSys.Length
    if ($localLen -ne $storeLen) {
        Write-Warn ""
        Write-Warn "[WARN] DriverStore .sys ($storeLen B) != package .sys ($localLen B)."
        Write-Warn "  pnputil probably did not take the new version (same DriverVer?)."
        Write-Warn "  Bump DriverVer in WazabiEDR_Driver.inx and rebuild."
    } else {
        Write-Ok "DriverStore $($storeSys.Length) B == package $localLen B -- correct version loaded."
    }
}

# ---- 8. Cleanup resume infrastructure --------------------------------------
# We reached the end successfully -- the post-reboot scheduled task
# has nothing more to do. Remove both the task and the marker file so
# the next reboot is a normal reboot (no spurious driver re-install).
$task = Get-ScheduledTask -TaskName $ResumeTaskName -ErrorAction SilentlyContinue
if ($task) {
    Unregister-ScheduledTask -TaskName $ResumeTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Ok "Removed scheduled task '$ResumeTaskName' (install successful)."
}
if (Test-Path $ResumeMarker) {
    Remove-Item -Force $ResumeMarker -ErrorAction SilentlyContinue
}
if ($IsResume) {
    Write-Ok "Post-reboot resume completed successfully. Driver fully operational."
}
