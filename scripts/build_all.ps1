param(
    [string]$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
)

$ErrorActionPreference = "Stop"

function Invoke-WindowsBuild {
    param([string]$Root)

    $gcc = Get-Command gcc -ErrorAction SilentlyContinue
    if (-not $gcc) {
        Write-Host "[windows] skip: gcc not found in PATH"
        return @{ state = "skipped" }
    }

    New-Item -ItemType Directory -Force -Path (Join-Path $Root "bin") | Out-Null

    $srcFiles = Get-ChildItem -Path (Join-Path $Root "src") -Filter "*.c" | Sort-Object Name | ForEach-Object { $_.FullName }
    if (-not $srcFiles -or $srcFiles.Count -eq 0) {
        Write-Host "[windows] fail: no C sources in src/"
        return @{ state = "failed" }
    }

    $includeDir = Join-Path $Root "include"
    $out = Join-Path $Root "bin\\odyssey.exe"
    $opensslCflags = @()
    $opensslLibs = @()
    $pkgConfig = Get-Command pkg-config -ErrorAction SilentlyContinue

    if ($pkgConfig) {
        & $pkgConfig.Source --exists openssl
        if ($LASTEXITCODE -eq 0) {
            $cf = (& $pkgConfig.Source --cflags openssl).Trim()
            $lb = (& $pkgConfig.Source --libs openssl).Trim()
            if ($cf) { $opensslCflags = $cf -split "\s+" }
            if ($lb) { $opensslLibs = $lb -split "\s+" }
            Write-Host "[windows] tls: openssl detected, enabling TLS build"
        } else {
            Write-Host "[windows] tls: openssl not found, building without TLS"
        }
    } else {
        Write-Host "[windows] tls: pkg-config not found, building without TLS"
    }

    $args = @(
        "-O2", "-Wall", "-Wextra", "-Wpedantic", "-std=c11",
        "-I$includeDir",
        "-o", $out
    )
    if ($opensslLibs.Count -gt 0) {
        $args += "-DOD_ENABLE_OPENSSL"
        $args += $opensslCflags
    }
    $args += $srcFiles
    $args += "-lws2_32"
    if ($opensslLibs.Count -gt 0) {
        $args += $opensslLibs
    }

    & $gcc.Source @args
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[windows] fail: compilation error"
        return @{ state = "failed" }
    }

    Write-Host "[windows] ok: $out"
    return @{ state = "ok" }
}

function Invoke-WslLinuxBuild {
    param([string]$Root)

    & wsl.exe -l -q 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[linux/wsl] skip: WSL not available"
        return @{ state = "skipped" }
    }

    $unixLike = $Root -replace "\\", "/"
    $wslRoot = (& wsl.exe wslpath -a $unixLike).Trim()
    if (-not $wslRoot) {
        Write-Host "[linux/wsl] skip: cannot resolve WSL path"
        return @{ state = "skipped" }
    }

    & wsl.exe bash -lc "command -v gcc >/dev/null 2>&1"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[linux/wsl] skip: gcc not installed in WSL"
        return @{ state = "skipped" }
    }

    $cmd = "cd '$wslRoot' && mkdir -p bin && " +
           "TLS_CFLAGS=''; TLS_LIBS=''; " +
           "if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists openssl >/dev/null 2>&1; then " +
           "TLS_CFLAGS='-DOD_ENABLE_OPENSSL $(pkg-config --cflags openssl)'; " +
           "TLS_LIBS='$(pkg-config --libs openssl)'; " +
           "echo '[linux/wsl] tls: openssl detected, enabling TLS build'; " +
           "else echo '[linux/wsl] tls: openssl not found, building without TLS'; fi; " +
           "gcc -O2 -Wall -Wextra -Wpedantic -std=c11 -Iinclude $TLS_CFLAGS -o bin/odyssey src/*.c $TLS_LIBS"
    & wsl.exe bash -lc $cmd
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[linux/wsl] fail: compilation error"
        return @{ state = "failed" }
    }

    Write-Host "[linux/wsl] ok: $wslRoot/bin/odyssey"
    return @{ state = "ok" }
}

$win = Invoke-WindowsBuild -Root $ProjectRoot
$lin = Invoke-WslLinuxBuild -Root $ProjectRoot

if ($win.state -eq "failed" -or $lin.state -eq "failed") {
    exit 1
}

if ($win.state -eq "ok" -or $lin.state -eq "ok") {
    exit 0
}

exit 2
