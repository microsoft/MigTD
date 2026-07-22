<#
.SYNOPSIS
    Upload a built MigTD TiP test package to the nodes of an existing TiP session.

.DESCRIPTION
    Run this from an FCShell session (started via DCM Explorer) on a SAW machine.
    The standard `migtd_package.zip` bundle places this script beside a
    `tip_package` directory, which is used by default. Pass `-PackagePath` only
    when the node package is staged elsewhere. The script publishes the package
    directory to the fabric image store as a NodeExecutePackage and distributes
    it to every node in the given TiP session. The fabric extracts the archive
    to `C:\NodeExecute\<PackageName>\` on each node, so after this script the
    IGVMs and test scripts are available at:

        C:\NodeExecute\<PackageName>\test-migtd-*.igvm
        C:\NodeExecute\<PackageName>\Run-TipTests.ps1
        ...

    This mirrors the upload path used by `tdx_lm_node_setup.ps1`
    (Add-Image -Type NodeExecutePackage + Add-NodeFile), so it relies on the same
    `acc_tip` and `TipNodeServiceAME` modules and an already-created TiP session.

.PARAMETER ClusterName
    Target cluster name, e.g. "CVL05PrdApp02". Used to connect to the fabric at
    "<ClusterName>.fc.core.windows.net".

.PARAMETER SessionId
    Existing TiP session id whose nodes receive the package. This script does not
    create sessions; allocate one with `tdx_lm_node_setup.ps1` (or
    `New-TipNodeSession`) first.

.PARAMETER PackagePath
    Local path on the SAW machine to the built TiP package directory. Defaults
    to the `tip_package` directory beside this script in `migtd_package.zip`.

.PARAMETER PackageName
    Logical name for the uploaded package. Determines the on-node directory
    `C:\NodeExecute\<PackageName>`. Defaults to "migtd-tip-package".

.PARAMETER KeepImage
    Leave the uploaded fabric image in place after distribution. By default the
    image is removed once every node has received it (the files stay on the nodes).

.EXAMPLE
    & "$HOME\migtd_package\Upload-TipPackage.ps1" -ClusterName CVL05PrdApp02 `
        -SessionId 11111111-2222-3333-4444-555555555555

.EXAMPLE
    # Upload a package staged at a specific path under a custom name.
    & "$HOME\migtd_package\Upload-TipPackage.ps1" -ClusterName CVL05PrdApp02 `
        -SessionId 11111111-2222-3333-4444-555555555555 `
        -PackagePath C:\builds\tip-package -PackageName migtd-pr1234
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory)][string]$ClusterName,
    [Parameter(Mandatory)][string]$SessionId,
    [string]$PackagePath = (Join-Path $PSScriptRoot 'tip_package'),
    [string]$PackageName = "migtd-tip-package",
    [switch]$KeepImage
)

$ErrorActionPreference = 'Stop'

# Trimmed copy of the Get-TipCommandOutput helper from tdx_lm_node_setup.ps1:
# fetches the NodeExecute result archive and returns its stdout/stderr.
function Get-TipCommandOutput {
    param([Parameter(Mandatory)]$Result)

    $requestId = $Result.RequestIdentifier
    $tempDir = Join-Path $env:TEMP "tip_$requestId"
    $zipFile = Join-Path $tempDir "tip.zip"
    $extractDir = Join-Path $tempDir "tip"

    try {
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        Invoke-WebRequest $Result.SASUri -OutFile $zipFile
        Expand-Archive $zipFile -DestinationPath $extractDir -Force

        $outFile = Join-Path $extractDir "Logs\NodeExecuteLogs\$requestId.out"
        $errFile = Join-Path $extractDir "Logs\NodeExecuteLogs\$requestId.err"

        $output = if (Test-Path $outFile) { Get-Content $outFile -Raw } else { $null }
        $errorOutput = if (Test-Path $errFile) { Get-Content $errFile -Raw } else { $null }
        return @{ StdOut = $output; StdErr = $errorOutput }
    }
    finally {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Main {
    $requiredModules = @('acc_tip', 'TipNodeServiceAME')
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module) -and -not (Get-Module -Name $module)) {
            Write-Error "Required module '$module' is not available. Import it before running (see tip_scripts README)."
            return 1
        }
    }

    if (-not (Test-Path -LiteralPath $PackagePath -PathType Container)) {
        Write-Error "PackagePath not found or not a directory: $PackagePath"
        return 1
    }
    $resolvedPackage = (Resolve-Path -LiteralPath $PackagePath).Path
    Write-Host "Package directory: $resolvedPackage"

    $igvms = @(Get-ChildItem -LiteralPath $resolvedPackage -Filter 'test-migtd*.igvm' -File -ErrorAction SilentlyContinue)
    if ($igvms.Count -eq 0) {
        Write-Error "No test-migtd*.igvm files found in $resolvedPackage. Build the package first with build_tip_package.sh."
        return 1
    }
    Write-Host "Found $($igvms.Count) IGVM image(s) to upload:"
    $igvms | ForEach-Object { Write-Host "  $($_.Name)" }

    Write-Host "Connecting to fabric for cluster '$ClusterName'..."
    $fabric = Get-Fabric -Address "$ClusterName.fc.core.windows.net"
    if (-not $fabric.TM.buildversion) {
        Write-Error "Failed to connect to fabric for cluster '$ClusterName'."
        return 1
    }

    $tipSession = $fabric | Get-TipNodeSession $SessionId
    if (-not $tipSession) {
        Write-Error "Failed to retrieve TiP session '$SessionId'."
        return 1
    }

    $nodes = @()
    foreach ($node in $tipSession.NodeList) {
        $nodes += $fabric | Get-Node $node.Guid
    }
    if ($nodes.Count -eq 0) {
        Write-Error "TiP session '$SessionId' has no nodes."
        return 1
    }
    Write-Host "Session '$SessionId' has $($nodes.Count) node(s)."

    # Package the whole tip-package directory into <PackageName>.zip. The fabric
    # extracts a NodeExecutePackage named <PackageName>.zip into
    # C:\NodeExecute\<PackageName>\ on each node.
    $tempDir = Join-Path $env:TEMP "migtd_tip_upload_$(Get-Date -Format 'yyyyMMddHHmmss')"
    $zipFile = Join-Path $tempDir "$PackageName.zip"
    $onNodeDir = "C:\NodeExecute\$PackageName"
    $uploadedImage = $null

    try {
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        Write-Host "Compressing package to $zipFile ..."
        # Archive the directory contents (not the parent folder) so files land
        # directly under C:\NodeExecute\<PackageName>\.
        Compress-Archive -Path (Join-Path $resolvedPackage '*') -DestinationPath $zipFile -Force
        Write-Host "Created archive: $zipFile ($([math]::Round((Get-Item $zipFile).Length / 1MB, 1)) MB)"

        Write-Host "Publishing package to the fabric image store..."
        $fabric | Add-Image $zipFile -Type NodeExecutePackage | Out-Null
        $uploadedImage = $fabric | Get-Image -ImageName "$PackageName.zip" -Type NodeExecutePackage
        if (-not $uploadedImage) {
            Write-Error "Package image '$PackageName.zip' not found after Add-Image."
            return 1
        }
        Write-Host "Uploaded image: $($uploadedImage.Name)"

        $allOk = $true
        foreach ($node in $nodes) {
            Write-Host "Distributing to node $($node.Id)..."
            $node | Add-NodeFile $uploadedImage | Out-Null
            Start-Sleep -Seconds 20  # allow the fabric to place and extract the file

            # Verify extraction on the node.
            $verifyCmd = "cmd /c if exist $onNodeDir (echo PRESENT) else (echo MISSING)"
            $result = Invoke-TipNodeCommand -TipSessionId $SessionId -NodeId $node -Command $verifyCmd
            $out = Get-TipCommandOutput -Result $result
            if ($out.StdOut -match 'PRESENT') {
                Write-Host "Node $($node.Id): package available at $onNodeDir"
            } else {
                Write-Warning "Node $($node.Id): $onNodeDir not found after distribution."
                if ($out.StdErr) { Write-Warning $out.StdErr }
                $allOk = $false
            }
        }

        if (-not $allOk) {
            Write-Error "One or more nodes did not receive the package."
            return 1
        }

        Write-Host "`n=== Upload complete ==="
        Write-Host "On each node, the package is at: $onNodeDir"
        Write-Host "Run tests from an elevated PowerShell on the node, e.g.:"
        Write-Host "  cd $onNodeDir"
        Write-Host "  .\Run-TipTests.ps1"
        return 0
    }
    finally {
        if ($uploadedImage -and -not $KeepImage) {
            Write-Host "Cleaning up fabric image '$($uploadedImage.Name)'..."
            $uploadedImage | Remove-Image -RemoveDeleted -ErrorAction SilentlyContinue | Out-Null
        }
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

try {
    $exitCode = Main
}
catch {
    Write-Error $_ -ErrorAction Continue
    $exitCode = 1
}

exit $exitCode
