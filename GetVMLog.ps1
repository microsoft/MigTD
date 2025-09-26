<#
.SYNOPSIS
    Connects to MigTD VM serial output via named pipe and displays logs.

.DESCRIPTION
    This script connects to a Hyper-V VM's serial port through a named pipe
    to capture and display MigTD log output in real-time.

.PARAMETER VmName
    The name of the Hyper-V VM to connect to. Default is 'migtdvm'.

.PARAMETER PipeName
    The name of the named pipe to connect to. Default is 'migtdcom1'.

.PARAMETER TimeoutSeconds
    Connection timeout in seconds. Default is 60 seconds.

.PARAMETER ComPort
    COM port number to use for VM serial connection. Default is 1.

.EXAMPLE
    .\GetVMLog.ps1
    Connects to default VM 'migtdvm' using default pipe 'migtdcom1'

.EXAMPLE
    .\GetVMLog.ps1 -VmName "MyMigTD" -PipeName "mycom" -TimeoutSeconds 120
    Connects to VM 'MyMigTD' using pipe 'mycom' with 120 second timeout

.EXAMPLE
    .\GetVMLog.ps1 -Help
    Shows this help information

.NOTES
    Requires Hyper-V PowerShell module and appropriate permissions.
#>

[CmdletBinding()]
param(
    [Parameter(Position=0, HelpMessage="Name of the Hyper-V VM")]
    [string]$VmName = 'migtdvm',
    
    [Parameter(HelpMessage="Name of the named pipe")]
    [string]$PipeName = 'migtdcom1',
    
    [Parameter(HelpMessage="Connection timeout in seconds")]
    [ValidateRange(1, 600)]
    [int]$TimeoutSeconds = 60,
    
    [Parameter(HelpMessage="COM port number for VM serial connection")]
    [ValidateRange(1, 4)]
    [int]$ComPort = 1,
    
    [Parameter(HelpMessage="Show help information")]
    [switch]$Help
)

# Show help if requested
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Full
    exit 0
}

# Start logging all output to file
$LogFile = "GetVMLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $LogFile -Append
Write-Host "Logging to: $LogFile" -ForegroundColor Cyan

# Validate required modules
if (-not (Get-Module -ListAvailable -Name Hyper-V)) {
    Write-Error "Hyper-V PowerShell module is required but not available."
    Stop-Transcript
    exit 1
}

Write-Host "Connecting to VM: $VmName" -ForegroundColor Green
Write-Host "Using pipe: $PipeName" -ForegroundColor Green
Write-Host "Timeout: $TimeoutSeconds seconds" -ForegroundColor Green

# Construct the pipe path
$pipePath = "\\.\pipe\$PipeName"
Write-Host "Pipe path: $pipePath" -ForegroundColor Green

try {
    Set-VMComPort -VMName $VmName -Number $ComPort -Path $pipePath
    Write-Host "VM COM port configured successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to configure VM COM port: $($_.Exception.Message)"
    exit 1
}

# Create a NamedPipeClientStream object to connect to the pipe
$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream(".", $PipeName, "In")

# Wait for the server to be ready for connection (with a timeout)
Write-Host "Attempting to connect to pipe: $pipePath" -ForegroundColor Yellow
Write-Host "Start the VM now." -ForegroundColor Yellow
try {
    $pipeClient.Connect($TimeoutSeconds * 1000) # Convert to milliseconds
    Write-Host "Connected to pipe. Now listening for output. "
    
    # Create a stream reader
    $reader = New-Object System.IO.StreamReader($pipeClient)
    
    # Continuously read line-by-line until the server closes the connection
    while ($true) {
        $line = $reader.ReadLine()
        if ($line -eq $null) {
            # An empty read indicates the server has closed the pipe
            Write-Warning "The VM has closed the pipe."
            break
        }
        Write-Host "Received: $line"
    }
}
catch {
    Write-Host "An error occurred: $($_.Exception.Message)"
}
finally {
    # Clean up and close the connection
    if ($reader) {
        $reader.Dispose()
    }
    if ($pipeClient.IsConnected) {
        $pipeClient.Dispose()
    }
    Write-Host "Disconnected from the pipe."
    
    # Stop logging
    Stop-Transcript
}