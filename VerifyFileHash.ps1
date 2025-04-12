<#
.SYNOPSIS
    Verifies the integrity of files by comparing their SHA-256 hash values with expected values.

.DESCRIPTION
    This PowerShell script helps users verify the integrity of downloaded files by comparing 
    their calculated SHA-256 hash with an expected hash value. It automatically locates files 
    in the Downloads folder and supports multiple hash algorithms.

.NOTES
    File Name      : VerifyFileHash.ps1
    Author         : Improved by Claude
    Prerequisite   : PowerShell 5.1 or later
    Version        : 2.0
#>

# Function to clean the filename by removing invalid characters and trimming
function Get-CleanFileName {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$RawFileName
    )

    Write-Verbose "Cleaning filename: '$RawFileName'"

    # Trim leading and trailing whitespace or quotes
    $CleanName = $RawFileName.Trim("`"", "'", "`t", "`n", "`r", " ")

    # Ensure the filename does not contain invalid characters
    $InvalidChars = [System.IO.Path]::GetInvalidFileNameChars()
    foreach ($char in $InvalidChars) {
        $CleanName = $CleanName -replace [regex]::Escape($char), ''
    }

    # Remove the file extension if present
    if ($CleanName.Contains('.')) {
        $CleanName = [System.IO.Path]::GetFileNameWithoutExtension($CleanName)
    }

    Write-Verbose "Cleaned filename: '$CleanName'"
    return $CleanName
}

# Function to validate and compare hash values
function Compare-HashValues {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidatePattern('^[0-9a-fA-F]+$')]
        [string]$Expected,
        
        [Parameter(Mandatory, Position = 1)]
        [ValidatePattern('^[0-9a-fA-F]+$')]
        [string]$Computed
    )

    Write-Verbose "Comparing hash values (case-insensitive)"
    return $Expected.ToUpper() -eq $Computed.ToUpper()
}

# Function to determine the Downloads folder (independent of username)
function Get-DownloadsFolder {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    Write-Verbose "Attempting to locate Downloads folder..."
    
    # Primary method for modern Windows
    try {
        Write-Verbose "Method 1: Using Shell.Application COM object"
        $shell = New-Object -ComObject Shell.Application
        $downloadsFolder = $shell.NameSpace('shell:Downloads').Self.Path
        
        if (Test-Path -Path $downloadsFolder) {
            Write-Verbose "Downloads folder found: $downloadsFolder"
            
            # Release COM object to prevent memory leaks
            if ($null -ne $shell) {
                [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
            }
            
            return $downloadsFolder
        }
        
        # Release COM object to prevent memory leaks
        if ($null -ne $shell) {
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
        }
    } 
    catch {
        Write-Verbose "Method 1 (Shell.Application) failed: $_"
    }

    # Fallback method using environment
    try {
        Write-Verbose "Method 2: Using Environment.GetFolderPath"
        $downloadsFolder = [Environment]::GetFolderPath("UserProfile") + "\Downloads"
        if (Test-Path -Path $downloadsFolder) {
            Write-Verbose "Downloads folder found: $downloadsFolder"
            return $downloadsFolder
        }
    } 
    catch {
        Write-Verbose "Method 2 (Environment variable) failed: $_"
    }

    # Registry method as additional fallback
    try {
        Write-Verbose "Method 3: Using Registry key lookup"
        $key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
        $downloadsFolder = (Get-ItemProperty -Path $key -Name "{374DE290-123F-4565-9164-39C4925E467B}")."{374DE290-123F-4565-9164-39C4925E467B}"
        if (Test-Path -Path $downloadsFolder) {
            Write-Verbose "Downloads folder found: $downloadsFolder"
            return $downloadsFolder
        }
    } 
    catch {
        Write-Verbose "Method 3 (Registry) failed: $_"
    }

    # If all methods fail, ask the user directly
    Write-Host "Downloads folder could not be found automatically." -ForegroundColor Red
    Write-Host "Please enter the full path to your Downloads folder:" -ForegroundColor Cyan
    $customPath = Read-Host

    if (-not [string]::IsNullOrEmpty($customPath) -and (Test-Path -Path $customPath)) {
        Write-Verbose "Using user-provided path: $customPath"
        return $customPath
    }

    throw "Downloads folder could not be found. Please provide a valid path."
}

# Function to find files based on a pattern
function Find-Files {
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo[]])]
    param(
        [Parameter(Mandatory)]
        [string]$FolderPath,
        
        [Parameter(Mandatory)]
        [string]$FilePattern,
        
        [switch]$Recursive = $false
    )

    Write-Verbose "Searching for files matching pattern '$FilePattern' in '$FolderPath' (Recursive: $Recursive)"
    
    $searchParams = @{
        Path = $FolderPath
        File = $true
        ErrorAction = "SilentlyContinue"
    }
    
    if ($Recursive) {
        $searchParams.Add("Recurse", $true)
    }
    
    # Start with exact pattern
    $exactPattern = "$FilePattern.*"
    Write-Verbose "Trying exact pattern: $exactPattern"
    $files = @(Get-ChildItem @searchParams -Filter $exactPattern)
    
    # If no results, try with wildcard
    if ($files.Count -eq 0) {
        $wildcardPattern = "$FilePattern*"
        Write-Verbose "Trying wildcard pattern: $wildcardPattern"
        $files = @(Get-ChildItem @searchParams -Filter $wildcardPattern)
    }
    
    # If still no results, try a more flexible search using -like
    if ($files.Count -eq 0) {
        Write-Verbose "Trying flexible search with -like operator"
        $files = @(Get-ChildItem @searchParams | Where-Object { $_.BaseName -like "*$FilePattern*" })
    }
    
    Write-Verbose "Found $($files.Count) matching files"
    return $files
}

# Function to select from multiple files
function Select-FileFromList {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo[]]$Files
    )

    if ($Files.Count -eq 1) {
        Write-Verbose "Only one file found, automatically selecting it"
        return $Files[0].FullName
    }
    
    # PowerShell 7+ - Use Out-GridView for better selection experience
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        try {
            Write-Verbose "Using Out-GridView for file selection (PowerShell 7+)"
            $selected = $Files | Select-Object Name, @{Name="Size(MB)";Expression={[math]::Round($_.Length / 1MB, 2)}}, FullName, LastWriteTime | 
                Out-GridView -Title "Select a file to verify" -OutputMode Single
            
            if ($selected) {
                return $selected.FullName
            } 
            else {
                Write-Verbose "No file selected from Out-GridView"
                return $null
            }
        } 
        catch {
            Write-Verbose "Out-GridView selection failed, falling back to console selection: $_"
            # Fall through to console selection
        }
    }
    
    # Traditional console selection
    Write-Host "Multiple files found. Please select one:" -ForegroundColor Yellow
    
    for ($i = 0; $i -lt $Files.Count; $i++) {
        $fileInfo = $Files[$i]
        $sizeInMB = [math]::Round($fileInfo.Length / 1MB, 2)
        $lastModified = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
        Write-Host "[$i] $($fileInfo.Name) ($sizeInMB MB) - Modified: $lastModified" -ForegroundColor White
    }

    Write-Host "Enter the number of the file:" -ForegroundColor Cyan
    $selection = Read-Host

    if ($selection -match '^\d+$' -and [int]$selection -ge 0 -and [int]$selection -lt $Files.Count) {
        return $Files[[int]$selection].FullName
    } 
    else {
        Write-Verbose "Invalid selection: '$selection'"
        return $null
    }
}

# Function to calculate file hash with progress reporting
function Get-FileHashWithProgress {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        
        [ValidateSet("MD5", "SHA1", "SHA256", "SHA384", "SHA512")]
        [string]$Algorithm = "SHA256"
    )

    Write-Verbose "Calculating $Algorithm hash for file: $FilePath"
    
    try {
        $fileInfo = Get-Item -Path $FilePath
        $fileSize = $fileInfo.Length
        
        # For small files (< 10MB), use standard Get-FileHash cmdlet
        if ($fileSize -lt 10MB) {
            Write-Verbose "File size is small (< 10MB), using standard Get-FileHash"
            return (Get-FileHash -Path $FilePath -Algorithm $Algorithm).Hash
        }
        
        # For larger files, implement progress reporting
        Write-Verbose "Large file detected, using streaming hash calculation with progress"
        
        # Create the hash algorithm
        $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
        
        # Use a larger buffer for better performance
        $bufferSize = 4MB
        $buffer = New-Object byte[] $bufferSize
        $totalBytesRead = 0
        
        # Create a FileStream to read the file
        $fileStream = [System.IO.File]::OpenRead($FilePath)
        
        try {
            # Create progress parameters
            $progressParams = @{
                Activity = "Calculating $Algorithm hash"
                Status = "Processing file: $($fileInfo.Name)"
                PercentComplete = 0
            }
            
            # Read the file in chunks and update the hash
            do {
                Write-Progress @progressParams
                
                $bytesRead = $fileStream.Read($buffer, 0, $bufferSize)
                if ($bytesRead -gt 0) {
                    $null = $hashAlgorithm.TransformBlock($buffer, 0, $bytesRead, $buffer, 0)
                    $totalBytesRead += $bytesRead
                    $progressParams.PercentComplete = [math]::Min(100, [math]::Round(($totalBytesRead / $fileSize) * 100))
                }
            } while ($bytesRead -gt 0)
            
            # Complete the hash calculation
            $null = $hashAlgorithm.TransformFinalBlock($buffer, 0, 0)
            $hash = [BitConverter]::ToString($hashAlgorithm.Hash).Replace("-", "")
            
            # Complete the progress bar
            Write-Progress @progressParams -Completed
            
            return $hash
        }
        finally {
            # Clean up resources
            if ($null -ne $fileStream) { $fileStream.Close(); $fileStream.Dispose() }
            if ($null -ne $hashAlgorithm) { $hashAlgorithm.Clear() }
        }
    }
    catch {
        Write-Error "Error calculating hash: $_"
        throw
    }
}

# Function to display hash comparison results
function Show-HashComparisonResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        
        [Parameter(Mandatory)]
        [string]$ExpectedHash,
        
        [Parameter(Mandatory)]
        [string]$ComputedHash,
        
        [Parameter(Mandatory)]
        [bool]$IsMatching,
        
        [string]$Algorithm = "SHA256"
    )

    # Get file information for display
    $fileInfo = Get-Item -Path $FilePath
    $fileSize = [math]::Round($fileInfo.Length / 1MB, 2)
    $lastModified = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
    
    # Show result header
    Write-Host "`n--- $Algorithm Verification Result ---" -ForegroundColor Cyan
    Write-Host "File: $FilePath" -ForegroundColor White
    Write-Host "Size: $fileSize MB" -ForegroundColor White
    Write-Host "Last Modified: $lastModified" -ForegroundColor White
    Write-Host "Expected Hash: $ExpectedHash" -ForegroundColor White
    Write-Host "Calculated Hash: $ComputedHash" -ForegroundColor White
    
    # Show match result
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        # Use PowerShell 7+ ternary operator
        $resultMessage = $IsMatching ? 
            "`nResult: The file is verified and secure." : 
            "`nResult: The file is NOT verified. The hash doesn't match."
        $resultColor = $IsMatching ? "Green" : "Red"
        Write-Host $resultMessage -ForegroundColor $resultColor
    } 
    else {
        # PowerShell 5.1 compatible version
        if ($IsMatching) {
            Write-Host "`nResult: The file is verified and secure." -ForegroundColor Green
        } 
        else {
            Write-Host "`nResult: The file is NOT verified. The hash doesn't match." -ForegroundColor Red
        }
    }
    
    # Show differences if hashes don't match
    if (-not $IsMatching) {
        Write-Host "`nDifferences (ignoring case):" -ForegroundColor Yellow
        $ExpectedUpper = $ExpectedHash.ToUpper()
        $ComputedUpper = $ComputedHash.ToUpper()

        $diffFound = $false
        
        # Check for length differences
        if ($ExpectedUpper.Length -ne $ComputedUpper.Length) {
            Write-Host "The hashes have different lengths: Expected $($ExpectedUpper.Length), Calculated $($ComputedUpper.Length)" -ForegroundColor Red
            $diffFound = $true
        }
        
        # Check character by character
        $minLength = [Math]::Min($ExpectedUpper.Length, $ComputedUpper.Length)
        for ($i = 0; $i -lt $minLength; $i++) {
            if ($ExpectedUpper[$i] -ne $ComputedUpper[$i]) {
                Write-Host "Position $i`: Expected '$($ExpectedUpper[$i])', Calculated '$($ComputedUpper[$i])'" -ForegroundColor Red
                $diffFound = $true
            }
        }

        if (-not $diffFound) {
            Write-Host "No specific character differences found, but hashes do not match." -ForegroundColor Yellow
        }
    }
}

# Simple cache to store computed hashes
$script:hashCache = @{}

# Main function to verify file hash
function Test-FileHashMatch {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$FilePath,
        
        [Parameter(Position = 1)]
        [string]$ExpectedHash,
        
        [Parameter(Position = 2)]
        [string]$FileName,
        
        [ValidateSet("MD5", "SHA1", "SHA256", "SHA384", "SHA512")]
        [string]$Algorithm = "SHA256",
        
        [switch]$Recursive
    )
    
    try {
        # If filename not provided, ask user
        if ([string]::IsNullOrEmpty($FileName)) {
            Write-Host "Please enter the filename (without file type):" -ForegroundColor Cyan
            $rawFileName = Read-Host
            $FileName = Get-CleanFileName -RawFileName $rawFileName
            if ([string]::IsNullOrEmpty($FileName)) {
                Write-Host "No input. The script will exit." -ForegroundColor Red
                return
            }
        }
        
        # If expected hash not provided, ask user
        if ([string]::IsNullOrEmpty($ExpectedHash)) {
            Write-Host "Please enter the expected $Algorithm hash:" -ForegroundColor Cyan
            $ExpectedHash = Read-Host
            if ([string]::IsNullOrEmpty($ExpectedHash)) {
                Write-Host "No input. The script will exit." -ForegroundColor Red
                return
            }
        }
        
        # If file path not provided, find the file
        if ([string]::IsNullOrEmpty($FilePath)) {
            # Find the Downloads folder
            Write-Host "Searching for Downloads folder..." -ForegroundColor Yellow
            $downloadPath = Get-DownloadsFolder
            Write-Host "Downloads folder found: $downloadPath" -ForegroundColor Green
            
            # Search for files matching the pattern
            Write-Host "Searching for files matching '$FileName'..." -ForegroundColor Yellow
            $files = Find-Files -FolderPath $downloadPath -FilePattern $FileName -Recursive:$Recursive
            
            if ($files.Count -eq 0) {
                Write-Host "The file matching '$FileName' was not found in the Downloads folder." -ForegroundColor Red
                return
            }
            
            # Select a file from the list
            $selectedFile = Select-FileFromList -Files $files
            if ([string]::IsNullOrEmpty($selectedFile)) {
                Write-Host "No file selected. The script will exit." -ForegroundColor Red
                return
            }
            
            $FilePath = $selectedFile
        }
        elseif (-not (Test-Path -Path $FilePath -PathType Leaf)) {
            Write-Host "The specified file does not exist: $FilePath" -ForegroundColor Red
            return
        }
        
        # Check if hash is in cache
        $cacheKey = "$FilePath-$Algorithm"
        if ($script:hashCache.ContainsKey($cacheKey)) {
            Write-Host "Using cached hash value..." -ForegroundColor Yellow
            $computedHashValue = $script:hashCache[$cacheKey]
        } 
        else {
            # Calculate hash with progress indicator
            Write-Host "Calculating $Algorithm hash for $FilePath..." -ForegroundColor Yellow
            
            try {
                $computedHashValue = Get-FileHashWithProgress -FilePath $FilePath -Algorithm $Algorithm
                $script:hashCache[$cacheKey] = $computedHashValue
            } 
            catch {
                Write-Host "Error calculating hash: $_" -ForegroundColor Red
                return
            }
        }
        
        # Compare hashes
        $isMatching = Compare-HashValues -Expected $ExpectedHash -Computed $computedHashValue
        
        # Show result
        Show-HashComparisonResults -FilePath $FilePath -ExpectedHash $ExpectedHash -ComputedHash $computedHashValue -IsMatching $isMatching -Algorithm $Algorithm
    }
    catch {
        Write-Host "An unexpected error occurred: $_" -ForegroundColor Red
        Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor DarkGray
    }
}

# Main script entry point
function Start-FileVerification {
    [CmdletBinding()]
    param(
        [Parameter(HelpMessage = "Path to the file to verify")]
        [string]$FilePath,
        
        [Parameter(HelpMessage = "Expected hash value to compare against")]
        [string]$ExpectedHash,
        
        [Parameter(HelpMessage = "Filename pattern to search for")]
        [string]$FileName,
        
        [Parameter(HelpMessage = "Hash algorithm to use")]
        [ValidateSet("MD5", "SHA1", "SHA256", "SHA384", "SHA512")]
        [string]$Algorithm = "SHA256",
        
        [Parameter(HelpMessage = "Search recursively in subfolders")]
        [switch]$Recursive,
        
        [Parameter(HelpMessage = "Enable verbose output")]
        [switch]$VerboseOutput
    )
    
    try {
        if ($VerboseOutput) {
            $VerbosePreference = "Continue"
        }
        
        # Detect PowerShell 7+ and apply some optimizations
        $isPwsh7 = $PSVersionTable.PSVersion.Major -ge 7
        if ($isPwsh7) {
            # In PowerShell 7 we can use parallel processing for certain operations
            Write-Host "PowerShell 7+ detected. Advanced features will be used." -ForegroundColor Green
        }

        # Call the main verification function
        Test-FileHashMatch -FilePath $FilePath -ExpectedHash $ExpectedHash -FileName $FileName -Algorithm $Algorithm -Recursive:$Recursive
    }
    catch {
        Write-Host "A critical error has occurred: $_" -ForegroundColor Red
        Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor DarkGray
    }
    finally {
        # Wait before closing the window if running in a console
        if ($Host.UI -and $Host.UI.RawUI) {
            Write-Host "`nPress any key to exit the program..." -ForegroundColor Cyan
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        } 
        else {
            Write-Host "`nScript execution completed. Exiting..." -ForegroundColor Cyan
        }
    }
}

# Run the script with optional parameters
Start-FileVerification @args
