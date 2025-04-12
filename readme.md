# VerifyFileHash.ps1

## Overview

`VerifyFileHash.ps1` is a PowerShell script designed to verify the integrity of files by comparing their calculated hash values (e.g., SHA-256) with expected values. It supports multiple hash algorithms and provides a user-friendly interface for selecting files and viewing results.

## Features

- **Hash Verification**: Compares the calculated hash of a file with an expected hash value.
- **Multiple Hash Algorithms**: Supports MD5, SHA1, SHA256, SHA384, and SHA512.
- **Automatic File Search**: Locates files in the Downloads folder or a user-specified directory.
- **Progress Reporting**: Displays progress for large files during hash calculation.
- **PowerShell 7+ Enhancements**: Utilizes advanced features like `Out-GridView` for file selection and parallel processing.
- **Error Handling**: Provides detailed error messages and stack traces for troubleshooting.

## Prerequisites

- **PowerShell Version**: PowerShell 5.1 or later (PowerShell 7+ recommended for advanced features).
- **Operating System**: Windows (tested on modern Windows versions).

## Usage

### Running the Script

1. Save the script as `VerifyFileHash.ps1`.
2. Open a PowerShell terminal.
3. Run the script with optional parameters:
   ```powershell
   .\VerifyFileHash.ps1 -FilePath <PathToFile> -ExpectedHash <ExpectedHashValue> -Algorithm <HashAlgorithm> -Recursive -VerboseOutput

   # VerifyFileHash.ps1

## Overview

`VerifyFileHash.ps1` is a PowerShell script designed to verify the integrity of files by comparing their calculated hash values (e.g., SHA-256) with expected values. It supports multiple hash algorithms and provides a user-friendly interface for selecting files and viewing results.

## Features

- **Hash Verification**: Compares the calculated hash of a file with an expected hash value.
- **Multiple Hash Algorithms**: Supports MD5, SHA1, SHA256, SHA384, and SHA512.
- **Automatic File Search**: Locates files in the Downloads folder or a user-specified directory.
- **Progress Reporting**: Displays progress for large files during hash calculation.
- **PowerShell 7+ Enhancements**: Utilizes advanced features like `Out-GridView` for file selection and parallel processing.
- **Error Handling**: Provides detailed error messages and stack traces for troubleshooting.

## Prerequisites

- **PowerShell Version**: PowerShell 5.1 or later (PowerShell 7+ recommended for advanced features).
- **Operating System**: Windows (tested on modern Windows versions).

# VerifyFileHash.ps1

## Usage

### Running the Script

1. Save the script as `VerifyFileHash.ps1`.
2. Open a PowerShell terminal.
3. Run the script without any parameters:
   ```powershell
   .\VerifyFileHash.ps1
