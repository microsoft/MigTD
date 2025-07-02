# MigTD AzCVMEmu API Documentation

## Overview

The AzCVMEmu feature enables MigTD to build and run in environments without the real td-shim, using minimal emulation crates. The API design keeps initialization and file operations in the emulation layer, with MigTD's config.rs providing only essential policy/root CA access functions.

**Key Feature: Real File I/O Support**

When the AzCVMEmu feature is enabled, the emulation layer includes std support and can perform real file I/O operations, reading policy and root CA data from actual files on the host filesystem.

## Architecture

```
MigTD main.rs
     |
     ├─ td_shim_interface_emu::* (direct API calls with real file I/O)
     └─ config::get_policy() / get_root_ca() (unified access, delegates to emulation layer)
```

## Emulation Layer APIs

All file-based emulation APIs are available directly from `td_shim_interface_emu`:

### Real File I/O Functions (Preferred for AzCVMEmu)

```rust
use td_shim_interface_emu;

// Initialize with real file access and custom paths (RECOMMENDED)
td_shim_interface_emu::init_file_based_emulation_with_real_files(
    "/tmp/policy.bin", 
    "/tmp/root_ca.bin"
);

// Initialize with real file access using default paths
td_shim_interface_emu::init_file_based_emulation_with_real_files_default();
```

### Simulation-based Functions (for testing/fallback)

```rust
// Initialize with simulated file access (pattern-based)
td_shim_interface_emu::init_file_based_emulation_with_paths(
    "/tmp/policy.bin", 
    "/tmp/root_ca.bin"
);

// Initialize with default paths (/tmp/migtd_policy.bin, /tmp/migtd_root_ca.bin)
td_shim_interface_emu::init_file_based_emulation();

// Initialize with pattern-based file reader (simulated)
td_shim_interface_emu::init_file_based_emulation_with_pattern();
```

### Data Loading Functions

```rust
// Load data directly from buffers
td_shim_interface_emu::load_policy_data(b"policy data");
td_shim_interface_emu::load_root_ca_data(b"root CA data");

// Set file paths individually
td_shim_interface_emu::set_policy_file_path("/custom/policy.bin");
td_shim_interface_emu::set_root_ca_file_path("/custom/root_ca.bin");

// Set custom file reader function
td_shim_interface_emu::set_file_reader(custom_reader_fn);
```

### Lower-level APIs

For advanced use cases, access the full `td_uefi_pi::fv` module:

```rust
use td_shim_interface_emu::td_uefi_pi::fv;

// All init functions also available here
fv::init_file_based_emulation_with_paths(policy_path, root_ca_path);

// Advanced file reader options
fv::init_with_default_file_reader();
fv::init_with_pattern_file_reader();
fv::init_with_simple_file_reader();
```

## MigTD Config Layer

The `config.rs` module provides only essential access functions:

```rust
use migtd::config;

// Access policy and root CA data (works in both td-shim and AzCVMEmu modes)
let policy = config::get_policy();     // Option<&'static [u8]>
let root_ca = config::get_root_ca();   // Option<&'static [u8]>
```

## Usage in main.rs

```rust
#[cfg(feature = "AzCVMEmu")]
{
    // Initialize event log emulation
    td_shim_emu::event_log::init_event_log();

    // Initialize file-based emulation with real file access
    let result = td_shim_interface_emu::init_file_based_emulation_with_real_files(
        "/tmp/migtd_policy.bin",
        "/tmp/migtd_root_ca.bin"
    );
    
    if !result {
        // Fallback to hardcoded data if real file access fails
        td_shim_interface_emu::load_policy_data(b"fallback policy");
        td_shim_interface_emu::load_root_ca_data(b"fallback root CA");
    }
}

// Later, access the data through config layer
let policy = config::get_policy().expect("Policy not found");
let root_ca = config::get_root_ca().expect("Root CA not found");
```

## File Preparation

For real file I/O to work, create the policy and root CA files:

```bash
# Create policy file
echo "Your policy data here" > /tmp/migtd_policy.bin

# Create root CA file  
echo "Your root CA data here" > /tmp/migtd_root_ca.bin
```

## Benefits of This Design

1. **Clean Separation**: Emulation logic is isolated in the emulation layer
2. **Direct Access**: Main code uses emulation APIs directly, no unnecessary wrappers
3. **Compatibility**: config.rs provides the same interface for both td-shim and AzCVMEmu modes
4. **Flexibility**: Multiple initialization options available depending on use case
5. **Minimal Coupling**: MigTD core code is not polluted with emulation-specific logic
6. **Real File I/O**: Support for actual filesystem operations in AzCVMEmu environments

## File Reader Types

The emulation layer supports different file reader implementations:

1. **Real File Reader** (`real_file_reader`): Reads actual files from the host filesystem (requires std feature)
2. **Pattern File Reader** (`pattern_file_reader`): Simulates file content based on path patterns  
3. **Simple File Reader** (`simple_file_reader`): Provides hardcoded content for specific paths
4. **Default File Reader** (`default_file_reader`): Provides reasonable test data

### Std Feature Support

- **With std feature**: Real file I/O is available, files are read from the actual filesystem
- **Without std feature**: Falls back to pattern-based simulation for testing

The AzCVMEmu feature automatically enables std support in td-shim-interface-emu for real file operations.

## Feature Combinations

- **Default**: Uses real td-shim interfaces
- **AzCVMEmu**: Uses emulation layer with file-based policy/root CA loading
- **AzCVMEmu + vmcall-raw**: Emulation + raw vmcall support

All combinations build successfully and provide the same config.rs API surface.
