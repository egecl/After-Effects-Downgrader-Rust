# AE Project Downgrader (Rust)

A small desktop utility inspired by the Python **AE Project Downgrader Toolkit**. It analyzes Adobe After Effects `.aep` project headers and can write a separate copy with an older version identifier.

> **Important:** This changes version metadata in the project header. It does not convert newer effects, expressions, plugins, 3D features, or other project data to older equivalents. After Effects may still warn, omit features, or fail to open the result. Always keep a backup and test on a copy.

## Features

- Desktop GUI with English and Turkish language options
- Inspect `.aep` project header and detected version
- Create a downgraded copy of a single project, keeping the input file unchanged
- Batch process `.aep` files from a folder into a separate output folder
- Preview changes without writing output (`Preview only` / `--dry-run`)
- Target versions: After Effects 2018–2025

## Download

For most users, download the Windows executable from the repository’s **Releases** page. The executable is a build artifact and should be attached to a release, rather than committed to the source repository.

## Build from source (Windows)

Install a recent stable Rust toolchain and the Visual Studio C++ Build Tools, then run:

```powershell
git clone https://github.com/egecl/After-Effects-Downgrader-Rust
cd ae-downgrade-toolkit-rust
cargo build --release
```

The executable will be created at:

```text
target/release/ae-downgrade-toolkit-rust.exe
```

To build and launch the GUI directly:

```powershell
cargo run --release
```

## Command-line usage

Running the executable with no arguments opens the GUI. Commands are also available for automation:

```powershell
# Inspect a project
.\target\release\ae-downgrade-toolkit-rust.exe analyze .\project.aep

# Preview a downgrade without writing a file
.\target\release\ae-downgrade-toolkit-rust.exe patch .\project.aep -t 2023 --dry-run

# Write a separate output copy
.\target\release\ae-downgrade-toolkit-rust.exe patch .\project.aep -t 2023 -o .\project_2023.aep

# Process .aep files from one folder into another
.\target\release\ae-downgrade-toolkit-rust.exe batch .\projects .\output -t 2023
```

Supported target years: `2018`, `2019`, `2020`, `2021`, `2022`, `2023`, `2024`, and `2025`.

Use `--force` to apply the target header update even when the project is already marked with that target version. Batch mode only processes `.aep` files directly inside the selected input folder.

## How it works and limitations

The tool locates the project container and `head` chunk, updates the version byte and, for supported versions, the associated signature. It does not rewrite the project’s compositions or translate features to equivalents supported by older After Effects releases.

Compatibility depends on the project. New effects, expressions, plugins, 3D/VR features, and other version-specific content may not work in the older application. The result is not guaranteed to open correctly.

## Relationship to the Python edition

This Rust application is a separate implementation inspired by the Python AE Project Downgrader Toolkit.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
## Contributing

Bug reports and pull requests are welcome. When reporting a problem, include the After Effects versions involved, whether the input was `.aep`, and the tool’s status or command output. Do not upload private or client project files.


