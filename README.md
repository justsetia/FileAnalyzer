# FileAnalyzer
FileAnalyzer is a forensic utility designed for structural file analysis and threat detection. It enables users to identify hidden binary structures, embedded payloads, and anomalies, such as executable (PE/EXE) signatures hidden within non-executable file types.
📁 Repository Structure

    /src: Contains the full Python source code for transparency and custom builds.
    /dist: Contains the pre-compiled Windows executable (.exe) for quick, ready-to-run use.

🚀 Getting Started
Quick Run (Windows)

    Download the full project: Click the green “Code” button at the top of this repository and select “Download ZIP”.
    Extract the downloaded folder to your computer.
    Open and run MyScanner.exe.
        Note: Windows may flag this as “unrecognized.” This is normal for custom-compiled applications.

🔍 Features

    Structural Integrity Analysis: Detects hidden headers that deviate from standard file formats.
    Polyglot Detection: Scans the entire file to identify EXE and Multiple embedded structures.
    Visual Reporting: GUI-based logging for easy interpretation of scan results.
    Transparency: Open-source logic allows you to verify exactly how your files are being analyzed.    
