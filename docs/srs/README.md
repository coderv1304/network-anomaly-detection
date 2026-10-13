# Software Requirements Specification (SRS) Generator

This folder contains the script to generate the project's IEEE 830-1998 compliant SRS PDF document.

## Files
- `generate_srs.py`: Python script utilizing WeasyPrint to compile the formal HTML specification into `SRS_AI_Network_Anomaly_Detection.pdf`.

## Usage
Install the required dependency:
```bash
pip install weasyprint
```
Run the generator:
```bash
python docs/srs/generate_srs.py
```
The output PDF will be created inside this directory.
