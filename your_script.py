from weasyprint import HTML
import os

# Define the HTML content for the SRS document
html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <style>
        @page {
            size: A4;
            margin: 20mm;
            background-color: #ffffff;
            @bottom-right {
                content: "Page " counter(page);
                font-size: 9pt;
                color: #666;
            }
            @bottom-left {
                content: "SRS: AI-Driven Network Anomaly Detection";
                font-size: 9pt;
                color: #666;
            }
        }

        body {
            font-family: 'Segoe UI', Calibri, Arial, sans-serif;
            font-size: 11pt;
            line-height: 1.5;
            color: #333;
            margin: 0;
            padding: 0;
        }

        .cover-page {
            height: 250mm;
            display: flex;
            flex-direction: column;
            justify-content: center;
            text-align: center;
            border: 2px solid #2c3e50;
            padding: 20px;
            margin-bottom: 50px;
            page-break-after: always;
        }

        .cover-page h1 {
            font-size: 28pt;
            color: #2c3e50;
            margin-top: 100px;
        }

        .cover-page h2 {
            font-size: 18pt;
            color: #34495e;
            margin-bottom: 50px;
        }

        .cover-details {
            margin-top: 100px;
            font-size: 12pt;
            text-align: left;
            width: 60%;
            margin-left: 20%;
        }

        h1, h2, h3 {
            color: #2c3e50;
            page-break-after: avoid;
        }

        h1 { font-size: 18pt; border-bottom: 2px solid #2c3e50; padding-bottom: 5px; margin-top: 30pt; }
        h2 { font-size: 14pt; margin-top: 20pt; border-left: 5px solid #3498db; padding-left: 10px; }
        h3 { font-size: 12pt; margin-top: 15pt; }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            page-break-inside: avoid;
        }

        th, td {
            border: 1px solid #bdc3c7;
            padding: 10px;
            text-align: left;
            vertical-align: top;
        }

        th {
            background-color: #f2f4f4;
            color: #2c3e50;
            font-weight: bold;
        }

        .toc {
            page-break-after: always;
        }

        .toc ul {
            list-style: none;
            padding: 0;
        }

        .toc li {
            margin-bottom: 8px;
        }

        .toc a {
            text-decoration: none;
            color: #333;
        }

        .appendix {
            background-color: #f9f9f9;
            padding: 15px;
            border: 1px solid #ddd;
        }

        .code-block {
            font-family: 'Courier New', Courier, monospace;
            background: #eee;
            padding: 10px;
            border-radius: 4px;
            font-size: 9pt;
        }
    </style>
</head>
<body>

    <div class="cover-page">
        <h1>Software Requirements Specification (SRS)</h1>
        <h2>AI-Driven Network Traffic Anomaly Detection System</h2>
        <div class="cover-details">
            <p><strong>Version:</strong> 1.0</p>
            <p><strong>Date:</strong> April 2026</p>
            <p><strong>Status:</strong> Formal Release</p>
            <p><strong>Author:</strong> [Your Name]</p>
            <p><strong>Standard:</strong> IEEE 830-1998 Structure</p>
        </div>
    </div>

    <div class="toc">
        <h1>Table of Contents</h1>
        <ul>
            <li>1. Introduction</li>
            <li>&nbsp;&nbsp;1.1 Purpose</li>
            <li>&nbsp;&nbsp;1.2 Document Conventions</li>
            <li>&nbsp;&nbsp;1.3 Intended Audience</li>
            <li>&nbsp;&nbsp;1.4 Project Scope</li>
            <li>2. Overall Description</li>
            <li>&nbsp;&nbsp;2.1 Product Perspective</li>
            <li>&nbsp;&nbsp;2.2 Product Functions</li>
            <li>&nbsp;&nbsp;2.3 Operating Environment</li>
            <li>3. Specific Requirements</li>
            <li>&nbsp;&nbsp;3.1 External Interface Requirements</li>
            <li>&nbsp;&nbsp;3.2 Functional Requirements</li>
            <li>&nbsp;&nbsp;3.3 Non-Functional Requirements</li>
            <li>4. Appendices</li>
        </ul>
    </div>

    <h1>1. Introduction</h1>
    <h3>1.1 Purpose</h3>
    <p>This Software Requirements Specification (SRS) document describes the functional and non-functional requirements for the AI-Driven Network Traffic Anomaly Detection System. The system uses machine learning (Random Forest) trained on the CIC-IDS-2017 dataset to classify network flows as benign or malicious.</p>

    <h3>1.2 Document Conventions</h3>
    <ul>
        <li><strong>Shall:</strong> Indicates a mandatory requirement.</li>
        <li><strong>Should:</strong> Indicates a recommended but not mandatory requirement.</li>
        <li><strong>IEEE 830-1998:</strong> Standard structure followed throughout.</li>
    </ul>

    <h3>1.3 Intended Audience</h3>
    <p>This document is intended for project supervisors, developers, and future maintainers of the anomaly detection system.</p>

    <h3>1.4 Project Scope</h3>
    <p>The system encompasses the preprocessing of network flow data in CIC-IDS-2017 CSV format, training a Random Forest classifier, and providing a Flask-based web interface for batch analysis and live monitoring simulation.</p>

    <h1>2. Overall Description</h1>
    <h3>2.1 Product Perspective</h3>
    <p>The system is a standalone web application developed in Python (Flask). It is designed to run locally and interact with CSV-based network traffic logs.</p>

    <h3>2.2 Product Functions</h3>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Description</th>
            </tr>
        </thead>
        <tbody>
            <tr><td>F-1</td><td>Upload a CSV file containing network flow features.</td></tr>
            <tr><td>F-2</td><td>Preprocess data (clean, scale, select features).</td></tr>
            <tr><td>F-3</td><td>Run inference using pre-trained Random Forest model.</td></tr>
            <tr><td>F-4</td><td>Display summary statistics and attack type distributions.</td></tr>
            <tr><td>F-5</td><td>Provide a simulated live monitoring dashboard.</td></tr>
        </tbody>
    </table>

    <h3>2.3 Operating Environment</h3>
    <table>
        <thead>
            <tr>
                <th>Component</th>
                <th>Specification</th>
            </tr>
        </thead>
        <tbody>
            <tr><td>Hardware</td><td>8 GB RAM minimum (16 GB recommended).</td></tr>
            <tr><td>OS</td><td>Windows 10/11, macOS, or Linux.</td></tr>
            <tr><td>Browser</td><td>Modern browser (Chrome 90+, Firefox 88+).</td></tr>
            <tr><td>Server</td><td>Python 3.8+ with Flask.</td></tr>
        </tbody>
    </table>

    <h1>3. Specific Requirements</h1>
    
    <h2>3.1 External Interface Requirements</h2>
    <h3>3.1.1 User Interfaces</h3>
    <p>The system shall provide a web interface including an Upload Page with drag-and-drop capabilities and a Live Dashboard with real-time Chart.js visualizations.</p>

    <h3>3.1.2 Software Interfaces</h3>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Interface</th>
                <th>Format</th>
            </tr>
        </thead>
        <tbody>
            <tr><td>SI-1</td><td>ML Model Artifacts</td><td>Joblib (.pkl)</td></tr>
            <tr><td>SI-2</td><td>Input Data</td><td>CSV (UTF-8)</td></tr>
            <tr><td>SI-3</td><td>Visualizations</td><td>Chart.js CDN</td></tr>
        </tbody>
    </table>

    <h2>3.2 Functional Requirements</h2>
    <h3>3.2.1 Data Ingestion & Preprocessing</h3>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Requirement</th>
            </tr>
        </thead>
        <tbody>
            <tr><td>FR-2.1</td><td>Handle UTF-8 and Latin-1 CSV encodings.</td></tr>
            <tr><td>FR-2.4</td><td>Replace infinite values and drop NaN rows.</td></tr>
            <tr><td>FR-2.7</td><td>Apply saved StandardScaler to feature set.</td></tr>
        </tbody>
    </table>

    <h2>3.3 Non-Functional Requirements</h2>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Category</th>
                <th>Requirement</th>
            </tr>
        </thead>
        <tbody>
            <tr><td>NFR-1.1</td><td>Performance</td><td>Process 10,000 rows within 30 seconds.</td></tr>
            <tr><td>NFR-3.2</td><td>Security</td><td>Sanitize file paths to prevent traversal attacks.</td></tr>
            <tr><td>NFR-6.1</td><td>Portability</td><td>Cross-platform support (Windows/Linux/Mac).</td></tr>
        </tbody>
    </table>

    <h1>4. Appendices</h1>
    <div class="appendix">
        <h3>Appendix A: Glossary</h3>
        <p><strong>Flow:</strong> A unidirectional sequence of packets sharing the same 5-tuple.</p>
        <p><strong>CIC-IDS-2017:</strong> Intrusion Detection Evaluation Dataset 2017.</p>
        
        <h3>Appendix B: System Architecture</h3>
        <div class="code-block">
            [User Browser] <--> [Flask Web Server] <--> [Preprocessing] <--> [Random Forest Model]
        </div>
    </div>

</body>
</html>
"""

# Save to PDF
output_pdf = "SRS_AI_Network_Anomaly_Detection.pdf"
HTML(string=html_content).write_pdf(output_pdf)