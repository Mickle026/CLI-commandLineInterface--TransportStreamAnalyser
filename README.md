# **TransportStreamAnalyzer**

An essential command-line utility for analyzing, manipulating, and extracting data from **MPEG Transport Stream (.ts)** files. Built with C\# and designed for performance and flexibility in broadcast and video processing workflows.

## **Overview**

TransportStreamAnalyzer allows users to read a Transport Stream file, identify its structure (PAT/PMT), analyze its content (PIDs, PCR), and extract specific segments or programs based on various criteria like PID, program length, or time.

## **✨ Features**

* **Detailed PID Analysis:** Generate a comprehensive report of all Program IDs (PIDs) present, including their packet counts.  
* **Program Extraction:** Extract the entire program with the **longest elementary stream** detected in the stream (\-extractprogram longest).  
* **PID Filtering:** Extract a single PID (\-extractpid) or a comma-separated list of PIDs (\-extractpids).  
* **MPEG-Only Filtering:** Automatically filter an extracted program to only include essential MPEG-1/2/4 Video and Audio streams (\-extractmpeg).  
* **Time-Based Segmentation:** Extract a segment of the stream based on a start and end time (utilizes PCR data).  
* **Packet Range Segmentation:** Extract a segment based on exact packet indices.  
* **PCR Analysis:** Detailed analysis of Program Clock Reference (PCR) data for a specified PID.  
* **Customization:** Force a specific PMT PID and control the output file name and location.

## **🛠️ Prerequisites**

To build and run this project, you need:

* **.NET 8.0 SDK** or later.

## **⚙️ Building the Project**

1. Clone this repository:  
   git clone \[repository-url\]  
   cd TransportStreamAnalyzer

2. Build the application using the .NET CLI:  
   dotnet build

3. The executable will be located in the appropriate bin/\[Debug|Release\]/net8.0/ folder. For most uses, building a **Release** version is recommended:  
   dotnet publish \-c Release \-r win-x64 \--self-contained true

## **🚀 Usage**

The general usage pattern is to provide the file path followed by one or more options.

TransportStreamAnalyzer \<file\_path\> \[options\]

### **Options**

| Option | Description | Example Value |
| :---- | :---- | :---- |
| **\<file\_path\>** | The path to the MPEG Transport Stream file. | my\_stream.ts |
| \-extractpid \<pid\> | Extracts a single PID to a new file. | \-extractpid 101 |
| \-extractpids \<pid1,pid2,...\> | Extracts a list of PIDs. | \-extractpids 101,102,103 |
| \-extractprogram longest | Extracts the program with the longest elementary stream. | \-extractprogram longest |
| \-extractmpeg | Used with \-extractprogram longest to filter the output to only essential MPEG video/audio streams. | \-extractmpeg |
| \-extractsegment \<start\> \<end\> | Extracts packets between two packet indices (inclusive). | \-extractsegment 1000 5000 |
| \-extracttimesegment \<mm:ss\>-\<mm:ss\> | Extracts a segment between two timecodes (requires valid PCR). | \-extracttimesegment 01:30-05:00 |
| \-pidanalysis | Performs a detailed analysis of all PIDs in the stream. | \-pidanalysis |
| \-pcranalysis \<pid\> | Performs analysis on the Program Clock Reference (PCR) PID. | \-pcranalysis 100 |
| \-forcedpmtpid \<pid\> | Forces a specific PMT PID for analysis/extraction. | \-forcedpmtpid 256 |
| \-output \<filename\> | Specifies a custom name for the output file. | \-output my\_clip.ts |
| \-sourcedir | Places the output file in the source file's directory instead of the application directory. | \-sourcedir |

### **Examples**

**1\. Analyze all PIDs in a stream:**

TransportStreamAnalyzer input.ts \-pidanalysis

**2\. Extract the longest detected program and filter to only video/audio:**

TransportStreamAnalyzer input.ts \-extractprogram longest \-extractmpeg \-output longest\_program.ts

**3\. Extract PIDs 101, 102, and 103:**

TransportStreamAnalyzer input.ts \-extractpids 101,102,103 \-output streams.ts

**4\. Extract a segment from 5 minutes 0 seconds to 10 minutes 30 seconds:**

TransportStreamAnalyzer input.ts \-extracttimesegment 05:00-10:30 \-output clip.ts

## **🤝 Contributing**

Contributions are welcome\! Feel free to open issues or submit pull requests.

## 🧑‍💻 Developers

**Author:** Mike Williams  

## **📄 License**

This project is licensed under the [**MIT License**](https://www.google.com/search?q=LICENSE) \- see the LICENSE file for details.
