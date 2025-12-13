COMP3010 – Security Operations & Incident Management
Cw2: BOTSv3 AWS Incident Analysis

Student: Mo
Dataset: BOTSv3
Tooling: Splunk Enterprise (Ubuntu VM)
Focus: AWS CloudTrail, S3 Access Logs, Windows Host Monitoring

Table of Contents:

Introduction ..................... 1

SOC Roles & Incident Handling Reflection ............. 2

Installation & Data Preparation ..................... 3

Guided Questions – AWS Investigation Results ........ 4
  4.1 IAM Users Accessing AWS Services ............... 4
  4.2 AWS API Activity Without MFA .................. 5
  4.3 Processor Number on Web Servers ............... 5
  4.4 Event ID Enabling Public S3 Access ............ 6
  4.5 Bud’s Username ............................... 6
  4.6 Publicly Accessible S3 Bucket Name ........... 7
  4.7 File Uploaded During Public Access ........... 7
  4.8 Windows OS Anomaly Endpoint .................. 8

Conclusion and Recommendations ......... 9

References ..................... 10

Introduction: 

This report presents a security operations centre style investigation of AWS-related activity within the Frothly environment using the BOTSv3 dataset. The goal is to identify misconfigurations, suspicious access, and anomalous host behaviour by analysing multiple Splunk source types, primarily AWS CloudTrail, S3 access logs, and Windows host monitoring data. The investigation aligns with real world SOC practices, emphasising evidence-driven analysis, correlation across data sources, and clear reporting for security stakeholders.
