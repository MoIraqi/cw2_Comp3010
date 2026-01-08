Comp3010 CW 2 	 

Dataset: BOTSv3  

Tooling: Splunk Enterprise (Ubuntu VM) 

Focus: AWS CloudTrail, S3 Access Logs, Windows Host Monitoring 

https://youtu.be/pCzncozM1ho 

https://github.com/MoIraqi/cw2_Comp3010.git 

 

Table of Contents 

Introduction ........................................ page 2 

SOC Roles & Incident Handling Reflection .............Page 2  

Installation & Data Preparation ..................... Page 3 

Guided Questions – AWS Investigation Results ........ Page 4 
  4.1 IAM Users Accessing AWS Services ............... page 4 
  4.2 AWS API Activity Without MFA .................. page 5 
  4.3 Processor Number on Web Servers .............. page 6 
  4.4 Event ID Enabling Public S3 Access ............ page 6 
  4.5 Bud’s Username ............................... page 7 
  4.6 Publicly Accessible S3 Bucket Name ........... page 8 
  4.7 File Uploaded During Public Access ........... page 9 
  4.8 Windows OS Anomaly Endpoint .................. Page 10 

Conclusion and Recommendations ...................... Page 12 

References ......................................... page 13 

 

 

 

1. Introduction 

This report presents a structured Security Operations Centre (SOC) investigation into AWS-related security events within the Frothly environment using the Boss of the SOC v3 (BOTSv3) dataset. The aim of this investigation is to identify any insecure cloud configurations, alongside some anomalous access patterns, and endpoint inconsistencies through the systematic analysis of log data in Splunk. 

The scope of this investigation focuses specifically on AWS CloudTrail logs, Amazon S3 access logs, hardware telemetry, and Windows host monitoring data. These data sources were selected to reflect realistic SOC monitoring capabilities across cloud infrastructure and endpoints. The report does not attempt to attribute attacker intent or perform malware reverse engineering, but instead concentrates on detection, validation, and interpretation of security-relevant events. 

The report is structured to mirror professional SOC reporting practices1. Following this introduction, a reflection on SOC roles and incident handling methodologies is provided to contextualise the investigation within operational security practice. The methodology section outlines the Splunk installation and data preparation process. The main body presents guided investigative findings supported by reproducible SPL queries and evidence. The report concludes with recommendations aimed at improving cloud security posture and SOC readiness. 

 

 

2. SOC Roles & Incident Handling Reflection 

 

The investigation reflects a Tier 1–2 SOC workflow. The initial detection involved log triage and filtering to identify relevant AWS API activity. Log triage is the act analysing and prioritising log data to identify and respond to potential issues or threats in a system. It helps teams focus on the most critical alerts, improving response time. Analysis escalated to correlation across CloudTrail and S3 access logs to confirm misconfiguration impact. The incident handling lifecycle, followed preparation (log availability and Splunk ingestion), identification (public S3 access and anomalous actions), containment considerations (bucket access restriction), and lessons learned for prevention. This mirrors professional real-world SOC operations where analysts must contextualise and understand cloud events rapidly and accurately. 

 

3. Installation & Data Preparation 

Splunk Enterprise was installed on an Ubuntu virtual machine and configured according to BOTSv3 guidance. The dataset was ingested and validated by confirming event counts and availability across key source types. Relevant indexes included AWS CloudTrail logs, S3 access logs, hardware telemetry, and Windows host monitoring data. Time normalisation and field extraction were verified to ensure accurate querying and correlation. 

 

 

4. Guided Questions AWS Investigation Results 

Q1. IAM Users Accessing AWS Services 

Using: sourcetype="aws:cloudtrail" 

| stats values(userIdentity.userName) as IAM_Users 

| mvsort(IAM_Users)  

This search was used to identify IAM users who accessed AWS services within the Frothly environment: 

Result: bstoll,btun,splunk_access,web_admin 

These IAM users were identified as having accessed AWS services successfully or unsuccessfully. This highlights multiple identities interacting with the AWS environment, increasing the attack surface if principles of least privilege  are not enforced. 

 

Q2. Field to Detect AWS API Activity Without MFA 

Using: sourcetype="aws:cloudtrail" 

| search userIdentity.sessionContext.attributes.mfaAuthenticated="false" 

Result: userIdentity.sessionContext.attributes.mfaAuthenticated 

This field allows SOC teams to detect sensitive AWS API actions performed without MFA, which represents a significant security risk. 

 

Q3. Processor Number on Web Servers 

Using: sourcetype="hardware" 

| stats values(cpu) by host 

Result: E5-2676 

This showed consistent processor usage across web servers, supporting baseline system profiling also anomaly detection. 

 

Q4. Event ID Enabling Public S3 Access 

Source Type: aws:cloudtrail 

sourcetype="aws:cloudtrail" eventName=PutBucketAcl 

| table _time eventName eventID userIdentity.userName requestParameters.bucketName 

 

Result: ab45689d-69cd-41e7-8705-5350402cf7ac 

This corresponds to the PutBucketAcl API call that made the S3 bucket publicly accessible, representing a critical misconfiguration. 

 

Q5. Bud’s Username 

Result: bstoll 

sourcetype="aws:cloudtrail" eventName=PutBucketAcl 

| table _time userIdentity.userName eventName 

This username is associated with the user account that is associated with Bud, who did this action 

 

Q6. Publicly Accessible S3 Bucket Name 

Source Type: aws:cloudtrail 

sourcetype="aws:cloudtrail" eventName=PutBucketAcl 

| table requestParameters.bucketName userIdentity.userName 

Result: frothlywebcode 

The bucket name was identified as the resource affected by the misconfiguration. 

 

Q7. Text File Uploaded While Bucket Was Public 

Source Type: aws:s3:accesslogs 

sourcetype="aws:s3:accesslogs" frothlywebcode 

| search (PUT OR "REST.PUT.OBJECT") 

| search status=200 OR http_status=200 

| table _time bucket key operation status 

 

Result: OPEN_BUCKET_PLEASE_FIX.txt 

This file was successfully uploaded while the bucket was publicly accessible, further showing the real world impact of the misconfiguration. 

 

 

Q8. Endpoint with Different Windows OS Edition 

Source Type: winhostmon 

sourcetype="winhostmon" 

| stats values(os) by host 

 

Result: BSTOLL-L.froth.ly 

One endpoint was identified as running a different Windows operating system edition than others. These inconsistencies may indicate misconfiguration, testing systems, elevated risk and overall poor security. 

 

 

 

5. Conclusion and Suggestions 

 

This entire investigation shows how log correlation in Splunk can be used to detect and validate cloud misconfigurations, especially those involving publicly accessible S3 buckets. The results highlight the significance of stringent IAM controls, MFA enforcement, and ongoing cloud resource monitoring. Enabling S3 Block Public Access by default, requiring MFA for all privileged IAM actions, setting up automated alerts for potentially dangerous CloudTrail events, and routinely auditing host configurations are some of the recommendations. Together, these actions lessen the possibility and consequences of future occurrences of this kind. 

 

References: 
1 Gelnaw, A. (2024). Cybersecurity Executive Summary Example for Reporting. [online] www.bitsight.com. Available at: https://www.bitsight.com/blog/a-security-operations-center-report-template. 

 
