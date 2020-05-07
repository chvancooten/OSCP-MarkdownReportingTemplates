# Offensive Security - Penetration Test Report for PWK Internal Labs

<!-- Insert your details here -->
[email@email.email]
OSID: [OS-XXXXX]
[Date]

# Outline
## Introduction

The Offensive Security Lab penetration test report contains all efforts that were conducted in order to pass the Offensive Security Lab. This report will be graded from a standpoint of correctness and fullness to all aspects of the Lab. The purpose of this report is to ensure that the student has a full understanding of penetration testing methodologies as well as the technical knowledge to pass the qualifications for the Offensive Security Certified Professional.

## Objective

The objective of this assessment is to perform an internal penetration test against the Offensive Security Lab network. The student is tasked with following a methodical approach in obtaining access to the objective goals. This test should simulate an actual penetration test and how you would start from beginning to end, including the overall report. An example page has already been created for you at the latter portions of this document that should give you ample information on what is expected to pass this course. Use the sample report as a guideline to get you through the reporting.

## Requirements

The student will be required to fill out this penetration testing report fully and to include the following sections:

- Overall High-Level Summary and Recommendations (non-technical)
- Methodology walkthrough and detailed outline of steps taken
- Each finding with included screenshots, walkthrough, sample code, and proof.txt if applicable
- Any additional items that were not included

# High-Level Summary

The author of this report was tasked with performing an internal penetration test towards the Offensive Security Lab environment. An internal penetration test is a dedicated offensive simulation against internally connected systems. The focus of this test is to perform attacks, similar to those of a malicious hacker and attempt to infiltrate Offensive Security’s internal Lab systems – including but not limited to the THINC.local domain. The overall objective was to evaluate the network, identify systems, and exploit vulnerabilities, ultimately reporting findings back to Offensive Security.

During the assessment, several alarming vulnerabilities were identified on Offensive Security’s networks. When performing the attacks, the author was able to gain access to multiple machines, primarily due to outdated patches and poor security configurations. During the tests, all systems were succesfully compromised, granting full control over every system in the network. These systems, as well as a brief description on how access was obtained, are listed in the section below.

## Overview of Compromised Machines

It should be noted that this section solely provides a high-level description of the vulnerability which was exploited to gain a foothold on the machine. For details on lateral movement and privilege escalation within each box, please refer to the details provided in the ‘exploitation details’ chapters.

<!-- Update the below sections with the right subnets, hosts, and a brief description of the initial exploited vulnerability -->
**Public Subnet**

- X.X.X.X (Hostname) - Initial Vulnerability

**Other Subnet**

- X.X.X.X (Hostname) - Initial Vulnerability

**Other Subnet**

- X.X.X.X (Hostname) - Initial Vulnerability

**Other Subnet**

- X.X.X.X (Hostname) - Initial Vulnerability

## Recommendations

It is strongly recommended to patch the vulnerabilities identified during the testing to ensure that an attacker cannot exploit these systems in the future. For each application, patching recommendations are provided.

One thing to note is that these systems require frequent patching and once patched, should remain on a regular patch program to protect additional vulnerabilities that are discovered at a later date.

# Methodologies

A widely adopted approach to performing penetration testing was utilized during the tests to test how well the Offensive Security Lab environments are secured.
Below, a breakdown of the applied methodology is provided. 

## Information Gathering

The information gathering portion of a penetration test focuses on identifying the scope of the penetration test. During this penetration test, the objective was to exploit the exam network. Three IP ranges were in scope:

<!-- Update the list of subnets -->
- The 'Public' subnet: X.X.X.X/24
- Another subnet: X.X.X.X/24

As part of the Information Gathering phase, both passive and active scans were performed to gather information about open ports and running services.

## Penetration

<!-- Update this paragraph with the appropriate amount of compromised machines -->
The penetration testing portions of the assessment focus on gaining access to a variety of systems. During this penetration test, **[X]** out of **67** systems were succesfully and completely compromised. The next chapters provide an overview of the identified services and exploited vulnerabilities for every machine, as well as the proof keys for every compromised machine and recommendations for mitigating the identified vulnerabilities.

## Maintaining Access

Maintaining access to a system is important to attackers, ensuring that access to a system can be regained after it has been exploited is invaluable.
The 'maintaining access' phase of the penetration test focuses on ensuring that once the attack has been executed, an attacker can easily regain administrative access over the system. Additionally, certain exploits may only be executable once. As such, having a foothold into a system proves invaluable.

## Lateral Movement

As part of the engagement, exploitation in closed subnets was requested by Offensive Security, requiring lateral movement from compromised hosts. Furthermore, lateral movement within subnets was realized through the use of known credentials from compromised hosts. Technical details on lateral movement are provided in the next chapter, and a full overview of compromised credentials is provided in the appendix.

## House Cleaning

The 'house cleaning' portions of the assessment ensures that remnants of the penetration test are removed.
Often fragments of tools or user accounts are left on an organization's computer which can cause security issues down the road.
Ensuring that no remnants of our penetration test are left over is important.

After all proof keys were collected from the lab networks, all user accounts, passwords, as well as the Meterpreter services installed on the system were removed. Offensive Security should not have to remove any additional backdoors, user accounts, or files from the system.

# Exploitation Details: Public Subnet (X.X.X.X/24)

<!-- Insert machine write-ups from .md template here -->

# Exploitation Details: Public Subnet (X.X.X.X/24)

<!-- Insert machine write-ups from .md template here -->

# Appendix A - Lab Exercises

<!-- Insert your notes here -->

# Appendix B - Compromised Credentials
<!-- Optional, you can dump the credentials that you harvested in this chapter -->
As part of the engagement, several sets of credentials were found on compromised machines. Some credentials were found in hashed form and cracked, indicating the weakness of these credentials. For the sake of full disclosure, these credentials are disclosed below. Note that they should be rotated as soon as possible.

## Personal accounts
```plaintext
CREDENTIALS:HERE
```

## Non-personal accounts
```plaintext
CREDENTIALS:HERE
```