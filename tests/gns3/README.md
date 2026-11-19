

\# SD-WAN GNS3 CI Automation



\## Overview



Python-based testing tools for the vcpe-sdwan project.



The initial script connects to a dedicated GNS3 project,

inspects its topology, validates two CPE nodes, and prepares

an inter-CPE link configuration in dry-run mode.



\## Current capabilities



\- Connect to GNS3 using its REST API

\- Discover network nodes and links

\- Validate CPE-1 and CPE-2

\- Compare nodes with an optional local baseline

\- Check availability of adapter 1 on both CPEs

\- Prepare an inter-CPE link without applying changes



\## Requirements



\- Python 3.10 or newer

\- requests

\- Access to an authorized GNS3 server



Install dependencies:



&#x20;   python -m pip install -r requirements.txt



\## Configuration



Set the environment variables:



&#x20;   GNS3\_URL

&#x20;   GNS3\_PROJECT\_ID



Optional:



&#x20;   GNS3\_BASELINE\_PATH



Do not commit credentials, private keys, local VM images,

or private infrastructure details.



\## Run



From the tests/gns3 directory:



&#x20;   python sdwan\_ci.py



\## Current limitations



This script is read-only.



It does not yet:

\- Recreate the GNS3 topology

\- Start or configure CPEs

\- Create Linux namespaces

\- Establish SD-WAN tunnels

\- Execute connectivity tests

\- Generate automated PASS/FAIL test reports



\## Planned next steps



1\. Implement safe topology recreation

2\. Configure both CPEs

3\. Provision one Linux namespace per CPE

4\. Test LAN and inter-CPE connectivity

5\. Generate structured test reports



\## Safety



Only use the dedicated, authorized CI test project.

Do not reset or delete shared GNS3 projects.
