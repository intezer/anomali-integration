# Intezer Anomali integration
Intezer Analyze integration with anomali provide hash enrichment.

## How does it work?
The integration will take the hash and query it in Intezer Analyze for the last analysis. 
If an analysis is not found, the integration will try and analyze the hash in case the file is available in Intezer Analyze.

## Setup
From Anomali app store, search for "Intezer Analyze".
When setting up the integration, there are few options:
* API key: your Intezer API key found in [account details](https://analyze.intezer.com/account-details)
* Timeout waiting for an analysis to finish
* Should the querying of the latest analysis only return private analysis. 
Use this to avoid consuming quota everytime query.

![Setup option](.artwork/options.png)

## Integration details
The integration will show Intezer verdict and analysis details first:
![Analysis details](.artwork/analysis_details.png)

### Network IOCs 
![Network IOCs](.artwork/network_iocs.png)

### Files IOCs 
![Files IOCs](.artwork/files_iocs.png)

### Signatures 
![Signatures](.artwork/signatures.png)