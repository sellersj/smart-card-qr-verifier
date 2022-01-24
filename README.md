# smart-card-qr-verifier

This is a spike / PoC for an app that will allow someone to upload a government generated PDF containing a SMART QR code 
and it will extract basic info.

References
* https://github.com/ongov/OpenVerify
* https://files.ontario.ca/apps/verify/verifyRulesetON.json

* https://smarthealth.cards/en/
* https://github.com/smart-on-fhir/health-cards
* https://github.com/smart-on-fhir/health-cards/blob/main/docs/index.md



After trying many, many libraries, I found nimbus could read it and allow modifications to be able to deal with the SMART health card QA code
* https://connect2id.com/products/nimbus-jose-jwt

#### SMART health card dev tools
This is where I found the schema that I use to generate java model classes.
* https://github.com/smart-on-fhir/health-cards-dev-tools/

#### Vaccine type code, draft
* http://build.fhir.org/valueset-vaccine-code.html

#### SNOMED Codes
They can be looked up http://mchp-appserv.cpe.umanitoba.ca/viewConcept.php?printer=Y&conceptID=1514

| SNOMED Code  | Description | Tariff Code |
| -----------  | ----------- | ----------- |
| 28571000087109 | COVID-19 - Moderna      | 8252 |
| 28581000087106 | COVID-19 - Pfizer       | 8251 |
| 28761000087108 | COVID-19 - Astra Zeneca | 8256 |
| 28951000087107 | COVID-19 - Johnson & Johnson / Janssen | 8255 |
| 33361000087101 | COVID19-Pfizer Pediatric | 8292 |
| MB8293 | COVID19-Moderna Half Dose | 8293 |