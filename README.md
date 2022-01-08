# smart-card-qr-verifier

This is a spike / PoC for an app that will allow someone to upload a government generated PDF containing a SMART QR code 
and it will extract basic info.

References
* https://github.com/ongov/OpenVerify

* https://smarthealth.cards/en/
* https://github.com/smart-on-fhir/health-cards
* https://github.com/smart-on-fhir/health-cards/blob/main/docs/index.md

Vaccine type code, draft
* http://build.fhir.org/valueset-vaccine-code.html

After trying many, many libraries, I found nimbus could read it and allow modifications to be able to deal with the SMART health card QA code
* https://connect2id.com/products/nimbus-jose-jwt
