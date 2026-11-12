
======================================================================
CASIOLAB - DW-H5600 (MODULE 3516)
REVERSE ENGINEERING STATUS
Consolidated technical assessment
Date: 2026-11-12
======================================================================

1. PROJECT OBJECTIVE
----------------------------------------------------------------------

The objective is to reverse-engineer the Casio DW-H5600 ecosystem,
including:

- BLE communication protocol
- Nordic BLE firmware
- STM firmware update architecture
- SOTB and OLDAP components
- Android application internals
- Firmware containers and metadata
- Cryptographic validation mechanisms
- Watch-side update and recovery behavior

The objective is not merely to reproduce the official companion app.

The long-term goal is an open, reproducible and independently
implementable DW-H5600 ecosystem.


2. NORDIC BLE FIRMWARE
----------------------------------------------------------------------

STATUS: SUBSTANTIAL REVERSE-ENGINEERING PROGRESS

Identified hardware and firmware information:

- Nordic BLE controller identified.
- HCI Manufacturer ID: 0x0059
- HCI subversion: 0x0100
- hw_version: 0x34
- nRF52840 compatibility hypothesis.
- BLE application: QXGP4_ble_app.bin
- Application size: 77,416 bytes.
- sd_bl.bin identified in firmware assets.
- Nordic DFU metadata (.dat) identified.
- ECDSA P-256 / SHA-256 signature mechanism identified.

The Nordic update package contains distinct components:

- Application firmware
- SoftDevice / bootloader-related component
- DFU metadata

IMPORTANT:

The Nordic ECDSA signature mechanism must not be confused with
the RSA mechanism reported for the STM update chain.

The Nordic firmware analysis does not prove that STM firmware
can be modified or installed.

CROSS-MODEL FINDING:

The Nordic firmware components from NB3515 and NB3516 were
reported byte-identical, with matching SHA-256 hashes.

This suggests that major differences between the two watch
variants may reside outside the Nordic BLE application.


3. STM / SOTB / OLDAP FIRMWARE
----------------------------------------------------------------------

STATUS: PARTIAL RECONSTRUCTION

The firmware extraction revealed multiple component families:

- STM
- SOTB
- OLDAP
- Nordic BLE

The 3515 and 3516 configurations are not identical.

Reported configuration hashes:

3515:
MD5 = e4c68d9d5a97ee13aa3294179ed46c09

3516:
MD5 = 07a923086e6841ba6e5ea73b0f79aae8

OLDAP 3516:

- Size: 215,853 bytes
- MD5: B8D016C60F9731B110A4905BA6377634

An unexpected reference to OLDAP 3515 was found in a
configuration associated with 3516.

This is an unresolved compatibility and component-selection
question.

Additional observation:

INFO2 = 0x01

Its precise meaning has not yet been established.

Possible explanations requiring investigation:

- Component availability state
- Firmware version compatibility
- Hardware variant selection
- Security validation state
- Component update eligibility


4. CRYPTOGRAPHIC ARCHITECTURE
----------------------------------------------------------------------

STATUS: REPORTED MECHANISMS - IMPLEMENTATION DETAILS
NOT FULLY VALIDATED

The STM update chain is reported to involve:

A. ENCRYPTION

- AES-128-CTR
- Encrypted STM payload
- RSA-wrapped encryption key

The STM payload has not been successfully decrypted.

B. AUTHENTICATION

- RSA-2048-PSS reportedly required.
- Casio private signing key unavailable.
- No valid replacement signing method established.

C. ANTI-ROLLBACK

- SEC_CNT security counter reported.
- Exact storage location unknown.
- Counter update behavior unknown.
- Minimum accepted security version unknown.

IMPORTANT DISTINCTION:

The exact relationship between RSA signature verification,
AES decryption and bootloader acceptance remains unresolved.

Questions still open:

- Is the signature applied to the encrypted payload?
- Is it applied to the decrypted firmware?
- Does it authenticate the entire container?
- Are multiple independent signatures involved?
- Which component performs each verification?


5. CURRENT TECHNICAL BLOCKERS
----------------------------------------------------------------------

BLOCKER 1 - STM PAYLOAD ENCRYPTION

The STM payload remains encrypted.

AES-128-CTR and RSA-wrapped key mechanisms are reported.

No confirmed plaintext STM firmware has been obtained.

BLOCKER 2 - RSA SIGNATURE

RSA-2048-PSS authentication is reported.

No Casio private signing key is available.

No legitimate signing path for modified STM firmware
has been established.

BLOCKER 3 - SECURITY COUNTER

SEC_CNT / anti-rollback mechanism is reported.

Its exact behavior has not been characterized.

BLOCKER 4 - RE-ENCRYPTION

No validated STM decryption and re-encryption workflow exists.

BLOCKER 5 - BOOTLOADER

No complete bootloader dump has been confirmed.

No complete plaintext key inventory is available.

BLOCKER 6 - RECOVERY

No documented insecure DFU mode has been confirmed.

No usable recovery test point has been established.


6. ANDROID UPDATE PIPELINE
----------------------------------------------------------------------

STATUS: PARTIAL SOURCE AND BINARY ANALYSIS

Relevant findings from the Android application:

- OTA firmware assets extracted from assets/airdata/.
- FileUploader comparison logic identified.
- Cloud/local firmware comparison investigated.
- BLE update command 0x20 identified.
- Nordic Secure DFU service 0xFE59 identified.
- STM, SOTB and OLDAP resources identified.

The complete component-selection and update decision chain
still needs to be reconstructed.

Main questions:

- Which component is selected for each hardware variant?
- Which metadata fields determine eligibility?
- At what stage are signatures checked?
- Which component initiates STM update?
- Which failures originate in Android?
- Which failures originate in the watch?


7. OLDAP INVESTIGATION
----------------------------------------------------------------------

PRIORITY: HIGH

Known observations:

- OLDAP 3516 file exists.
- Size: 215,853 bytes.
- MD5: B8D016C60F9731B110A4905BA6377634.
- A 3515 reference exists in a 3516-associated configuration.
- INFO2 = 0x01 was observed.

Required investigations:

1. Identify the exact INFO2 field offset.
2. Find all references to INFO2 in Android code.
3. Compare 3515 and 3516 configuration structures.
4. Determine OLDAP component-selection rules.
5. Identify whether INFO2 affects update eligibility.
6. Determine whether the reference to 3515 is intentional,
   inherited or erroneous.

No interpretation should be considered confirmed without
supporting evidence.


8. PRIORITY INVESTIGATION PLAN
----------------------------------------------------------------------

PRIORITY A - COMPLETE OTA DECISION PIPELINE

Reconstruct the complete Android update sequence:

- Firmware discovery
- Version comparison
- Hardware compatibility
- Component selection
- Transfer initiation
- Update completion
- Error handling

PRIORITY B - CRYPTOGRAPHIC CONTAINER ANALYSIS

For every STM-related file, record:

- Exact file size
- SHA-256
- Header structure
- Field offsets
- Payload offsets
- Length fields
- Encryption metadata
- Signature metadata
- Component identifiers

PRIORITY C - RSA VALIDATION ANALYSIS

Identify:

- Public certificates
- Public keys
- RSA modulus size
- Padding scheme
- Signature length
- Signed data boundaries
- Key-envelope format

A public key may allow signature verification without
requiring the private signing key.

PRIORITY D - SEC_CNT CHARACTERIZATION

Identify:

- Counter location
- Counter format
- Associated firmware component
- Minimum accepted value
- Increment conditions
- Rollback rejection behavior

PRIORITY E - OLDAP 3515/3516 COMPARISON

Investigate configuration inheritance and INFO2 semantics.

PRIORITY F - BOOTLOADER AND RECOVERY

Determine whether the available firmware assets expose:

- Bootloader version
- Bootloader validation logic
- Recovery commands
- Update-state transitions
- Error codes
- Security configuration


9. EVIDENCE CLASSIFICATION
----------------------------------------------------------------------

All future findings must use four evidence levels.

[OBSERVED]

Directly captured or extracted:

- BLE packets
- File contents
- Hashes
- Binary structures
- Runtime behavior

[STATICALLY ESTABLISHED]

Established by source analysis, disassembly or binary analysis.

[HYPOTHESIS]

Technically plausible interpretation requiring validation.

[UNCONFIRMED]

Not demonstrated experimentally or supported by sufficient
evidence.

Never present a static-analysis hypothesis as a proven
bootloader behavior.


10. CURRENT PROJECT ASSESSMENT
----------------------------------------------------------------------

WHAT HAS BEEN ACHIEVED:

- Nordic BLE firmware identification.
- Firmware asset extraction.
- Nordic DFU metadata analysis.
- Cross-model firmware comparison.
- STM / SOTB / OLDAP component identification.
- Android update pipeline investigation.
- BLE protocol reverse engineering.
- Firmware configuration comparison.

WHAT HAS NOT BEEN ACHIEVED:

- Confirmed STM plaintext extraction.
- Valid modified STM firmware image.
- Casio-compatible RSA signing.
- Validated STM re-encryption.
- Confirmed bootloader bypass.
- Confirmed custom firmware installation.
- Confirmed alternative recovery method.

THE CENTRAL TECHNICAL CHALLENGE:

Understanding firmware is not equivalent to producing
firmware accepted by the target bootloader.

CasioLab has made substantial progress in firmware analysis
and update architecture reconstruction.

The next milestone is to establish the precise relationship
between STM encryption, RSA authentication, security counters
and component-selection logic.


11. STRATEGIC CONCLUSION
----------------------------------------------------------------------

The immediate objective should NOT be to assume that RSA
must be bypassed.

The next investigations should establish:

1. Why does the 3516 configuration reference OLDAP 3515?
2. What exactly does INFO2 = 0x01 represent?
3. Where is the boundary between Nordic, STM, SOTB and OLDAP?
4. What exact data is authenticated by RSA?
5. Where and how is SEC_CNT enforced?
6. At which stage does the Android application hand control
   to the watch-side update mechanism?

Resolving these questions could reveal the complete update
architecture without requiring access to Casio private keys.

======================================================================
CASIOLAB - DW-H5600 / MODULE 3516
STATUS: ACTIVE REVERSE ENGINEERING
======================================================================

