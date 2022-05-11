Some hacks to bridge ibm dilithium with x509
```
Dilithium (this list already includes the supported round 2 6-5 strength) and Kyber strengths:
The following object identifiers (OIDs) from IBM’s networking OID range
are reserved for Crystals variants:
-- round 2 Dilithium, with SHAKE(-256) as PRF:
1.3.6.1.4.1.2.267.1 dilithium
1.3.6.1.4.1.2.267.1.5.4 dilithium-rec -- NIST ’recommended’
1.3.6.1.4.1.2.267.1.6.5 dilithium-high -- NIST ’high-security’
1.3.6.1.4.1.2.267.1.8.7 dilithium-87 -- used for outbound-authentication
-- round 3 Dilithium, with SHAKE(-256) as PRF:
1.3.6.1.4.1.2.267.7 dilithium-r3
1.3.6.1.4.1.2.267.7.4.4 dilithium-r3-weak
1.3.6.1.4.1.2.267.7.6.5 dilithium-r3-rec -- NIST ’recommended’
1.3.6.1.4.1.2.267.7.8.7 dilithium-r3-vhigh -- NIST ’high-security’
-- round 2 Dilithium, equivalents with SHA-512 as PRF:
1.3.6.1.4.1.2.267.3 dilithium-sha512
1.3.6.1.4.1.2.267.3.5.4 dilithium-sha512-rec -- see NIST recommended
1.3.6.1.4.1.2.267.3.6.5 dilithium-sha512-high -- see NIST high-security
1.3.6.1.4.1.2.267.3.7.6 dilithium-sha512-vhigh -- see NIST ’vhigh’
-- round 2 Kyber submissions, with SHAKE(-128) as PRF:
1.3.6.1.4.1.2.267.5 Kyber-r2
1.3.6.1.4.1.2.267.5.3.3 Kyber-r2rec
1.3.6.1.4.1.2.267.5.4.4 Kyber-r2high
```
