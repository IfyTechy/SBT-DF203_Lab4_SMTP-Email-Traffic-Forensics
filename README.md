# SBT-DF203-Lab4: SMTP Email Traffic Forensic Analysis

A structured network forensics investigation focused on inspecting cleartext Simple Mail Transfer Protocol (SMTP) traffic inside a packet capture (`.pcap`) file. This lab demonstrates packet-level inspection, cryptographic hash verification, Base64 credential extraction, and email message reconstruction using CLI and GUI network analysis tools.

---

## 📌 Investigation Overview

- **Target PCAP:** `smtp.pcap` (Wireshark Sample Captures)
- **Primary Tools:** `tshark`, `wireshark`, `python3`, `sha256sum`, `capinfos`
- **Environment:** Kali Linux

### Key Analytical Findings
- **Transport Layer Security:** The mail server advertised `STARTTLS` capability in the `EHLO` response, but the client did not initiate an upgrade. Entire communication took place over cleartext TCP (Port 25).
- **Authentication Method:** Executed via `AUTH LOGIN` (Base64 encoded).
- **Extracted Mail Server:** `xc90.websitewelcome.com` (Exim 4.69) [IP: `74.53.140.153`]
- **Client Endpoints:** Internal IP `10.10.1.4:1470` / Connecting IP `122.162.143.157`

---

## 📁 Repository Structure

```text
SBT-DF203-Lab4/
├── evidence/
│   └── smtp.pcap                   # Original evidence capture file
├── working/
│   └── smtp_working.pcap           # Working copy for analysis
├── scripts/
│   └── decode_auth.py              # Base64 credential decoding script
├── reports/
│   ├── smtp_capture_hashes.txt     # Cryptographic integrity hashes
│   ├── smtp_capinfos.txt           # Metadata summary of the PCAP file
│   ├── tcp_conversations.txt       # Stream & conversation summaries
│   ├── smtp_packet_inventory.tsv   # Structured packet-by-packet inventory
│   ├── smtp_commands_responses.tsv # Parsed SMTP verbs and response codes
│   ├── decoded_auth_masked.txt     # Redacted credential dump for reporting
│   ├── smtp_stream_0.txt           # Full TCP stream ASCII follow
│   ├── message_headers.txt         # Extracted email RFC 822 headers
│   └── reconstructed_email_redacted.txt # Complete reconstructed stream
└── README.md
```

## ⚙️ Execution & Methodology

**1. Evidence Acquisition & Integrity Verification**
Downloaded the target packet capture file, created a working replica, and verified SHA-256 hashes to guarantee evidence integrity:

```bash
mkdir -p ~/SBT-DF203-Lab4/{evidence,working,exported,reports,scripts}
cd ~/SBT-DF203-Lab4

# Download evidence
wget -O evidence/smtp.pcap '[https://wiki.wireshark.org/uploads/_moin_import_/attachments/SampleCaptures/smtp.pcap](https://wiki.wireshark.org/uploads/_moin_import_/attachments/SampleCaptures/smtp.pcap)'

# Preserve timestamps and create working copy
cp --preserve=timestamps evidence/smtp.pcap working/smtp_working.pcap

# Calculate & verify SHA-256 hashes
sha256sum evidence/smtp.pcap working/smtp_working.pcap | tee reports/smtp_capture_hashes.txt
```

Verification: Ensure both `evidence/smtp.pcap` and `working/smtp_working.pcap output` matching SHA-256 hashes `(17ad230db1b6fd5dd18eb311092df1cf6eb162054bdb47697b89bef5a86a47ab)`.

**2. PCAP Metadata & Conversation Summaries**

Generated statistical and layer-4 metadata using capinfos and tshark:

```bash
# Capture metadata
capinfos evidence/smtp.pcap | tee reports/smtp_capinfos.txt

# Extract TCP conversation statistics
tshark -r working/smtp_working.pcap -z conv,tcp | tee reports/tcp_conversations.txt
```

**3. Protocol & Command Analysis**

Extracted packet inventories, response codes, and verified security capabilities:

```bash
# Extract SMTP Packet Inventory
tshark -r working/smtp_working.pcap -Y 'smtp' -T fields \
  -e frame.number -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e _ws.col.Info \
  | tee reports/smtp_packet_inventory.tsv

# Check STARTTLS Availability vs Execution
tshark -r working/smtp_working.pcap -Y 'smtp.rsp.parameter contains "STARTTLS"' \
  -T fields -e frame.number -e frame.time -e smtp.rsp.parameter | tee reports/starttls_check.txt

tshark -r working/smtp_working.pcap -Y 'smtp.req.command == "STARTTLS"' | tee reports/starttls_invoked_check.txt
```

**4. Base64 Credential Extraction & Decoding**

Extracted Base64 encoded `AUTH LOGIN` parameters from the packet stream and decoded them via Python:

```bash

# scripts/decode_auth.py
import base64

samples = {
    'username': 'Z3VycGFydGFwQHBhdHJpb3RzLmlu',
    'password': 'cHVuamFiQDEyMw='
}

for label, value in samples.items():
    try:
        decoded = base64.b64decode(value).decode('utf-8', errors='replace')
        print(f'{label}: {decoded}')
    except Exception as exc:
        print(f'{label}: decode failed: {exc}')
```

Execute and save outputs:

```bash
python3 scripts/decode_auth.py | tee reports/decoded_auth_full.txt
```

Verification: Verify that the script decodes the authentication strings into readable email and password credentials.

**5. Stream Reconstruction & Redaction**

Reconstructed the raw TCP stream (Stream ID 0) and parsed email headers:

```bash
# Follow TCP Stream 0
tshark -r working/smtp_working.pcap -q -z follow,tcp,ascii,0 | tee reports/smtp_stream_0.txt

# Filter email headers
grep -E '^(From|To|Subject|Date|Message-ID|MIME-Version|Content-Type|X-Mailer):' \
  reports/smtp_stream_0.txt | tee reports/message_headers.txt

# Create redacted stream export for public reporting
sed -e 's/Z3VycGFydGFwQHBhdHJpb3RzLmlu/[REDACTED-BASE64-USERNAME]/' \
    -e 's/cHVuamFiQDEyMw==/[REDACTED-BASE64-PASSWORD]/' \
    reports/smtp_stream_0.txt > reports/reconstructed_email_redacted.txt
```

## 🔒 Security & Forensic Notes

**1. Lack of In-Transit Encryption:** Using standard AUTH LOGIN over unencrypted SMTP (TCP/25) exposes plaintext credentials to network eavesdropping and man-in-the-middle (MitM) inspection.

**2. Chain of Custody:** The integrity of the PCAP file was maintained throughout analysis by isolating raw evidence in a read-only state and performing all operations on working copies verified via SHA-256 integrity checks.














