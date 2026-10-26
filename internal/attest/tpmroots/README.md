<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# TPM makers' certificates

`roots.pem` holds the root and intermediate certificates of the TPM makers that endorsement
key (EK) certificates lead to (docs/protocol.md, section 17, "TPM evidence"). A key in a
TPM whose EK certificate leads to none of them stays `hardware`, never `proven`.

The source is Microsoft's TrustedTpm.cab (`https://go.microsoft.com/fwlink/?linkid=2097925`),
Authenticode-signed, which Windows uses for the same check. The maintainer updates it before
a release: download it, check its signature, extract the certificates, review the diff, and
write the source's date here. Until the first update the file is empty and no TPM is proven.
