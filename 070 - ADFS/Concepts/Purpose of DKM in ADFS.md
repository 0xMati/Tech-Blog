---
title: "The Use of Distributed Key Manager (DKM) in Active Directory Federation Services (AD FS)"
date: 2025-04-08
---

## Overview

When planning and designing an Active Directory Federation Services (AD FS) infrastructure, certificate management is a critical aspect. AD FS shares a set of common certificates for token signing and decryption, and a key question is: how are the private keys protected and shared?

The answer lies in the **Distributed Key Manager (DKM)**, a component of Active Directory Domain Services (AD DS) used by AD FS to protect cryptographic material such as certificate private keys.

---

## How It Works

### 🔐 Certificate Storage and Encryption

- Token signing and decryption certificates (in PFX format) are stored in the **AD FS configuration database**.
- The database table that stores these encrypted PFX blobs is protected using **Distributed Key Manager (DKM)**.
- DKM keys themselves are stored in **Active Directory Domain Services (AD DS)**, in a secured container accessible only by the AD FS service account.

### 🔄 Key Lifecycle

- During initial AD FS farm setup, a **dedicated container** is created in AD DS to store the DKM master encryption key.
- This container must be in the same domain as the AD FS service account.
- AD FS generates new DKM keys as needed—when the farm is created or when an existing key expires (by default, after one year).

---

## Certificate Generation & Synchronization

When a certificate needs to be created or renewed:

1. One AD FS node generates the certificate and stores it in the **MY certificate store** of the AD FS service account.
2. The certificate is **serialized and encrypted** with the DKM master key and stored in the AD FS config database.

Upon AD FS startup:

1. The server **retrieves and decrypts** the certificate using the DKM client API.
2. The **PFX is deserialized** and installed locally into the MY certificate store of the AD FS service account.

---

## Summary Points

- Certificates are stored as **PFX blobs** in the AD FS configuration database.
- Encrypted using **DKM**, with master keys stored in **AD DS**.
- AD FS nodes **decrypt and read keys** from AD DS during startup.
- Only the **AD FS service account** can access the DKM keys and read certificates.
- All AD FS nodes share the same **token signing and decryption certificates**.

---

## Further Reading

- Original blog post by Paul Williams: [source](https://blog.msresource.net/2016/05/04/the-use-of-distributed-key-manager-dkm-in-active-directory-federation-services-ad-fs/)
- [How AD FS uses DKM](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/overview/ad-fs-design-overview)

