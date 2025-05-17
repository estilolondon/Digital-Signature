# Electronic Signature Verification Smart Contract

A Clarity smart contract for managing and verifying electronic signatures on the Stacks blockchain.

## Overview

This smart contract provides a complete solution for electronic signature verification, document management, and signature tracking. It leverages the Stacks blockchain to create a tamper-proof, secure system for verifying and managing electronic signatures.

## Features

- **Document Management**
  - Create and store document hashes
  - Track document metadata and status
  - Support for document revocation
  - Update document metadata

- **Electronic Signature Operations**
  - Register user public keys
  - Sign documents with cryptographic signatures
  - Verify signature authenticity
  - Batch verification of multiple signatures
  - Invalidate specific signatures

- **Security and Access Control**
  - Creator-only access for sensitive operations
  - Status checking before operations
  - Comprehensive error handling

## Requirements

- Stacks blockchain network access
- Clarity-compatible wallet (like Hiro Wallet)
- Basic understanding of cryptographic signatures

## Installation

1. Clone this repository
2. Deploy the contract to the Stacks blockchain using Clarinet or another Stacks deployment tool:

```bash
clarinet contract deploy
```

## Usage Guide

### Key Management

Before using the signature system, users must register their public keys:

```clarity
(contract-call? .electronic-signature-verification register-public-key <public-key>)
```

### Document Management

#### Creating a Document

```clarity
(contract-call? .electronic-signature-verification create-document 
  <document-hash> 
  <title> 
  <description>)
```

The `document-hash` should be a 32-byte buffer representing the SHA-256 hash of your document.

#### Updating Document Metadata

Only the document creator can update metadata:

```clarity
(contract-call? .electronic-signature-verification update-document-metadata 
  <document-hash> 
  <new-title> 
  <new-description>)
```

#### Revoking a Document

Document creators can revoke documents to prevent further signatures:

```clarity
(contract-call? .electronic-signature-verification revoke-document <document-hash>)
```

### Signature Operations

#### Signing a Document

```clarity
(contract-call? .electronic-signature-verification sign-document 
  <document-hash> 
  <signature> 
  <message>)
```

The `signature` must be a valid 65-byte ECDSA signature created by signing the hash of the concatenation of the document hash and the message.

#### Batch Verification

Verify multiple signatures at once:

```clarity
(contract-call? .electronic-signature-verification batch-verify-signatures 
  <document-hash> 
  <list-of-signers>)
```

#### Invalidating a Signature

Document creators can invalidate specific signatures:

```clarity
(contract-call? .electronic-signature-verification invalidate-signature 
  <document-hash> 
  <signer>)
```

### Read-Only Functions

Query information without changing contract state:

- `get-document`: Retrieve document details
- `document-exists`: Check if a document exists
- `get-signature`: Get signature details
- `has-signed`: Check if a principal has signed a document
- `get-signature-count`: Count signatures for a document
- `get-public-key`: Retrieve a user's public key
- `verify-signature`: Verify a signature against a message
- `get-total-documents`: Get the total number of documents

## Technical Details

### Cryptographic Verification

The contract uses Clarity's built-in `secp256k1-recover?` function to verify ECDSA signatures. This ensures that only the holder of the private key corresponding to the registered public key can create valid signatures.

### Data Storage

- Documents are stored with their hash as the key
- Signatures are stored with a composite key of document hash and signer address
- Public keys are stored with the principal (user address) as the key

### Error Codes

- `u401`: Not authorized
- `u404`: Document or key not found
- `u409`: Document already exists or already signed
- `u400`: Invalid signature
- `u403`: Document revoked

## Security Considerations

- Never share your private key
- Verify document hashes carefully before signing
- Document creators should maintain proper records of all signatures
- Consider implementing a multi-signature approach for critical documents