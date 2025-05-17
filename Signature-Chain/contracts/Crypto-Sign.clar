;; Electronic Signature Verification Smart Contract
;; Purpose: Verify electronic signatures, manage document hashes, and track signatures

;; Data Maps and Variables

;; Map to store document hashes with their metadata
(define-map documents
  { document-hash: (buff 32) }
  {
    creator: principal,
    title: (string-utf8 256),
    description: (string-utf8 1024),
    created-at: uint,
    status: (string-utf8 20)  ;; "active" or "revoked"
  }
)

;; Map to track signatures for each document
(define-map signatures
  { 
    document-hash: (buff 32),
    signer: principal
  }
  {
    signature: (buff 65),     ;; ECDSA signatures are 65 bytes
    signed-at: uint,
    message: (string-utf8 256),
    is-valid: bool
  }
)

;; Map to store public keys for users
(define-map user-public-keys
  { user: principal }
  { public-key: (buff 33) }   ;; Compressed secp256k1 public keys are 33 bytes
)

;; Counter for tracking total documents
(define-data-var total-documents uint u0)

;; Error Constants
(define-constant ERR-NOT-AUTHORIZED (err u401))
(define-constant ERR-DOCUMENT-NOT-FOUND (err u404))
(define-constant ERR-DOCUMENT-ALREADY-EXISTS (err u409))
(define-constant ERR-INVALID-SIGNATURE (err u400))
(define-constant ERR-ALREADY-SIGNED (err u409))
(define-constant ERR-DOCUMENT-REVOKED (err u403))
(define-constant ERR-PUBLIC-KEY-NOT-FOUND (err u404))

;; Read-Only Functions

;; Get document details
(define-read-only (get-document (document-hash (buff 32)))
  (map-get? documents { document-hash: document-hash })
)

;; Check if a document exists
(define-read-only (document-exists (document-hash (buff 32)))
  (is-some (map-get? documents { document-hash: document-hash }))
)

;; Get signature details for a document and signer
(define-read-only (get-signature (document-hash (buff 32)) (signer principal))
  (map-get? signatures { document-hash: document-hash, signer: signer })
)

;; Check if a document has been signed by a specific principal
(define-read-only (has-signed (document-hash (buff 32)) (signer principal))
  (is-some (map-get? signatures { document-hash: document-hash, signer: signer }))
)

;; Get the total number of signatures for a document
(define-read-only (get-signature-count (document-hash (buff 32)))
  (fold check-signature-for-document u0 (map-get? documents { document-hash: document-hash }))
)

;; Helper function for counting signatures
(define-private (check-signature-for-document (count uint) (doc-data (optional {
  creator: principal,
  title: (string-utf8 256),
  description: (string-utf8 1024),
  created-at: uint,
  status: (string-utf8 20)
})))
  (match doc-data
    doc-unwrapped (fold count-signature count (unwrap-panic doc-unwrapped))
    count
  )
)

;; Helper function for signature counting
(define-private (count-signature (count uint) (signer principal))
  (if (has-signed (some-buff document-hash) signer)
    (+ count u1)
    count
  )
)

;; Get user's public key
(define-read-only (get-public-key (user principal))
  (map-get? user-public-keys { user: user })
)

;; Verify a signature for a message
(define-read-only (verify-signature 
    (message (buff 32))
    (signature (buff 65))
    (public-key (buff 33)))
  (is-eq (secp256k1-recover? message signature) (ok public-key))
)

;; Get total documents count
(define-read-only (get-total-documents)
  (var-get total-documents)
)

;; Public Functions

;; Register user public key
(define-public (register-public-key (public-key (buff 33)))
  (begin
    (map-set user-public-keys
      { user: tx-sender }
      { public-key: public-key }
    )
    (ok true)
  )
)

;; Create a new document
(define-public (create-document 
    (document-hash (buff 32))
    (title (string-utf8 256))
    (description (string-utf8 1024)))
  (let ((current-time (unwrap-panic (get-block-info? time (- block-height u1)))))
    (if (document-exists document-hash)
      ERR-DOCUMENT-ALREADY-EXISTS
      (begin
        (map-set documents
          { document-hash: document-hash }
          {
            creator: tx-sender,
            title: title,
            description: description,
            created-at: current-time,
            status: "active"
          }
        )
        (var-set total-documents (+ (var-get total-documents) u1))
        (ok true)
      )
    )
  )
)

;; Sign a document
(define-public (sign-document 
    (document-hash (buff 32))
    (signature (buff 65))
    (message (string-utf8 256)))
  (let (
    (doc-data (get-document document-hash))
    (current-time (unwrap-panic (get-block-info? time (- block-height u1))))
    (public-key-data (get-public-key tx-sender))
  )
    (asserts! (is-some doc-data) ERR-DOCUMENT-NOT-FOUND)
    (asserts! (is-some public-key-data) ERR-PUBLIC-KEY-NOT-FOUND)
    
    (let (
      (doc (unwrap-panic doc-data))
      (public-key (get public-key (unwrap-panic public-key-data)))
      (message-hash (sha256 (concat document-hash (string-to-buff message))))
    )
      ;; Check if document is active
      (asserts! (is-eq (get status doc) "active") ERR-DOCUMENT-REVOKED)
      
      ;; Check if already signed
      (asserts! (not (has-signed document-hash tx-sender)) ERR-ALREADY-SIGNED)
      
      ;; Verify signature
      (asserts! (verify-signature message-hash signature public-key) ERR-INVALID-SIGNATURE)
      
      ;; Record the signature
      (map-set signatures
        { document-hash: document-hash, signer: tx-sender }
        { 
          signature: signature,
          signed-at: current-time,
          message: message,
          is-valid: true
        }
      )
      (ok true)
    )
  )
)

;; Revoke a document (only creator can revoke)
(define-public (revoke-document (document-hash (buff 32)))
  (let ((doc-data (get-document document-hash)))
    (asserts! (is-some doc-data) ERR-DOCUMENT-NOT-FOUND)
    
    (let ((doc (unwrap-panic doc-data)))
      ;; Check if caller is the creator
      (asserts! (is-eq tx-sender (get creator doc)) ERR-NOT-AUTHORIZED)
      
      ;; Update document status to revoked
      (map-set documents
        { document-hash: document-hash }
        (merge doc { status: "revoked" })
      )
      (ok true)
    )
  )
)

;; Batch verify signatures
(define-public (batch-verify-signatures
    (document-hash (buff 32))
    (signers (list 10 principal)))
  (let ((doc-data (get-document document-hash)))
    (asserts! (is-some doc-data) ERR-DOCUMENT-NOT-FOUND)
    
    (let ((doc (unwrap-panic doc-data)))
      ;; Check if document is active
      (asserts! (is-eq (get status doc) "active") ERR-DOCUMENT-REVOKED)
      
      ;; Verify all signatures in batch
      (ok (fold check-signatures true signers))
    )
  )
)

;; Helper function for batch verification
(define-private (check-signatures (result bool) (signer principal))
  (if result
    (is-some (get-signature (some-buff document-hash) signer))
    false
  )
)

;; Update document metadata (only creator can update)
(define-public (update-document-metadata
    (document-hash (buff 32))
    (title (string-utf8 256))
    (description (string-utf8 1024)))
  (let ((doc-data (get-document document-hash)))
    (asserts! (is-some doc-data) ERR-DOCUMENT-NOT-FOUND)
    
    (let ((doc (unwrap-panic doc-data)))
      ;; Check if caller is the creator
      (asserts! (is-eq tx-sender (get creator doc)) ERR-NOT-AUTHORIZED)
      
      ;; Update document metadata
      (map-set documents
        { document-hash: document-hash }
        (merge doc { 
          title: title,
          description: description
        })
      )
      (ok true)
    )
  )
)

;; Invalidate a signature (only document creator can invalidate signatures)
(define-public (invalidate-signature
    (document-hash (buff 32))
    (signer principal))
  (let (
    (doc-data (get-document document-hash))
    (sig-data (get-signature document-hash signer))
  )
    (asserts! (is-some doc-data) ERR-DOCUMENT-NOT-FOUND)
    (asserts! (is-some sig-data) ERR-INVALID-SIGNATURE)
    
    (let (
      (doc (unwrap-panic doc-data))
      (sig (unwrap-panic sig-data))
    )
      ;; Check if caller is the creator
      (asserts! (is-eq tx-sender (get creator doc)) ERR-NOT-AUTHORIZED)
      
      ;; Invalidate the signature
      (map-set signatures
        { document-hash: document-hash, signer: signer }
        (merge sig { is-valid: false })
      )
      (ok true)
    )
  )
)

;; Helper functions for converting between types
(define-private (string-to-buff (str (string-utf8 256)))
  (unwrap-panic (as-max-len? (concat 0x (sha256 str)) u32))
)