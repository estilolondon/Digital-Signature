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
;; This is a placeholder implementation that always returns 0
(define-read-only (get-signature-count (document-hash (buff 32)))
  u0  ;; Returning a fixed value for now
)

;; In a real implementation, you would likely want a proper signature counting mechanism
;; Here's an example approach that could be implemented:
;; 1. Store a counter for each document
;; 2. Increment the counter when a signature is added
;; 3. Decrement the counter when a signature is invalidated

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
            status: u"active"  ;; Changed from "active" to u"active" for UTF-8 encoding
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
      ;; Create a hash directly from document-hash and message for verification
      (message-hash (sha256 (concat document-hash (sha256 (unwrap! (to-consensus-buff? message) ERR-INVALID-SIGNATURE)))))
    )
      ;; Check if document is active
      (asserts! (is-eq (get status doc) u"active") ERR-DOCUMENT-REVOKED)
      
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
        (merge doc { status: u"revoked" })  ;; Changed from "revoked" to u"revoked" for UTF-8 encoding
      )
      (ok true)
    )
  )
)

;; Batch verify signatures - one-by-one approach
(define-public (batch-verify-signatures
    (document-hash (buff 32))
    (signers (list 10 principal)))
  (let ((doc-data (get-document document-hash)))
    (asserts! (is-some doc-data) ERR-DOCUMENT-NOT-FOUND)
    
    (let ((doc (unwrap-panic doc-data)))
      ;; Check if document is active
      (asserts! (is-eq (get status doc) u"active") ERR-DOCUMENT-REVOKED)
      
      ;; Check each signer individually
      ;; This is a very verbose approach but avoids the recursion issue
      (ok (and
        ;; Check if list is empty - if so, consider it valid
        (or (is-eq (len signers) u0) 
          (and
            ;; Check first signer if exists
            (or (< (len signers) u1) (has-signed document-hash (unwrap-panic (element-at signers u0))))
            ;; Check second signer if exists
            (or (< (len signers) u2) (has-signed document-hash (unwrap-panic (element-at signers u1))))
            ;; Check third signer if exists
            (or (< (len signers) u3) (has-signed document-hash (unwrap-panic (element-at signers u2))))
            ;; Check fourth signer if exists
            (or (< (len signers) u4) (has-signed document-hash (unwrap-panic (element-at signers u3))))
            ;; Check fifth signer if exists
            (or (< (len signers) u5) (has-signed document-hash (unwrap-panic (element-at signers u4))))
            ;; Check sixth signer if exists
            (or (< (len signers) u6) (has-signed document-hash (unwrap-panic (element-at signers u5))))
            ;; Check seventh signer if exists
            (or (< (len signers) u7) (has-signed document-hash (unwrap-panic (element-at signers u6))))
            ;; Check eighth signer if exists
            (or (< (len signers) u8) (has-signed document-hash (unwrap-panic (element-at signers u7))))
            ;; Check ninth signer if exists
            (or (< (len signers) u9) (has-signed document-hash (unwrap-panic (element-at signers u8))))
            ;; Check tenth signer if exists
            (or (< (len signers) u10) (has-signed document-hash (unwrap-panic (element-at signers u9))))
          )
        )
      ))
    )
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