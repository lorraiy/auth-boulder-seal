;; AuthBoulderSeal - Decentralized Credential Verification System
;; A privacy-preserving professional credential platform

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-authorized (err u101))
(define-constant err-credential-exists (err u102))
(define-constant err-credential-not-found (err u103))
(define-constant err-institution-not-registered (err u104))
(define-constant err-credential-revoked (err u105))
(define-constant err-invalid-commitment (err u106))

;; Data Variables
(define-data-var institution-count uint u0)
(define-data-var credential-count uint u0)
(define-data-var minting-fee uint u1000000) ;; 1 STX in microSTX

;; Data Maps
(define-map institutions 
  principal 
  {
    name: (string-ascii 100),
    registered-at: uint,
    active: bool,
    credentials-issued: uint
  }
)

(define-map credentials
  uint
  {
    holder: principal,
    issuer: principal,
    credential-type: (string-ascii 50),
    issued-at: uint,
    expires-at: (optional uint),
    revoked: bool,
    commitment-hash: (buff 32),
    metadata-uri: (string-ascii 256)
  }
)

(define-map holder-credentials
  principal
  (list 100 uint)
)

(define-map credential-endorsements
  uint
  {
    endorsement-count: uint,
    reputation-score: uint
  }
)

(define-map endorsements
  {credential-id: uint, endorser: principal}
  {
    timestamp: uint,
    weight: uint
  }
)

;; Private Functions
(define-private (is-institution (account principal))
  (match (map-get? institutions account)
    institution (get active institution)
    false
  )
)

;; Public Functions

;; Register Institution
(define-public (register-institution (name (string-ascii 100)))
  (let ((caller tx-sender))
    (asserts! (is-eq caller contract-owner) err-owner-only)
    (ok (map-set institutions caller {
      name: name,
      registered-at: block-height,
      active: true,
      credentials-issued: u0
    }))
  )
)

;; Mint Credential
(define-public (mint-credential 
  (holder principal)
  (credential-type (string-ascii 50))
  (expires-at (optional uint))
  (commitment-hash (buff 32))
  (metadata-uri (string-ascii 256))
)
  (let (
    (caller tx-sender)
    (new-id (+ (var-get credential-count) u1))
    (institution-data (unwrap! (map-get? institutions caller) err-institution-not-registered))
  )
    (asserts! (get active institution-data) err-not-authorized)
    
    ;; Pay minting fee
    (try! (stx-transfer? (var-get minting-fee) caller contract-owner))
    
    ;; Create credential
    (map-set credentials new-id {
      holder: holder,
      issuer: caller,
      credential-type: credential-type,
      issued-at: block-height,
      expires-at: expires-at,
      revoked: false,
      commitment-hash: commitment-hash,
      metadata-uri: metadata-uri
    })
    
    ;; Update holder's credential list
    (let ((current-creds (default-to (list) (map-get? holder-credentials holder))))
      (map-set holder-credentials holder (unwrap-panic (as-max-len? (append current-creds new-id) u100)))
    )
    
    ;; Initialize endorsement tracking
    (map-set credential-endorsements new-id {
      endorsement-count: u0,
      reputation-score: u0
    })
    
    ;; Update institution stats
    (map-set institutions caller (merge institution-data {
      credentials-issued: (+ (get credentials-issued institution-data) u1)
    }))
    
    (var-set credential-count new-id)
    (ok new-id)
  )
)

;; Verify Credential (ZK-proof verification placeholder)
(define-read-only (verify-credential (credential-id uint) (proof-hash (buff 32)))
  (let ((cred (unwrap! (map-get? credentials credential-id) err-credential-not-found)))
    (asserts! (not (get revoked cred)) err-credential-revoked)
    (ok {
      valid: (is-eq (get commitment-hash cred) proof-hash),
      issuer: (get issuer cred),
      credential-type: (get credential-type cred),
      issued-at: (get issued-at cred)
    })
  )
)

;; Revoke Credential
(define-public (revoke-credential (credential-id uint))
  (let (
    (cred (unwrap! (map-get? credentials credential-id) err-credential-not-found))
    (caller tx-sender)
  )
    (asserts! (is-eq caller (get issuer cred)) err-not-authorized)
    (ok (map-set credentials credential-id (merge cred {revoked: true})))
  )
)

;; Add Endorsement
(define-public (endorse-credential (credential-id uint) (weight uint))
  (let (
    (cred (unwrap! (map-get? credentials credential-id) err-credential-not-found))
    (caller tx-sender)
    (endorsement-data (default-to {endorsement-count: u0, reputation-score: u0} 
                                   (map-get? credential-endorsements credential-id)))
  )
    (asserts! (not (get revoked cred)) err-credential-revoked)
    
    ;; Record endorsement
    (map-set endorsements {credential-id: credential-id, endorser: caller} {
      timestamp: block-height,
      weight: weight
    })
    
    ;; Update reputation
    (ok (map-set credential-endorsements credential-id {
      endorsement-count: (+ (get endorsement-count endorsement-data) u1),
      reputation-score: (+ (get reputation-score endorsement-data) weight)
    }))
  )
)

;; Read-Only Functions

(define-read-only (get-credential (credential-id uint))
  (ok (map-get? credentials credential-id))
)

(define-read-only (get-holder-credentials (holder principal))
  (ok (map-get? holder-credentials holder))
)

(define-read-only (get-institution (institution principal))
  (ok (map-get? institutions institution))
)

(define-read-only (get-credential-reputation (credential-id uint))
  (ok (map-get? credential-endorsements credential-id))
)

(define-read-only (get-minting-fee)
  (ok (var-get minting-fee))
)

;; Admin Functions

(define-public (set-minting-fee (new-fee uint))
  (begin
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (ok (var-set minting-fee new-fee))
  )
)

(define-public (deactivate-institution (institution principal))
  (let ((inst-data (unwrap! (map-get? institutions institution) err-institution-not-registered)))
    (asserts! (is-eq tx-sender contract-owner) err-owner-only)
    (ok (map-set institutions institution (merge inst-data {active: false})))
  )
)