(ns metabase.sso.cloudflare-zero-trust.jwt
  "JWT token validation for Cloudflare Zero Trust (Access).

   Validates JWTs from the Cf-Access-Jwt-Assertion header using Cloudflare's
   JWKS endpoint. Implements security measures including:
   - Explicit RS256 algorithm allowlist (prevents alg=none attacks)
   - SSRF protection for JWKS URL
   - JWKS caching with automatic refresh on signature failure
   - Required claim validation (email, aud, iss, exp, nbf)"
  (:require
   [buddy.core.keys :as keys]
   [buddy.sign.jwt :as jwt]
   [cheshire.core :as json]
   [clj-http.client :as http]
   [clojure.string :as str]
   [java-time.api :as t]
   [metabase.sso.cloudflare-zero-trust.settings :as settings]
   [metabase.util :as u]
   [metabase.util.http :as u.http]
   [metabase.util.log :as log]))

(set! *warn-on-reflection* true)

;;; ------------------------------------------------ Constants ------------------------------------------------

(def ^:private allowed-algorithms
  "SECURITY: Only RS256 is allowed. This prevents algorithm confusion attacks where
   an attacker changes the alg header to 'none' or 'HS256' to bypass signature verification."
  #{:rs256})

(def ^:private jwks-cache-ttl-ms
  "JWKS cache TTL: 5 minutes. After this time, cached JWKS will be re-fetched."
  (* 5 60 1000))

(def ^:private clock-skew-leeway-seconds
  "Allow 60 seconds of clock skew for exp and nbf validation."
  60)

;;; ------------------------------------------------ JWKS Cache ------------------------------------------------

(def ^:private jwks-cache
  "Cache of JWKS with TTL. Atom containing {:keys [list of JWKs] :fetched-at timestamp}."
  (atom {:keys nil :fetched-at nil}))

(defn clear-jwks-cache!
  "Clear the cached JWKS. Useful for testing and when keys need to be re-fetched."
  []
  (reset! jwks-cache {:keys nil :fetched-at nil})
  nil)

(defn invalidate-jwks-cache!
  "Invalidate the cached JWKS. Used when signature verification fails to trigger
   a re-fetch on the next validation attempt (handles key rotation)."
  []
  (swap! jwks-cache assoc :fetched-at nil)
  nil)

(defn- cache-expired?
  "Check if the JWKS cache has expired."
  [{:keys [keys fetched-at]}]
  (or (nil? keys)
      (nil? fetched-at)
      (> (- (t/to-millis-from-epoch (t/instant)) fetched-at) jwks-cache-ttl-ms)))

;;; ------------------------------------------------ JWKS Fetching ------------------------------------------------

(defn- validate-jwks-url!
  "SECURITY: Validate that the JWKS URL is a valid Cloudflare Access endpoint.
   Prevents SSRF attacks by ensuring the URL matches the expected pattern."
  [url]
  (when-not (re-matches #"https://[\w-]+\.cloudflareaccess\.com/cdn-cgi/access/certs" url)
    (throw (ex-info "Invalid JWKS URL format"
                    {:url url
                     :status-code 400})))
  (when-not (u.http/valid-host? :external-only url)
    (throw (ex-info "Invalid JWKS URI: internal addresses not allowed"
                    {:url url
                     :status-code 400})))
  url)

(defn- fetch-jwks
  "Fetch JWKS from Cloudflare. Returns a vector of JWK maps.
   Validates the URL format before fetching (SSRF protection)."
  []
  (let [url (settings/jwks-uri)]
    (when-not url
      (throw (ex-info "Cloudflare Zero Trust team name not configured"
                      {:status-code 500})))
    (validate-jwks-url! url)
    (log/info "Fetching JWKS from Cloudflare" {:url url})
    (try
      (let [response (http/get url {:as           :json
                                    :accept       :json
                                    :throw-exceptions true
                                    :conn-timeout 5000
                                    :socket-timeout 5000})]
        (or (:keys (:body response))
            (throw (ex-info "No keys in JWKS response" {:url url}))))
      (catch Exception e
        (log/error e "Failed to fetch JWKS from Cloudflare" {:url url})
        (throw (ex-info "Failed to fetch JWKS from Cloudflare"
                        {:url url
                         :status-code 503}
                        e))))))

(defn- get-public-keys
  "Get JWKS keys, using cache if valid. Never falls back to stale cache (fail-closed).
   Returns a vector of JWK maps."
  []
  (let [cached @jwks-cache]
    (if (cache-expired? cached)
      (let [new-keys (fetch-jwks)]
        (when (empty? new-keys)
          (throw (ex-info "No keys returned from JWKS endpoint" {:status-code 503})))
        (reset! jwks-cache {:keys new-keys :fetched-at (t/to-millis-from-epoch (t/instant))})
        (log/debug "Cached new JWKS" {:key-count (count new-keys)})
        new-keys)
      (do
        (log/debug "Using cached JWKS" {:key-count (count (:keys cached))})
        (:keys cached)))))

;;; ------------------------------------------------ Algorithm Validation ------------------------------------------------

(defn- decode-jwt-header
  "Decode the JWT header without signature verification.
   Returns the parsed header map."
  [token]
  (try
    (let [[header-b64 _ _] (str/split token #"\." 3)]
      (when-not header-b64
        (throw (ex-info "Invalid JWT format" {:status-code 401})))
      (-> header-b64
          (.getBytes "UTF-8")
          java.util.Base64/getUrlDecoder
          (.decode)
          (String. "UTF-8")
          (json/parse-string true)))
    (catch Exception e
      (throw (ex-info "Failed to decode JWT header"
                      {:status-code 401}
                      e)))))

(defn- validate-algorithm!
  "SECURITY: Validate that the JWT uses an allowed algorithm BEFORE signature verification.
   This prevents algorithm confusion attacks (e.g., alg=none)."
  [token]
  (let [header (decode-jwt-header token)
        alg    (keyword (u/lower-case-en (or (:alg header) "none")))]
    (when-not (contains? allowed-algorithms alg)
      (throw (ex-info (str "JWT algorithm not allowed: " (name alg))
                      {:algorithm alg
                       :allowed   allowed-algorithms
                       :status-code 401})))
    alg))

;;; ------------------------------------------------ Signature Verification ------------------------------------------------

(defn- try-verify-with-key
  "Try to verify the JWT signature with a single JWK.
   Returns the verified claims map or nil if verification fails."
  [token jwk audience issuer]
  (try
    (let [public-key (keys/jwk->public-key jwk)]
      (jwt/unsign token public-key
                  {:alg    :rs256
                   :aud    audience
                   :iss    issuer
                   :leeway clock-skew-leeway-seconds}))
    (catch Exception _
      nil)))

(defn- try-verify-with-keys
  "Try to verify the JWT signature with multiple JWKs (for key rotation support).
   Returns the verified claims map or nil if no key works."
  [token public-keys audience issuer]
  (some (fn [jwk]
          (try-verify-with-key token jwk audience issuer))
        public-keys))

;;; ------------------------------------------------ Claim Validation ------------------------------------------------

(defn- validate-email-claim!
  "Validate that the email claim is present and non-empty."
  [claims]
  (let [email (:email claims)]
    (when-not (string? email)
      (throw (ex-info "Missing email claim in JWT"
                      {:status-code 400})))
    (when (str/blank? email)
      (throw (ex-info "Email claim is empty"
                      {:status-code 400})))
    claims))

(defn- normalize-email
  "Normalize email: lowercase and trim whitespace."
  [email]
  (-> email str/trim u/lower-case-en))

;;; ------------------------------------------------ Public API ------------------------------------------------

(defn decode-and-verify
  "Decode and verify a Cloudflare Access JWT.

   Security checks performed:
   1. Algorithm must be RS256 (prevents alg=none attacks)
   2. Signature verified with JWKS public keys
   3. aud, iss, exp, nbf claims validated (with clock skew leeway)
   4. email claim must be present and non-empty
   5. On signature failure, retries with fresh keys (handles key rotation)

   Returns the verified claims map with normalized email.
   Throws ex-info with :status-code on failure."
  [token]
  (when (str/blank? token)
    (throw (ex-info "JWT token is required" {:status-code 401})))

  ;; Step 1: Validate algorithm BEFORE any signature verification
  (validate-algorithm! token)

  (let [audience (settings/cloudflare-zero-trust-audience-tag)
        issuer   (settings/issuer-uri)]

    (when-not audience
      (throw (ex-info "Cloudflare Zero Trust audience tag not configured"
                      {:status-code 500})))
    (when-not issuer
      (throw (ex-info "Cloudflare Zero Trust team name not configured"
                      {:status-code 500})))

    ;; Step 2: Try verification with cached keys
    (if-let [claims (try-verify-with-keys token (get-public-keys) audience issuer)]
      ;; Step 3: Validate and normalize claims
      (-> claims
          validate-email-claim!
          (update :email normalize-email))

      ;; Step 4: Retry with fresh keys (handles key rotation)
      (do
        (log/info "JWT verification failed with cached keys, refreshing JWKS")
        (invalidate-jwks-cache!)
        (if-let [claims (try-verify-with-keys token (get-public-keys) audience issuer)]
          (-> claims
              validate-email-claim!
              (update :email normalize-email))
          (throw (ex-info "JWT signature verification failed"
                          {:status-code 401})))))))
