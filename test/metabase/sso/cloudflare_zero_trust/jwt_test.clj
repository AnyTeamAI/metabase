(ns metabase.sso.cloudflare-zero-trust.jwt-test
  "Tests for Cloudflare Zero Trust JWT validation.

   These tests verify:
   - RS256 signature validation
   - Algorithm confusion attack prevention (alg=none, alg=HS256)
   - Claim validation (aud, iss, exp, nbf, email)
   - JWKS caching and refresh behavior
   - Email normalization"
  (:require
   [buddy.core.keys :as buddy.keys]
   [buddy.sign.jwt :as jwt]
   [cheshire.core :as json]
   [clj-http.client :as http]
   [clojure.test :refer :all]
   [java-time.api :as t]
   [metabase.sso.cloudflare-zero-trust.jwt :as cf-jwt]
   [metabase.sso.cloudflare-zero-trust.settings :as settings]
   [metabase.test.util :as tu]))

(set! *warn-on-reflection* true)

;;; ------------------------------------------------ Test Keys ------------------------------------------------

(def ^:private test-rsa-private-key-pem
  "Test RSA private key PEM string for signing JWTs"
  "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCzaoNf/pO3shyj
M5ynvNemVGb2S/KETJi7HCrlLBEkk4qs7gelUUfDXoX4bT2COXCejtcsEwat/4cq
rMecbrnc7F6OEqG2hobVDVHvMoyd51fBjRP9shlu0lj0LvBAkn0EKJj09rc85e7d
kE666tQboZb9f2MzQIZjnWvk1c2L+ruRXvCteX86l7JUychszrDjfRl/FO3cCrya
2G+9HiWr7i3eS8FwC117Xcob8G5L9Dys0wlNvz0WLH81hYDvdklXDB5qhjC+i/he
4Mk0OAEVJAuZLO1tKWpKMQnNZmDAvAvuZCxl6g7jkOg6ilChau50ssooceG4h7An
wdqobhTnAgMBAAECggEAEVepikUNL0jyrAh9oIMdpJDCVmq3RE2JHTEBqR741ecY
alMkfw4xGHPnEZaG8bMEAqI+WfQe2wEjph7cY+/EsdOmkidqj+jyAzRjPUf5aqal
h2p6dQqFmyjkUKTG3rRU4ZWGWiC3oUB9NdfQnGW9ifbf0EduJdKbYD6juBNokm/z
PqnLyz6lXt0fYhKiLrbZaKxtADQr0ueaJ9AHIGVjewnbi7hIPz4fwpXkP4hjos+n
PKnR33TNrn7zyVTRui68wM+oM6gMtI0yP6rUhyMBPosS7llT/fWNZJbAUxA+ujrx
ZJrif9FrForHbmQ3OVJbSLBfddx00EV9rMhOIXqp4QKBgQD799+US2yeCR6JoCgR
4e114oUNtQrhJJECdlbsMsZRO0DbaH4C8mlP0x5E8JORyhRJuf8xcMPvyJP7mYPg
ok1mZcG7JRgwWfxAeeRblchFyhTnwENuu/uO/367MZzhb+TLtdy4IJ/wNMhRWIt2
WstooHco9lJEeUses4S5iDiKxwKBgQC2SXKLoQ3iols1+sdTaZz2ukhPRyO3cgZN
garL7xThNo7zENQ+tWmt4VmjtAyM2SNw5EAJaPW7qxGfZPECCVgMnkhEAcp5rwzr
0m8Z8sDxe6lKaONB+4Hs2gKPn+gAwvFHEZFl3obGSMNuZ1/ZWEsNQLfLbge3nqmp
QIoylecE4QKBgHQCViBS8bl5fWPkJ07EdK5YEuaSumWajmFR1wd9AS4ZV+0tGQeG
UNJ942veUDNJlTm0tzguMShPc0LeFYfxci15IE9n7tEkPS36cRdxyPnI5wMk1GdB
ibr3C4RofVCWUgMwwmTMMJdJ1gkN+XgOqaSMbRChCJOaPOnvwWYiv9W1AoGAbHCX
Ft9xjjA9iIguSb3bZZ994sOUSM4pV7RascUBq9S0B38sdD2hp5IWrF8w1B1ciw0N
10s8XC8xZZw8D5UVbzQ+E07pb6gmTKe79jjGdSG2nRB2mUsQiKFMwrpC3ykZNckK
sQpHLPAearBOgdKXm0Oz0u4a4y4dChXd4KfybaECgYBGG6YQL3JYqPnJFFoxlElJ
6qZ8YxN8UqWG/meMxA25wDyFaWH4mpQzY8s1OP9Br0ZD9snNktKb6RfoJIr6IMOL
FoQyvsf7lfwsO1MqmDEWuTjHfLyAFqhdJOQBdhpaKVaRQI45oyQIH5krTvfrBA2f
C4LNFx/mlSrwtFu9TAtd2A==
-----END PRIVATE KEY-----")

(def ^:private test-rsa-public-key-pem
  "Test RSA public key PEM string corresponding to test-rsa-private-key-pem"
  "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs2qDX/6Tt7IcozOcp7zX
plRm9kvyhEyYuxwq5SwRJJOKrO4HpVFHw16F+G09gjlwno7XLBMGrf+HKqzHnG65
3OxejhKhtoaG1Q1R7zKMnedXwY0T/bIZbtJY9C7wQJJ9BCiY9Pa3POXu3ZBOuurU
G6GW/X9jM0CGY51r5NXNi/q7kV7wrXl/OpeyVMnIbM6w430ZfxTt3Aq8mthvvR4l
q+4t3kvBcAtde13KG/BuS/Q8rNMJTb89Fix/NYWA73ZJVwweaoYwvov4XuDJNDgB
FSQLmSztbSlqSjEJzWZgwLwL7mQsZeoO45DoOopQoWrudLLKKHHhuIewJ8HaqG4U
5wIDAQAB
-----END PUBLIC KEY-----")

(def ^:private test-rsa-private-key
  (delay (buddy.keys/str->private-key test-rsa-private-key-pem)))

(def ^:private test-rsa-public-key
  (delay (buddy.keys/str->public-key test-rsa-public-key-pem)))

(def ^:private test-jwk
  (delay (merge {:kid "test-key-id" :use "sig" :alg "RS256"}
                (buddy.keys/public-key->jwk @test-rsa-public-key))))

(def ^:private test-team-name "test-team")
(def ^:private test-audience "test-audience-tag")
(def ^:private test-issuer (str "https://" test-team-name ".cloudflareaccess.com"))

;;; ------------------------------------------------ Helper Functions ------------------------------------------------

(defn- create-test-jwt
  "Create a test JWT with the given claims. Uses RS256 by default."
  [claims & {:keys [alg kid] :or {alg :rs256 kid "test-key-id"}}]
  (jwt/sign claims @test-rsa-private-key {:alg alg :header {:kid kid}}))

(defn- create-valid-claims
  "Create valid JWT claims with the given email."
  [email]
  {:email email
   :aud   test-audience
   :iss   test-issuer
   :exp   (+ (quot (t/to-millis-from-epoch (t/instant)) 1000) 3600) ; 1 hour from now
   :iat   (quot (t/to-millis-from-epoch (t/instant)) 1000)
   :sub   "test-user-id"})

(defn- mock-jwks-response
  "Create a mock HTTP response with JWKS."
  [& {:keys [keys] :or {keys [@test-jwk]}}]
  {:status 200
   :body   {:keys keys}})

(defmacro with-cf-settings
  "Execute body with Cloudflare Zero Trust settings configured."
  [& body]
  `(tu/with-temporary-setting-values
     [:cloudflare-zero-trust-team-name ~test-team-name
      :cloudflare-zero-trust-audience-tag ~test-audience
      :cloudflare-zero-trust-enabled true]
     (cf-jwt/clear-jwks-cache!)
     ~@body))

;;; ------------------------------------------------ Tests ------------------------------------------------

(deftest decode-and-verify-valid-token-test
  (testing "Valid RS256 token with correct claims"
    (with-cf-settings
      (with-redefs [http/get (constantly (mock-jwks-response))]
        (let [token  (create-test-jwt (create-valid-claims "user@example.com"))
              result (cf-jwt/decode-and-verify token)]
          (is (map? result))
          (is (= "user@example.com" (:email result)))
          (is (= test-audience (:aud result)))
          (is (= test-issuer (:iss result))))))))

(deftest decode-and-verify-email-normalization-test
  (testing "Email is normalized to lowercase and trimmed"
    (with-cf-settings
      (with-redefs [http/get (constantly (mock-jwks-response))]
        (let [token  (create-test-jwt (create-valid-claims "  User@EXAMPLE.Com  "))
              result (cf-jwt/decode-and-verify token)]
          (is (= "user@example.com" (:email result))))))))

;;; ------------------------------------------------ Security Tests ------------------------------------------------

(deftest algorithm-none-attack-test
  (testing "CRITICAL SECURITY: Token with alg=none is rejected"
    (with-cf-settings
      (with-redefs [http/get (constantly (mock-jwks-response))]
        ;; Create a token with alg=none (no signature)
        (let [header  (json/generate-string {:alg "none" :typ "JWT"})
              payload (json/generate-string (create-valid-claims "attacker@evil.com"))
              header-b64  (.encodeToString (java.util.Base64/getUrlEncoder) (.getBytes header "UTF-8"))
              payload-b64 (.encodeToString (java.util.Base64/getUrlEncoder) (.getBytes payload "UTF-8"))
              token   (str header-b64 "." payload-b64 ".")]
          (is (thrown-with-msg? clojure.lang.ExceptionInfo #"algorithm not allowed"
                                (cf-jwt/decode-and-verify token))))))))

(deftest algorithm-hs256-attack-test
  (testing "CRITICAL SECURITY: Token with alg=HS256 is rejected"
    (with-cf-settings
      (with-redefs [http/get (constantly (mock-jwks-response))]
        ;; Create a token claiming to use HS256 (symmetric key)
        (let [header  (json/generate-string {:alg "HS256" :typ "JWT"})
              payload (json/generate-string (create-valid-claims "attacker@evil.com"))
              header-b64  (.encodeToString (java.util.Base64/getUrlEncoder) (.getBytes header "UTF-8"))
              payload-b64 (.encodeToString (java.util.Base64/getUrlEncoder) (.getBytes payload "UTF-8"))
              ;; Sign with the public key as if it were an HMAC secret
              fake-sig "fake-signature-base64"
              token    (str header-b64 "." payload-b64 "." fake-sig)]
          (is (thrown-with-msg? clojure.lang.ExceptionInfo #"algorithm not allowed"
                                (cf-jwt/decode-and-verify token))))))))

(deftest invalid-signature-test
  (testing "Token with tampered payload is rejected"
    (with-cf-settings
      (with-redefs [http/get (constantly (mock-jwks-response))]
        (let [valid-token   (create-test-jwt (create-valid-claims "user@example.com"))
              [header _ sig] (clojure.string/split valid-token #"\.")
              ;; Create different payload
              tampered-payload (json/generate-string (create-valid-claims "attacker@evil.com"))
              tampered-b64     (.encodeToString (java.util.Base64/getUrlEncoder)
                                                (.getBytes tampered-payload "UTF-8"))
              tampered-token   (str header "." tampered-b64 "." sig)]
          (is (thrown-with-msg? clojure.lang.ExceptionInfo #"signature verification failed"
                                (cf-jwt/decode-and-verify tampered-token))))))))

(deftest wrong-audience-test
  (testing "Token with wrong audience is rejected"
    (with-cf-settings
      (with-redefs [http/get (constantly (mock-jwks-response))]
        (let [claims (assoc (create-valid-claims "user@example.com")
                            :aud "wrong-audience")
              token  (create-test-jwt claims)]
          (is (thrown-with-msg? clojure.lang.ExceptionInfo #"signature verification failed"
                                (cf-jwt/decode-and-verify token))))))))

(deftest wrong-issuer-test
  (testing "Token with wrong issuer is rejected"
    (with-cf-settings
      (with-redefs [http/get (constantly (mock-jwks-response))]
        (let [claims (assoc (create-valid-claims "user@example.com")
                            :iss "https://wrong-team.cloudflareaccess.com")
              token  (create-test-jwt claims)]
          (is (thrown-with-msg? clojure.lang.ExceptionInfo #"signature verification failed"
                                (cf-jwt/decode-and-verify token))))))))

(deftest expired-token-test
  (testing "Token with expired exp claim is rejected"
    (with-cf-settings
      (with-redefs [http/get (constantly (mock-jwks-response))]
        (let [claims (assoc (create-valid-claims "user@example.com")
                            :exp (- (quot (t/to-millis-from-epoch (t/instant)) 1000) 3600)) ; 1 hour ago
              token  (create-test-jwt claims)]
          (is (thrown-with-msg? clojure.lang.ExceptionInfo #"signature verification failed"
                                (cf-jwt/decode-and-verify token))))))))

(deftest future-nbf-test
  (testing "Token with future nbf claim is rejected"
    (with-cf-settings
      (with-redefs [http/get (constantly (mock-jwks-response))]
        (let [claims (assoc (create-valid-claims "user@example.com")
                            :nbf (+ (quot (t/to-millis-from-epoch (t/instant)) 1000) 3600)) ; 1 hour from now
              token  (create-test-jwt claims)]
          (is (thrown-with-msg? clojure.lang.ExceptionInfo #"signature verification failed"
                                (cf-jwt/decode-and-verify token))))))))

(deftest missing-email-claim-test
  (testing "Token without email claim is rejected"
    (with-cf-settings
      (with-redefs [http/get (constantly (mock-jwks-response))]
        (let [claims (dissoc (create-valid-claims "user@example.com") :email)
              token  (create-test-jwt claims)]
          (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Missing email claim"
                                (cf-jwt/decode-and-verify token))))))))

(deftest empty-email-claim-test
  (testing "Token with empty email claim is rejected"
    (with-cf-settings
      (with-redefs [http/get (constantly (mock-jwks-response))]
        (let [claims (assoc (create-valid-claims "") :email "")
              token  (create-test-jwt claims)]
          (is (thrown-with-msg? clojure.lang.ExceptionInfo #"Email claim is empty"
                                (cf-jwt/decode-and-verify token))))))))

(deftest blank-token-test
  (testing "Empty or blank token is rejected"
    (with-cf-settings
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"token is required"
                            (cf-jwt/decode-and-verify "")))
      (is (thrown-with-msg? clojure.lang.ExceptionInfo #"token is required"
                            (cf-jwt/decode-and-verify nil))))))

;;; ------------------------------------------------ JWKS Cache Tests ------------------------------------------------

(deftest jwks-cache-test
  (testing "JWKS is cached and reused"
    (with-cf-settings
      (let [fetch-count (atom 0)]
        (with-redefs [http/get (fn [& _]
                                 (swap! fetch-count inc)
                                 (mock-jwks-response))]
          ;; First verification - should fetch JWKS
          (let [token1 (create-test-jwt (create-valid-claims "user1@example.com"))]
            (cf-jwt/decode-and-verify token1))
          ;; Second verification - should use cached JWKS
          (let [token2 (create-test-jwt (create-valid-claims "user2@example.com"))]
            (cf-jwt/decode-and-verify token2))
          ;; Should have only fetched once
          (is (= 1 @fetch-count)))))))

(deftest jwks-cache-refresh-on-failure-test
  (testing "JWKS cache is refreshed when signature verification fails"
    (with-cf-settings
      (let [fetch-count (atom 0)
            ;; First return old key, then return correct key
            old-key      {:kid "old-key-id" :use "sig" :alg "RS256"
                          :n "old" :e "AQAB" :kty "RSA"} ; Invalid key
            jwks-responses (atom [(mock-jwks-response :keys [old-key])
                                  (mock-jwks-response)])] ; Valid key on second call
        (with-redefs [http/get (fn [& _]
                                 (swap! fetch-count inc)
                                 (let [resp (first @jwks-responses)]
                                   (swap! jwks-responses rest)
                                   resp))]
          ;; This should fail with old key, refresh cache, and succeed with new key
          (let [token (create-test-jwt (create-valid-claims "user@example.com"))]
            (cf-jwt/decode-and-verify token))
          ;; Should have fetched twice (initial + retry)
          (is (= 2 @fetch-count)))))))
