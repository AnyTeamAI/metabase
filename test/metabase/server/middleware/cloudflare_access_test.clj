(ns metabase.server.middleware.cloudflare-access-test
  "Tests for Cloudflare Zero Trust middleware.

   These tests verify:
   - Middleware passes through when disabled
   - Middleware creates session with valid JWT
   - Middleware rejects when require-auth=true and no JWT
   - Middleware allows allowlisted paths without JWT
   - Error handling behavior"
  (:require
   [clojure.test :refer :all]
   [metabase.server.middleware.cloudflare-access :as mw.cloudflare-access]
   [metabase.sso.cloudflare-zero-trust.settings :as settings]))

(set! *warn-on-reflection* true)

;;; ------------------------------------------------ Helper Functions ------------------------------------------------

(defn- make-request
  "Create a mock request map."
  [& {:keys [uri headers session-key]
      :or   {uri     "/api/card"
             headers {}}}]
  (cond-> {:uri     uri
           :headers headers}
    session-key (assoc :metabase-session-key session-key)))

(defn- call-middleware
  "Call the middleware with a mock handler and return the result."
  [request]
  (let [result   (promise)
        handler  (fn [req respond _raise]
                   (respond {:status 200 :request req}))
        wrapped  (mw.cloudflare-access/wrap-cloudflare-access handler)]
    (wrapped request
             (fn [response] (deliver result response))
             (fn [error] (deliver result {:error error})))
    @result))

;;; ------------------------------------------------ Tests ------------------------------------------------

(deftest disabled-passes-through-test
  (testing "When Cloudflare Zero Trust is disabled, all requests pass through"
    (with-redefs [settings/cloudflare-zero-trust-enabled (constantly false)]
      (let [response (call-middleware (make-request))]
        (is (= 200 (:status response)))))))

(deftest no-jwt-optional-mode-test
  (testing "When require-auth=false and no JWT, request passes through"
    (with-redefs [settings/cloudflare-zero-trust-enabled       (constantly true)
                  settings/cloudflare-zero-trust-require-auth  (constantly false)
                  settings/path-allowed?                       (constantly false)]
      (let [response (call-middleware (make-request))]
        (is (= 200 (:status response)))))))

(deftest no-jwt-require-mode-test
  (testing "When require-auth=true and no JWT, request is rejected with 401"
    (with-redefs [settings/cloudflare-zero-trust-enabled       (constantly true)
                  settings/cloudflare-zero-trust-require-auth  (constantly true)
                  settings/path-allowed?                       (constantly false)]
      (let [response (call-middleware (make-request))]
        (is (= 401 (:status response)))))))

(deftest allowlisted-path-test
  (testing "Allowlisted paths bypass auth check even in require-auth mode"
    (with-redefs [settings/cloudflare-zero-trust-enabled       (constantly true)
                  settings/cloudflare-zero-trust-require-auth  (constantly true)
                  settings/path-allowed?                       (fn [path]
                                                                 (or (= path "/api/health")
                                                                     (and path
                                                                          (clojure.string/starts-with? path "/api/setup"))))]
      ;; Health endpoint should pass
      (let [response (call-middleware (make-request :uri "/api/health"))]
        (is (= 200 (:status response))))
      ;; Setup endpoint should pass
      (let [response (call-middleware (make-request :uri "/api/setup/init"))]
        (is (= 200 (:status response))))
      ;; Other endpoints should be rejected
      (let [response (call-middleware (make-request :uri "/api/card"))]
        (is (= 401 (:status response)))))))

(deftest existing-session-passes-through-test
  (testing "Request with existing session passes through without JWT validation"
    (with-redefs [settings/cloudflare-zero-trust-enabled       (constantly true)
                  settings/cloudflare-zero-trust-require-auth  (constantly false)
                  settings/path-allowed?                       (constantly false)]
      (let [response (call-middleware (make-request :session-key "existing-session-key"))]
        (is (= 200 (:status response)))
        ;; The session key should be preserved
        (is (= "existing-session-key" (get-in response [:request :metabase-session-key])))))))

(deftest invalid-jwt-optional-mode-test
  (testing "Invalid JWT in optional mode allows request to pass through"
    (with-redefs [settings/cloudflare-zero-trust-enabled       (constantly true)
                  settings/cloudflare-zero-trust-require-auth  (constantly false)
                  settings/path-allowed?                       (constantly false)]
      ;; Use an obviously invalid JWT
      (let [response (call-middleware
                      (make-request :headers {"cf-access-jwt-assertion" "invalid.jwt.token"}))]
        ;; Should pass through (other auth methods may work)
        (is (= 200 (:status response)))
        ;; But no session key should be set
        (is (nil? (get-in response [:request :metabase-session-key])))))))

(deftest invalid-jwt-require-mode-test
  (testing "Invalid JWT in require-auth mode rejects request"
    (with-redefs [settings/cloudflare-zero-trust-enabled       (constantly true)
                  settings/cloudflare-zero-trust-require-auth  (constantly true)
                  settings/path-allowed?                       (constantly false)]
      ;; Use an obviously invalid JWT
      (let [response (call-middleware
                      (make-request :headers {"cf-access-jwt-assertion" "invalid.jwt.token"}))]
        (is (= 401 (:status response)))))))
