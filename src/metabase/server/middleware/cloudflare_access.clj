(ns metabase.server.middleware.cloudflare-access
  "Middleware for Cloudflare Zero Trust (Access) authentication.

   When enabled, this middleware intercepts the Cf-Access-Jwt-Assertion header
   from Cloudflare and automatically creates a session for the authenticated user.

   Security behavior:
   - If require-auth=true: ALL requests need valid CF JWT (except allowlisted paths)
   - If require-auth=false: CF auth is optional, other auth methods work
   - Validates JWT algorithm is RS256 only (prevents alg=none attacks)
   - Creates new session on each auth when user has no existing session"
  (:require
   [clojure.string :as str]
   [java-time.api :as t]
   [metabase.auth-identity.core :as auth-identity]
   [metabase.request.core :as request]
   [metabase.request.util :as request.util]
   [metabase.sso.cloudflare-zero-trust.settings :as settings]
   [metabase.util.log :as log]))

(set! *warn-on-reflection* true)

;;; -------------------------------------------------- Constants --------------------------------------------------

(def ^:private cf-jwt-header-name
  "The header name where Cloudflare Access sends the JWT."
  "cf-access-jwt-assertion")

;;; -------------------------------------------------- Helper Functions --------------------------------------------------

(defn- get-cf-jwt-token
  "Extract the Cloudflare JWT from the request headers."
  [request]
  (get-in request [:headers cf-jwt-header-name]))

(defn- path-allowed?
  "Check if the request path is in the allowed paths list."
  [request]
  (settings/path-allowed? (:uri request)))

(defn- reject-unauthorized
  "Return a 401 Unauthorized response."
  [respond]
  (respond {:status  401
            :headers {"Content-Type" "application/json"}
            :body    "{\"error\": \"Cloudflare authentication required\"}"}))

(defn- has-existing-session?
  "Check if the request already has a valid Metabase session."
  [request]
  (some? (:metabase-session-key request)))

(defn- authenticate-and-create-session
  "Authenticate the Cloudflare JWT and create a session.
   Returns the session map on success, nil on failure."
  [cf-jwt-token request]
  (try
    (let [device-info  (request.util/device-info request)
          login-result (auth-identity/login! :provider/cloudflare-zero-trust
                                             {:cf-jwt-token cf-jwt-token
                                              :device-info  device-info})]
      (when (:success? login-result)
        (:session login-result)))
    (catch Exception e
      (log/warn e "Failed to authenticate Cloudflare Zero Trust token")
      nil)))

(defn- set-session-on-response
  "Add session cookies to the response."
  [request response session]
  (request/set-session-cookies
   request
   response
   session
   (t/zoned-date-time (t/zone-id "GMT"))))

;;; -------------------------------------------------- Middleware --------------------------------------------------

(defn wrap-cloudflare-access
  "Middleware that handles Cloudflare Zero Trust authentication.

   Flow:
   1. If disabled, pass through
   2. If path is allowlisted, pass through
   3. If require-auth=true and no JWT, reject with 401
   4. If JWT present:
      a. If user already has session, pass through
      b. Authenticate and create session
      c. Set session cookie in response
   5. If require-auth=false and no JWT, pass through

   Security:
   - JWT validation happens in the provider
   - New session is created for each authentication when user has no existing session
   - Error handling is fail-closed in require-auth mode"
  [handler]
  (fn [request respond raise]
    (if-not (settings/cloudflare-zero-trust-enabled)
      ;; Feature is disabled - pass through
      (handler request respond raise)

      (let [cf-jwt-token  (get-cf-jwt-token request)
            require-auth? (settings/cloudflare-zero-trust-require-auth)
            allowed?      (path-allowed? request)]
        (cond
          ;; Allowlisted paths bypass auth check
          allowed?
          (handler request respond raise)

          ;; Require mode: must have JWT
          (and require-auth? (nil? cf-jwt-token))
          (reject-unauthorized respond)

          ;; Has JWT: validate and create session if needed
          (some? cf-jwt-token)
          (if (has-existing-session? request)
            ;; Already has session, pass through
            ;; Note: We could validate that the session matches the JWT email, but
            ;; for now we trust existing sessions to avoid the overhead of JWT
            ;; validation on every request
            (handler request respond raise)
            ;; No session, create one from Cloudflare auth
            (if-let [session (authenticate-and-create-session cf-jwt-token request)]
              ;; Add session to request and set cookie in response
              (let [request-with-session (assoc request :metabase-session-key (:key session))]
                (handler request-with-session
                         (fn [response]
                           (respond (set-session-on-response request response session)))
                         raise))
              ;; Login failed
              (if require-auth?
                (reject-unauthorized respond)
                ;; In optional mode, continue without session (other auth may work)
                (handler request respond raise))))

          ;; Optional mode, no JWT: pass through
          :else
          (handler request respond raise))))))
