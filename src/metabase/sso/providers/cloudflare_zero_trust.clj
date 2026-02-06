(ns metabase.sso.providers.cloudflare-zero-trust
  "Cloudflare Zero Trust (Access) authentication provider.

   This provider handles authentication for users accessing Metabase through
   Cloudflare Zero Trust. When enabled, the Cf-Access-Jwt-Assertion header
   is validated and users are automatically logged in.

   Features:
   - JWT signature validation using Cloudflare's JWKS
   - JIT (Just-In-Time) user provisioning
   - Deactivated user handling
   - Audit logging

   See the settings namespace for configuration options."
  (:require
   [metabase.auth-identity.core :as auth-identity]
   [metabase.events.core :as events]
   [metabase.sso.cloudflare-zero-trust.jwt :as cf-jwt]
   [metabase.sso.cloudflare-zero-trust.settings :as settings]
   [metabase.util.i18n :refer [tru]]
   [metabase.util.log :as log]
   [methodical.core :as methodical]
   [toucan2.core :as t2]))

(set! *warn-on-reflection* true)

;;; -------------------------------------------------- Provider Hierarchy --------------------------------------------------

;; Register Cloudflare Zero Trust provider
(derive :provider/cloudflare-zero-trust :metabase.auth-identity.provider/provider)
(derive :provider/cloudflare-zero-trust :metabase.auth-identity.provider/create-user-if-not-exists)

;;; -------------------------------------------------- Authentication --------------------------------------------------

(methodical/defmethod auth-identity/authenticate :provider/cloudflare-zero-trust
  "Authenticate a Cloudflare Zero Trust JWT.

   Validates the JWT from the Cf-Access-Jwt-Assertion header and extracts
   user information from the claims.

   Args:
     request - Map containing :cf-jwt-token (the JWT from header)

   Returns:
     On success: {:success? true :user-data {...} :provider-id email}
     On failure: {:success? false :error keyword :message string}"
  [_provider {:keys [cf-jwt-token] :as _request}]
  (cond
    ;; Check if feature is enabled
    (not (settings/cloudflare-zero-trust-enabled))
    {:success? false
     :error    :not-enabled
     :message  (tru "Cloudflare Zero Trust authentication is not enabled")}

    ;; Token required
    (not cf-jwt-token)
    {:success? false
     :error    :invalid-request
     :message  (tru "Cloudflare JWT token is required")}

    :else
    (try
      (let [jwt-data (cf-jwt/decode-and-verify cf-jwt-token)
            email    (:email jwt-data)]
        (log/info "Successfully authenticated Cloudflare Zero Trust token" {:email email})
        ;; Publish audit event
        (events/publish-event! :event/cloudflare-auth-success {:email email})
        {:success?    true
         :user-data   {:email      email
                       :sso_source :cloudflare-zero-trust}
         :provider-id email
         :jwt-data    jwt-data})
      (catch clojure.lang.ExceptionInfo e
        (let [data (ex-data e)]
          (log/warn e "Cloudflare Zero Trust authentication failed"
                    {:error (:error data)})
          ;; Publish audit event (without email for security)
          (events/publish-event! :event/cloudflare-auth-failure
                                 {:reason (or (:error data) :unknown)})
          {:success? false
           :error    (or (:error data) :authentication-failed)
           :message  (ex-message e)}))
      (catch Exception e
        (log/error e "Unexpected error during Cloudflare Zero Trust authentication")
        (events/publish-event! :event/cloudflare-auth-failure {:reason :server-error})
        {:success? false
         :error    :server-error
         :message  (tru "An unexpected error occurred during authentication")}))))

;;; -------------------------------------------------- Login --------------------------------------------------

(methodical/defmethod auth-identity/login! :provider/cloudflare-zero-trust
  "Handle Cloudflare Zero Trust login.

   Checks:
   1. If user exists but is deactivated, rejects login
   2. If user doesn't exist and provisioning is disabled, rejects login
   3. Otherwise, proceeds with user creation/update via parent method"
  [provider {:keys [user user-data] :as request}]
  (cond
    ;; Authentication needs redirect (shouldn't happen for Cloudflare but handle it)
    (= :redirect (:success? request))
    request

    ;; Authentication failed
    (not (:success? request))
    request

    ;; User exists but is deactivated - reject login
    (and user (not (:is_active user)))
    (do
      (log/warn "Cloudflare Zero Trust login rejected: user account is deactivated"
                {:email (:email user-data)})
      (events/publish-event! :event/cloudflare-auth-failure
                             {:reason :account-deactivated
                              :user-id (:id user)})
      {:success? false
       :error    :account-disabled
       :message  (tru "Your account is disabled. Please contact your administrator.")})

    ;; User doesn't exist and provisioning is disabled
    (and (nil? user)
         (not (settings/cloudflare-zero-trust-user-provisioning-enabled)))
    (do
      (log/warn "Cloudflare Zero Trust login rejected: user provisioning disabled"
                {:email (:email user-data)})
      (events/publish-event! :event/cloudflare-auth-failure
                             {:reason :provisioning-disabled})
      {:success? false
       :error    :account-creation-not-allowed
       :message  (tru "You''ll need an administrator to create a Metabase account before you can log in.")})

    ;; Proceed with login (user will be created or updated by parent method)
    :else
    (let [;; If user doesn't exist, log that we're provisioning
          _ (when (nil? user)
              (log/info "Provisioning new user from Cloudflare Zero Trust"
                        {:email (:email user-data)})
              (events/publish-event! :event/cloudflare-user-provisioned
                                     {:email (:email user-data)}))]
      ;; Call parent method with is_active set to true (reactivate if needed)
      (next-method provider (-> request
                                (assoc-in [:user-data :is_active] true)
                                (assoc :user-provisioning-enabled?
                                       (settings/cloudflare-zero-trust-user-provisioning-enabled)))))))
