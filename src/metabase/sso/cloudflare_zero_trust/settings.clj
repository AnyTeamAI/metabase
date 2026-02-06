(ns metabase.sso.cloudflare-zero-trust.settings
  "Settings for Cloudflare Zero Trust (Access) authentication.

   When enabled, Metabase trusts Cloudflare Zero Trust to authenticate users.
   Cloudflare sends a signed JWT in the `Cf-Access-Jwt-Assertion` header which
   is validated using Cloudflare's JWKS endpoint."
  (:require
   [clojure.string :as str]
   [metabase.settings.core :as setting :refer [defsetting]]
   [metabase.util.i18n :refer [deferred-tru tru]]))

(set! *warn-on-reflection* true)

;;; ------------------------------------------------ Core Settings ------------------------------------------------

(defsetting cloudflare-zero-trust-team-name
  (deferred-tru "Your Cloudflare Zero Trust team/organization name. This is used to construct the JWKS endpoint URL: https://<team-name>.cloudflareaccess.com/cdn-cgi/access/certs")
  :encryption :when-encryption-key-set
  :audit      :getter
  :setter     (fn [new-value]
                (when new-value
                  (let [trimmed (str/trim new-value)]
                    (when-not (re-matches #"^[\w-]+$" trimmed)
                      (throw (ex-info (tru "Invalid team name: must contain only alphanumeric characters and hyphens")
                                      {:status-code 400})))
                    (setting/set-value-of-type! :string :cloudflare-zero-trust-team-name trimmed)))))

(defsetting cloudflare-zero-trust-audience-tag
  (deferred-tru "Application Audience (AUD) Tag from Cloudflare Zero Trust. This is used to validate the 'aud' claim in the JWT to ensure the token was issued for your application. Find this in your Cloudflare Zero Trust dashboard under Access > Applications.")
  :encryption :when-encryption-key-set
  :audit      :getter
  :setter     (fn [new-value]
                (when (and new-value (str/blank? (str/trim new-value)))
                  (throw (ex-info (tru "Audience tag cannot be empty")
                                  {:status-code 400})))
                (setting/set-value-of-type! :string :cloudflare-zero-trust-audience-tag
                                            (when new-value (str/trim new-value)))))

(defsetting cloudflare-zero-trust-configured?
  (deferred-tru "Are the mandatory Cloudflare Zero Trust settings (team name and audience tag) configured?")
  :type       :boolean
  :visibility :public
  :setter     :none
  :getter     (fn [] (boolean (and (cloudflare-zero-trust-team-name)
                                   (cloudflare-zero-trust-audience-tag))))
  :doc        false)

(defsetting cloudflare-zero-trust-enabled
  (deferred-tru "Is Cloudflare Zero Trust authentication enabled? When enabled, users authenticated via Cloudflare Zero Trust can access Metabase without an additional login step.")
  :type       :boolean
  :visibility :public
  :default    false
  :audit      :getter
  :getter     (fn []
                ;; Only return true if configured AND explicitly enabled
                (if (cloudflare-zero-trust-configured?)
                  (setting/get-value-of-type :boolean :cloudflare-zero-trust-enabled)
                  false))
  :setter     (fn [new-value]
                (when (and new-value (not (cloudflare-zero-trust-configured?)))
                  (throw (ex-info (tru "Cloudflare Zero Trust is not configured. Please set the Team Name and Audience Tag first.")
                                  {:status-code 400})))
                (setting/set-value-of-type! :boolean :cloudflare-zero-trust-enabled new-value)))

;;; ------------------------------------------------ User Provisioning ------------------------------------------------

(defsetting cloudflare-zero-trust-user-provisioning-enabled
  (deferred-tru "When a user logs in via Cloudflare Zero Trust, automatically create a Metabase account for them if they don''t have one. New users will have minimal permissions until an admin assigns them to appropriate groups.")
  :type    :boolean
  :default true
  :audit   :getter)

;;; ------------------------------------------------ Security Settings ------------------------------------------------

(defsetting cloudflare-zero-trust-require-auth
  (deferred-tru "SECURITY: When enabled, ALL requests to Metabase MUST include a valid Cloudflare Zero Trust JWT. Requests without a valid JWT will be rejected with a 401 error. Only enable this if Metabase is exclusively accessed through Cloudflare Zero Trust. Health check and setup endpoints are exempt.")
  :type       :boolean
  :visibility :admin
  :default    false
  :audit      :getter)

(def ^:private default-allowed-paths
  "Default paths that bypass Cloudflare authentication when require-auth is enabled."
  "/api/health,/api/setup,/api/util/logs")

(defsetting cloudflare-zero-trust-allowed-paths
  (deferred-tru "Comma-separated list of URL path prefixes that bypass Cloudflare Zero Trust authentication when ''Require Auth'' is enabled. Default: /api/health,/api/setup,/api/util/logs")
  :type       :string
  :visibility :admin
  :default    default-allowed-paths
  :encryption :no
  :audit      :getter
  :getter     (fn []
                (let [value (or (setting/get-value-of-type :string :cloudflare-zero-trust-allowed-paths)
                                default-allowed-paths)]
                  (->> (str/split value #",")
                       (map str/trim)
                       (remove str/blank?)
                       (into [])))))

;;; ------------------------------------------------ Helper Functions ------------------------------------------------

(defn jwks-uri
  "Returns the JWKS URI for the configured Cloudflare Zero Trust team."
  []
  (when-let [team-name (cloudflare-zero-trust-team-name)]
    (str "https://" team-name ".cloudflareaccess.com/cdn-cgi/access/certs")))

(defn issuer-uri
  "Returns the expected issuer URI for the configured Cloudflare Zero Trust team."
  []
  (when-let [team-name (cloudflare-zero-trust-team-name)]
    (str "https://" team-name ".cloudflareaccess.com")))

(defn path-allowed?
  "Check if a given path is in the allowed paths list (bypasses auth when require-auth is enabled)."
  [path]
  (when path
    (let [allowed (cloudflare-zero-trust-allowed-paths)]
      (some #(str/starts-with? path %) allowed))))
