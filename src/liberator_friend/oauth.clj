(ns liberator-friend.oauth
  "Helpers for Facebook and Strava registration on PaddleGuru."
  (:require [clj-http.client :as client]
            [cheshire.core :refer [parse-string]]
            [crypto.random :as random]
            [liberator-friend.conf :as conf]
            [liberator-friend.resources :as l :refer [defresource]]
            [ring.util.response]
            [ring.util.codec :as ring-codec]))
 
(defn replace-authz-code
  "Formats the token uri with the authorization code"
  [{:keys [query]} code]
  (assoc-in query [:code] code))
 
;; http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-5.1
(defn extract-access-token
  "Returns the access token from a JSON response body"
  [{body :body}]
  (-> body (parse-string true) :access_token))
 
(defn get-access-token-from-params
  "Alternate function to allow retrieve
   access_token when passed in as form params."
  [{body :body}]
  (-> body ring-codec/form-decode (get "access_token")))
 
(defn format-config-uri
  "Formats URI from domain and path pairs in a map"
  [{{:keys [domain path]} :callback}]
  (str domain path))
 
(defn format-authn-uri
  "Formats the client authentication uri"
  [{{:keys [query url]} :authentication-uri} anti-forgery-token]
  (->> (assoc query :state anti-forgery-token)
       ring-codec/form-encode
       (str url "?")))
 
(defn uri-config
  "Builds an OAuth config suitable for use with the friend oauth
  middleware."
  [{:keys [client-id client-secret auth-url token-url auth-query token-location] :as conf}]
  (let [formatted (format-config-uri conf)]
    {:token-location token-location
     :authentication-uri {:url auth-url
                          :query (merge auth-query
                                        {:client_id client-id
                                         :redirect_uri formatted})}
 
     :access-token-uri {:url token-url
                        :query {:client_id client-id
                                :client_secret client-secret
                                :redirect_uri formatted}}}))
 
(defn callback [provider]
  {:path (format "/oauth/%s/callback" (name provider))
   :domain (conf/get-config :current-server)})
 
(defn get-config [provider]
  (if-let [m (-> (conf/get-config :oauth)
                 (get provider))]
    (-> m
        (assoc :callback (callback provider))
        (uri-config))))
 
;; ## Anti-Forgery Token
 
(defn generate-anti-forgery-token
  "Generates random string for anti-forgery-token."
  []
  (random/url-part 60))


(defn add-anti-forgery [m token]
  (assoc m ::state token))
 
(defn get-anti-forgery [m]
  (-> m ::state))
 
(defn remove-anti-forgery [m]
  (dissoc m ::state))
 
;; ## Handshake Resource
 
(defn redirect-to-provider!
  "Redirects user to OAuth2 provider. Code should be in response."
  [uri-config request]
  (let [anti-forgery-token (generate-anti-forgery-token)
        session-with-af-token (add-anti-forgery (:session request)
                                                anti-forgery-token)]
    (-> uri-config
        (format-authn-uri anti-forgery-token)
        ring.util.response/redirect
        (assoc :session session-with-af-token))))
 
;; Resource that accepts the initial oauth endpoint request. This code
;; sends information
 
(defn oauth-base [provider]
  {:base l/authenticated-base
   :exists?
   (fn [_]
     (if-let [config (get-config (keyword provider))]
       {::config config}))})
 
(defresource handshake [provider]
  :base (oauth-base provider)
  :allowed-methods [:get]
  :available-media-types ["text/html"]
  :handle-ok (fn [context]
               ;; Switch in here. If they already have a token for the
               ;; provider, check if it's still valid. If so, then
               ;; just say you're already authenticated. Otherwise
               ;; kill it and redirect.
               (l/ring-response
                (redirect-to-provider! (::config context)
                                       (:request context)))))
 
 
;; ## Token Requests
 
(defn request-token
  "POSTs request to OAauth2 provider for authorization token."
  [config code]
  (let [token-location (:token-location config)
        access-token-uri (:access-token-uri config)
        query-map (merge {:grant_type "authorization_code"}
                         (replace-authz-code access-token-uri code))
        token-url (assoc access-token-uri :query query-map)
        token-response (client/post (:url token-url)
                                    {:form-params (:query token-url)
                                     :throw-entire-message? true})]
    (if (= :params token-location)
      (get-access-token-from-params token-response)
      (extract-access-token token-response))))
 
;; Resource that manages OAuth token fetching from providers.
 
(defresource token [provider]
  :base (oauth-base provider)
  :allowed-methods [:get]
  :available-media-types ["text/html"]
  :handle-ok (let [config (get-config (keyword provider))]
               (fn [context]
                 (let [req (:request context)
                       {:keys [state code]} (:params req)
                       session-state (-> req :session get-anti-forgery)]
                   (if (and code (= state session-state))
                     (let [access-token (request-token config code)]
                       (str "Token: " access-token))
                     ;; Redirect back home and note that an exception
                     ;; occurred with login. We need to properly
                     ;; handle the failed auth case.
                     "Something wentsdfsdf wrong!")))))
