(ns liberator-friend.conf
  (:require [schema.core :as s]))
 
(def OAuthConfig
  {:token-location (s/enum :params :body)
   :auth-url s/String
   :token-url s/String
   :client-id s/String
   :client-secret s/String
   (s/optional-key :auth-query) {s/Keyword s/String}})
 
(s/defn strava-config :- OAuthConfig
  "Strava returns its token in the body, via JSON. Any special
  permissions we need later need to be added in the :auth_query (these
  get sent along with the basic initial parameters for the oauth
  handshake.)"
  []
  {:token-location :body
   :client-id "!!!!!!!!!!!!"
   :auth-query {:response_type "code"}
   :auth-url "https://www.strava.com/oauth/authorize"
   :token-url "https://www.strava.com/oauth/token"
   :client-secret "!!!!!!!!"})
 
(s/defn facebook-config :- OAuthConfig
  "Token location specifies that the token is going to come back in
  the params, not the body. We also make sure to ask for email
  privileges, to beef up a particular user's profile."
  [mode]
  (merge {:token-location :params
          :auth-url "https://www.facebook.com/dialog/oauth"
          :token-url "https://graph.facebook.com/oauth/access_token"
          :auth-query {:scope "email"
                       :response_type "code"}}
         (if (= :dev mode)
           {:client-id "!!!"
            :client-secret "!!!"}
           {:client-id "!!!"
            :client-secret "!!!"})))

(defn mode [] :dev)

(defn get-config
  "Returns config items as requested."
  ([]
     {:oauth {:facebook (facebook-config (mode))
              :strava (strava-config)}})
  ([key]
     (get-config key nil))
  ([key fallback]
     ((get-config) key fallback)))
