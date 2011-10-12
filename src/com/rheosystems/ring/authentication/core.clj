(ns ^{:doc "Authentication middleware for ring. See the accompanying specification."}
  com.rheosystems.ring.authentication.core
  
  (:require [com.rheosystems.ring.authentication.user-repository :as udb]))

;;; *user* is the interface to the rest of the application - always
;;; bound to a valid user by the authentication middleware (this
;;; module). That user may be anonymous or an authenticated system
;;; user.
(def ^:dynamic *user*)

(defn from-req
  "Return the parameter from the request.

   The purpose is to decouple the rest of the module from the
   structure of the request.

   See https://github.com/mmcgrana/ring/blob/master/SPEC for a
   specification of the ring request map"

  [req key]
  (let [request (fn [key] (get req key))
        session (fn [key] (get-in req [:session key]))
        form-param (fn [key] (get-in req [:form-params key]))
        query-param (fn [key] (get-in req [:query-params key]))]
    (condp = key
            ; Module Input        ; Ring Transport
            :uri                  (request :uri)
            :method               (request :request-method)
            :time-of-last-request (session :time-of-last-request)
            :logged-in-user       (session :logged-in-user)
            :no-expire            (session :no-expire)
            :username             (form-param :username)
            :password             (form-param :password)
            :remember-me          (form-param :remember-me)
            :uid                  (query-param :uid)
            :key                  (query-param :key))))

(defn update-session
  "Updates the session in the response with the supplied attribute map.

   If the value of an attribute is nil, it is not set.

   Decouples the rest of the module from knowledge of response and
   session structure."
  [resp attrs]
  (let [attrs (apply hash-map (flatten (filter (fn [[k v]] (not (nil? v))) attrs)))
        session (:session resp)]
    (assoc resp :session (merge session attrs))))

;;; Predicates
;;; ----------

(defn is-user?
  "Returns true if the supplied user is a type of user."
  [u repo] (udb/user? repo u))

;;; Authentication Protocols

(defn login?
  "Returns true if the supplied request is a valid login request."
  [{:keys [req config] :as T}]
  (and
   (= (from-req req :uri) (:login-url config))
   (= (from-req req :method) :post)
   (string? (from-req req :username))
   (string? (from-req req :password))))

(defn logout?
  "Returns true if the supplied request is a valid logout request."
  [{:keys [req config] :as T}]
  (= (from-req req :uri) (:logout-url config)))

(defn active-login-session?
  "Returns true if the supplied request is a valid request in an active login session."
  [{:keys [req config repo] :as T}]
  (and
   (not (login? T))
   (not (logout? T))
   (number? (from-req req :time-of-last-request))
   (is-user? (from-req req :logged-in-user) repo)))

(defn per-req-authentication?
  "Returns true if the supplied request is a valid request for a single request authentication."
  [{:keys [req config] :as T}]
  (and
   (not (or (login? T)
            (logout? T)
            (active-login-session? T)))
   (string? (from-req req :uid))
   (string? (from-req req :key))))

(defn bad-request?
  "Returns true if none of the other cases is true."
  [{:keys [req config] :as T}]
  (not
   (or (login? T)
       (logout? T)
       (active-login-session? T)
       (per-req-authentication? T))))

;;; Utils
;;; -----

(defn ^:dynamic *curr-time* []
  (System/currentTimeMillis))

;;; Module Outputs
;;; --------------

;;; logged-in-user

(defn make-login-authenticator [req repo config]
  (fn [user repo]
    (when (udb/verify-password repo user (from-req req :password))
      user)))

(defn make-session-authenticator [req repo config]
  (letfn [(expired? [tolr] (> (- (*curr-time*) tolr) (:timeout-ms config)))]
    (fn [user repo]
      (if (from-req req :remember-me)
        user
        (when (not (expired? (from-req req :time-of-last-request)))
          user)))))

(defn check-authentication [repo user-identifier authenticator]
  (if-let [account (udb/find-login-account repo user-identifier)]
    (authenticator account repo)))

(defn check-login [req repo config]
  (check-authentication repo (from-req req :username) (make-login-authenticator req repo config)))

(defn check-session [req repo config]
  (check-authentication repo (from-req req :logged-in-user) (make-session-authenticator req repo config)))

(defn logged-in-user
  "Calculates :logged-in-user.

   This function caches its result on the Trace which is in effect for
   a single request. It stores the result on a new Trace which it
   returns. The cache is obviously only effective if the Trace
   returned from the first call to this function is used in subsequent
   calls."
  [{:keys [req repo config] :as T}]
  (if-let [liu (get T :liu)] ; per-req cache
    [T liu]
    (let [liu
          (cond
           (login? T)                (check-login req repo config)
           (active-login-session? T) (check-session req repo config)
           :else nil)]
      [(assoc T :liu liu) liu])))

;;; *user*

(defn auth-request
  [{:keys [req repo] :as T}]
  (if-let [user (udb/find-active-account repo (from-req req :uid))]
    (when (udb/verify-password repo user (from-req req :key))
      user)))

(defn get-liu [T]
  (let [[_ liu] (logged-in-user T)]
    liu))

(defn user
  "Calculates *user* which is dynamically bound for use by the application handler."
  [{:keys [req repo config] :as T}]
  (let [anonymous (udb/anonymous repo)]
    (cond
     (login? T)                  (or (get-liu T) anonymous)
     (active-login-session? T)   (or (get-liu T) anonymous)
     (per-req-authentication? T) (or (auth-request T) anonymous)
     :else anonymous)))

;;; Time of Last Request

(defn time-of-this-request
  "Calculates :time-of-last-request which is stored on the session."
  [{:keys [req config] :as T}]
  (cond
   (or (login? T) (active-login-session? T)) (*curr-time*)
   :else nil))

;;; No Expire

(defn no-expire
  "Calculates :no-expire, which is then stored on the session."
  [{:keys [req repo config] :as T}]
  (cond
   (active-login-session? T) (from-req req :no-expire)
   (login? T)                (and (check-login req repo config) (from-req req :remember-me))
   :else                     nil))

;;; Flash Message

(defn flash-message
  [{:keys [req repo config] :as T}]
  (if (login? T)
    (if (get-liu T)
      ((get-in config [:messages :login-success]) req)
      ((get-in config [:messages :login-failure]) req))
    (if (logout? T)
      ((get-in config [:messages :logout]) req))))

;;; log

(defn make-log-writer [logger]
  (fn [req config]))

(def DEFAULT-CONFIG
     {:login-url "/login"
      :logout-url "/logout"
      :timeout-ms (* 1000 60 30)
      :messages {:login-success (fn [req] "Welcome")
                 :login-failure (fn [req] "Incorrect credentials")
                 :logout (fn [req] "Bye")}})

(defn wrap-auth
  "This is the entry point for using the authentication module. It
  wraps a ring handler to enforce the authentication rules. Returns a
  new handler that deals with authentication and then calls the
  supplied handler."
  [handler user-repository logger
   & {:keys [login-url logout-url timeout-ms messages] :as config}]
  (let [config (merge DEFAULT-CONFIG config)
        write-log (make-log-writer logger)]
    (fn [req]
      ;; T is a Trace analogous to a trace in the Trace Function
      ;; Method. It is used to transport the inputs, and store the
      ;; intermediate outputs (as a per-request cache) in the case of
      ;; expensive functions. This approach allows the code to be
      ;; written in a per-output manner without compromising
      ;; performance. You can see that the interface to logged-in-user
      ;; is different at the moment (it is the only one to return a
      ;; T), which could be improved.
      (let [T {:req req :repo user-repository :config config}]
        (let [no-expire (no-expire            T)
              tolr      (time-of-this-request T)
              [T liu]   (logged-in-user       T)
              msg       (flash-message        T)]
          (binding [*user* (user T)]
            (do
              (write-log req config)
              (update-session
               (handler req)
               {:no-expire no-expire
                :time-of-last-request tolr
                :logged-in-user liu
                :flash-message msg}))))))))
