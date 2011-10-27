(ns authentication-test
  (:use
   [clojure.test]
   [com.rheosystems.ring.authentication core user-repository]))

;;; Fakes

(def accounts
     (atom
      {:david {"username" "david" "password" "snowy"}
       :cabinet1 {"username" "cabinet1" "password" "12345"}}))

(defn convert-identifier [identifier]
  (if (string? identifier)
    identifier
    (get identifier "username")))

(def anon {:name "Anonymous User"})

(defrecord FakeUserRepository []
  UserRepository

  (user? [this user] (contains? user "username"))
  
  (anonymous [this] anon)

  (find-login-account
   [this identifier]
   (let [id (keyword (convert-identifier identifier))]
     (get @accounts id)))

  (find-active-account
   [this identifier]
   (let [id (keyword (convert-identifier identifier))]
     (get @accounts id)))

  (verify-password
   [this identifier pw]
   (let [id (keyword (convert-identifier identifier))]
     (= pw (get (get @accounts id) "password")))))

(defrecord EmptyRepository []
  UserRepository
  (user? [this user] true)
  (anonymous [this] anon)
  (find-login-account [this id] nil)
  (find-active-account [this id] nil)
  (verify-password [this id pw] false))

(def udb (FakeUserRepository.))

(def anon (anonymous udb))

(def timer-count (atom 123))

(defn fake-timer []
  @timer-count)

(defn set-timer! [value]
  (swap! timer-count (constantly value)))

(defn reset-timer! []
  (swap! timer-count (constantly 123)))

;;; Test Data

(def base-login-request
     {:uri "/login"
      :request-method :post
      :form-params {"username" "david" "password" "snowy"}})

(def base-login-response
     {:session {:logged-in-user (:david @accounts)
                :time-of-last-request 123
                :flash-message "Welcome"}})

(def req base-login-request)

(def single-auth-request
     {:query-params {"uid" "cabinet1" "key" "12345"}})

(def base-session-request
     {:session {:logged-in-user (:david @accounts)
                :time-of-last-request 0
                :no-expire nil}})

(def spoof-session-request
     {:session {:logged-in-user {"username" "mallory" "password" "hacked"}
                :time-of-last-request 0
                :no-expire true}})

(def blank-response {})

;;; Test Setup

(defn test-setup [f]
  (reset-timer!)
  (f))

;;; Test Oracle

(defn expect-anon
  "Asserts that *user* is always thread bound and is anonymous"
  [req]
  (is (thread-bound? #'*user*))
  (is (= *user* anon))
  blank-response)

(defn expect-david
  "Asserts that *user* is always thread bound and is david."
  [req]
  (is (thread-bound? #'*user*))
  (is (= *user* (:david @accounts)))
  blank-response)

(defn expect-cabinet
  "Asserts that *user* is always thread bound and is cabinet1."
  [req]
  (is (thread-bound? #'*user*))
  (is (= *user* (:cabinet1 @accounts)))
  blank-response)

(def expect-anon-handler (wrap-auth expect-anon (FakeUserRepository.) nil))
(def expect-david-handler (wrap-auth expect-david (FakeUserRepository.) nil))
(def expect-cabinet-handler (wrap-auth expect-cabinet (FakeUserRepository.) nil))

;;; Tests

(defn assert-login [resp & [extra]]
  (is (= resp (merge-with merge base-login-response extra))))

(deftest test-login
  (binding [*curr-time* fake-timer]
    (testing "Correct username and password"
      (let [resp (expect-david-handler base-login-request)]
        (assert-login resp)))
    (testing "No such user"
      (let [resp (expect-anon-handler (merge base-login-request {:form-params {"username" "divad" "password" "snowy"}}))]
        (is (= resp {:session {:time-of-last-request 123 :flash-message "Incorrect credentials"}}))))
    (testing "Bad password"
      (let [resp (expect-anon-handler (merge base-login-request {:form-params {"username" "david" "password" "abcabc"}}))]
        (is (= resp {:session {:time-of-last-request 123 :flash-message "Incorrect credentials"}}))))))

(deftest test-remember-me
  (binding [*curr-time* fake-timer]
    (let [remember-me-req (merge-with merge base-login-request {:form-params {"remember-me" true}})
          resp (expect-david-handler remember-me-req)]
      (assert-login resp {:session {:no-expire true}}))))

(deftest test-per-req-auth
  (let [resp (expect-cabinet-handler single-auth-request)]
    (is (= resp {:session {}})))
  (testing "Cannot over-ride session with per-req auth"
    (binding [*curr-time* fake-timer]
      (let [resp (expect-david-handler (merge base-session-request single-auth-request))]
        (is (= resp {:session {:logged-in-user {"username" "david", "password" "snowy"} :time-of-last-request 123}}))))))

(deftest test-session
  (binding [*curr-time* fake-timer]
    (let [resp (expect-david-handler base-session-request)]
      (is (= resp {:session {:logged-in-user (:david @accounts) :time-of-last-request 123}})))
    (testing "Session expiry"
      (set-timer! 9999999999999)
      (let [resp (expect-anon-handler base-session-request)]
        (is (= resp {:session {:time-of-last-request 9999999999999}})))
      (reset-timer!))
    (testing "No session spoofing: the identified user must exist in the user repository"
      (let [resp (expect-anon-handler spoof-session-request)]
        ;; no-expire is always carried over from the last session request as per spec
        (is (= resp {:session {:time-of-last-request 123 :no-expire true}}))))
    (testing "If a user is removed from the repository the session is terminated"
      (let [no-user-handler (wrap-auth expect-anon (EmptyRepository.) nil)
            resp (no-user-handler base-session-request)]
        (is (= resp {:session {:time-of-last-request 123}}))))))

(deftest test-logout
  (binding [*curr-time* fake-timer]
    (let [resp (expect-anon-handler (merge base-session-request {:uri "/logout"}))]
      (is (= resp {:session {:flash-message "Bye"}})))))

(use-fixtures :each test-setup)

;; (run-tests)
