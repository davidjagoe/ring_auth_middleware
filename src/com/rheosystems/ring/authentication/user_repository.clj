(ns ^{:doc "This protocol must be implemented by the user repository
  that is supplied to core/wrap-auth."}
  com.rheosystems.ring.authentication.user-repository)

(defprotocol UserRepository
  (verify-password [this identifier password] "Returns true if the supplied password matches that of the identified user")
  (find-active-account [this identifier] "Return an active accounts matching the supplied identifier, or nil")
  (find-login-account [this identifier] "Return active account that is also login account, or nil")
  (anonymous [this] "Return an anonymous user")
  (user? [this user] "Returns true if user is recognized as a valid user object."))