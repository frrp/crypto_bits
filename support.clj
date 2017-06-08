(ns bits.crypt.support
  (:require [clojure.java.io :as io]
            [bits.crypt.api :as crypt.api]
            [bits.crypt.e2e :as e2e])
  (:import [java.io File]
           [java.security KeyFactory]
           [java.security.spec X509EncodedKeySpec]))

(def ^:private java-rsa-factory (KeyFactory/getInstance "RSA"))

(defn der->RSAPublicKey
  "Given the bytes representing a public key in the DER format, constructs
   bits.crypt.api.RSAPublicKey with correct exponent and modulus"
  [bytes]
  (let [spec (X509EncodedKeySpec. bytes)
        pkey (.generatePublic java-rsa-factory spec)]
    (crypt.api/rsa-public-key {:modulus   (.getModulus pkey)
                               :exponent  (.getPublicExponent pkey)})))

(def ^:private java-ec-factory (KeyFactory/getInstance "EC" "BC"))

(defn der->ECPublicKey
  "Given the bytes representing a public key in the DER format, constructs
  bits.crypt.api.ECPublicKey"
  [bytes]
  (let [spec (X509EncodedKeySpec. bytes)
        pkey (.generatePublic java-ec-factory spec)]
    (e2e/bc-pub->ECPublicKey pkey "P_384")))
