(ns cryptelo.crypt.bouncy-castle
  (:require [cryptelo.crypt.api :as api]
            [cryptelo.host :as h :refer [as-big-int as-byte-array]]
            [cryptelo.crypt.sha256 :as sha256])
  (:import [java.security Security MessageDigest]

           [javax.crypto Cipher
            ;; for AES
            spec.SecretKeySpec
            spec.IvParameterSpec]

           ;; for RSA
           [java.security KeyFactory KeyPairGenerator Signature]
           [java.security.spec RSAPublicKeySpec
            RSAMultiPrimePrivateCrtKeySpec]

           ;; for PBKF password generation
           org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
           org.bouncycastle.crypto.digests.SHA256Digest

           ;; bytes generator function
           org.bouncycastle.crypto.generators.HKDFBytesGenerator
           org.bouncycastle.crypto.params.HKDFParameters

           ;; for Bouncy Castle initialization
           org.bouncycastle.jce.provider.BouncyCastleProvider))

(defprotocol ICipher
  (update! [x data] "Update with given data")
  (finish! [x data] [x] "Finish the process and return the result"))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;      SHA encryption
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(deftype DigestInstance [instance return]
  cryptelo.host.IncrementalState
  (update! [s] s)
  (update! [s value] (.update instance (as-byte-array value)) s)
  (finish! [_] (-> instance .digest return)))

(defn- make-digest-instance
  [algo return]
  (DigestInstance. (MessageDigest/getInstance algo) return))

(defrecord Digest [algorithm return]
  clojure.lang.IFn
  (invoke [_ v1]
    (h/finish! (doto (make-digest-instance algorithm return)
                 (h/update! v1))))

  (invoke [_ v1 v2]
    (h/finish! (doto (make-digest-instance algorithm return)
                 (h/update! v1) (h/update! v2))))

  (invoke [_ v1 v2 v3]
    (h/finish! (doto (make-digest-instance algorithm return)
                 (h/update! v1) (h/update! v2) (h/update! v3))))

  (applyTo [x args]
    (-> (reduce h/update! (make-digest-instance algorithm return) args)
        h/finish!))

  h/Incremental
  (-incremental [_]
    (make-digest-instance algorithm return))

  h/ITransducer
  (transducer [x]
    (fn [rf]
      (let [algo (MessageDigest/getInstance algorithm)]
        (fn
          ([]
           (rf))
          ([result]
           (rf (rf result (return (.digest algo)))))
          ([result input]
           (.update algo (as-byte-array input))
           result))))))

(defn parse-sha-256 [o]
  (-> (h/parse-base64 o)
      sha256/wrap-sha-256))

(def sha-256 (Digest. "sha-256" sha256/wrap-sha-256))
(def sha256? sha256/sha256?)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;      Cipher instance
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defprotocol IJavaKey
  (-java-key [key])
  (-algo-params [key]))

(def ^:private cipher-mode
  {:decrypt Cipher/DECRYPT_MODE
   :encrypt Cipher/ENCRYPT_MODE})

(defprotocol IJavaInit
  (-java-init [self] "Return java Crypto/Signature object"))

(defrecord CipherProcess [cipher-descriptor]
  IJavaInit
  (-java-init [self]
    (-java-init cipher-descriptor))

  clojure.lang.IFn
  (invoke [x msg]
    (-> (-java-init x)
        (finish! (as-byte-array msg))))

  (applyTo [x args]
    (assert (= 1 (count args)))
    (x (first args)))

  h/ITransducer
  (transducer [x]
    (fn [rf]
      (let [cipher (-java-init x)
            completed? (volatile! false)]
        (fn
          ([]
           (rf))
          ([result]
           (if @completed?
             (rf result)
             (let [final (finish! cipher)]
               (vreset! completed? true)
               (if final
                 (rf (rf result final))
                 (rf result)))))
          ([result input]
           (if-let [v (update! cipher (as-byte-array input))]
             (rf result v)
             result)))))))

(defrecord SignProcess [provider algorithm init finish]
  IJavaInit
  (-java-init [_]
    (doto (Signature/getInstance algorithm provider)
      init))

  clojure.lang.IFn
  (invoke [x msg]
    (-> (-java-init x)
        (doto (.update (as-byte-array msg)))
        finish))

  (applyTo [x args]
    (assert (= 1 (count args)))
    (x (first args))))

;; public keys

(def ^:private java-rsa-factory (KeyFactory/getInstance "RSA"))

(defn rsa-key-generator
  "Make RSA key generator"
  [size]
  (let [generator (doto (KeyPairGenerator/getInstance "RSA")
                    (.initialize size))]
    (fn []
      (let [priv (.. generator genKeyPair getPrivate)]
        (api/rsa-private-key {:modulus (.getModulus priv)
                              :exponent (.getPublicExponent priv)
                              :private-exponent (.getPrivateExponent priv)
                              :private-p (.getPrimeP priv)
                              :private-q (.getPrimeQ priv)
                              :private-dmp1 (.getPrimeExponentP priv)
                              :private-dmq1 (.getPrimeExponentQ priv)
                              :private-coeff (.getCrtCoefficient priv)})))))

(defrecord SimpleCipherInit [provider scheme key mode]
  IJavaInit
  (-java-init [self]
    (let [delegate (doto (Cipher/getInstance scheme provider)
                     (.init (cipher-mode mode) (-java-key key) (-algo-params key)))]
      (reify ICipher

        (update! [this data] (.update  delegate data))
        (finish! [this data] (.doFinal delegate data))
        (finish! [this]      (.doFinal delegate))))))

(extend-type cryptelo.crypt.api.RSAPublicKey
  cryptelo.crypt.api/IEncryptor
  (encryptor [key]
    (->CipherProcess (SimpleCipherInit. "BC" "RSA/ECB/PKCS1Padding" key :encrypt)))

  cryptelo.crypt.api/IVerificator
  (verificator [key signature]
    (SignProcess. "BC" "SHA256withRSA"
                  #(.initVerify % (-> key api/to-public -java-key))
                  #(.verify % (as-byte-array signature))))

  IJavaKey
  (-algo-params [key] nil)
  (-java-key [key]
    (->> (RSAPublicKeySpec. (as-big-int (.-modulus key))
                            (as-big-int (.-exponent key)))
         (.generatePublic java-rsa-factory))))

(extend-type cryptelo.crypt.api.RSAPrivateKey
  cryptelo.crypt.api/IEncryptor
  (encryptor [key]
    (->CipherProcess
      (SimpleCipherInit. "BC" "RSA/ECB/PKCS1Padding" (api/to-public key) :encrypt)))

  cryptelo.crypt.api/IDecryptor
  (decryptor [key]
    (->CipherProcess (SimpleCipherInit. "BC" "RSA/ECB/PKCS1Padding" key :decrypt)))

  cryptelo.crypt.api/ISignator
  (signator [key]
    (SignProcess. "BC" "SHA256withRSA"
                  #(.initSign % (-java-key key))
                  #(.sign %)))

  IJavaKey
  (-algo-params [key] nil)
  (-java-key [key]
    (->> (RSAMultiPrimePrivateCrtKeySpec.
          (as-big-int (:modulus key))
          (as-big-int (:exponent key))
          (as-big-int (:private-exponent key))
          (as-big-int (:private-p key))
          (as-big-int (:private-q key))
          (as-big-int (:private-dmp1 key))
          (as-big-int (:private-dmq1 key))
          (as-big-int (:private-coeff key))
          nil)
         (.generatePrivate java-rsa-factory))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;      AES
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(extend-type cryptelo.crypt.api.AESKey
  cryptelo.crypt.api/IEncryptor
  (encryptor [key]
    (->CipherProcess (SimpleCipherInit. "BC" "AES/CBC/PKCS7Padding" key :encrypt)))

  cryptelo.crypt.api/IDecryptor
  (decryptor [key]
    (->CipherProcess (SimpleCipherInit. "BC" "AES/CBC/PKCS7padding" key :decrypt)))

  IJavaKey
  (-algo-params [key]
    (-> (or (:iv key) (take 16 (repeat 0)))
        as-byte-array
        IvParameterSpec.))

  (-java-key [key]
    (SecretKeySpec. (as-byte-array (:key key)) "AES")))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;      Generators
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn derive-key-pbkdf2-sha256
  ([password]
     (derive-key-pbkdf2-sha256 password 40000))
  ([password iterations]
     (derive-key-pbkdf2-sha256 password iterations (sha-256 password)))
  ([password iterations salt]
     (let [gen (doto (PKCS5S2ParametersGenerator. (SHA256Digest.))
                 (.init (h/as-byte-array password)
                        (h/as-byte-array salt)
                        iterations))]
       (-> (.generateDerivedMacParameters gen 256)
           .getKey))))

(defn hkdf
  "Expands given input key material into required length of output material"
  ([ikm] (hkdf ikm (/ 256 8)))
  ([ikm length]
     (let [bytes (h/as-byte-array ikm)
           sha   (SHA256Digest.)
           par   (HKDFParameters. ikm nil nil)
           gen   (HKDFBytesGenerator. sha)
           out   (byte-array length)]
       (.init gen par)
       (.generateBytes gen out 0 (count out))
       out)))
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;      Complete cryptelo.crypt api
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn digest-sha-256 []
  sha-256)

(def rsa-public-key  api/rsa-public-key)
(def rsa-private-key api/rsa-private-key)
(def aes-key         api/aes-key)

(def ^:dynamic *host-map*      h/*host-map*)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;      Init
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(h/reader-map-add! 'sha256 parse-sha-256)

(Security/addProvider (BouncyCastleProvider.))
