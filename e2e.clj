(ns bits.crypt.e2e
  (:require [bits.crypt.api           :as api]
            [clojure.string               :as str]
            [bits.crypt.bouncy-castle :as bc]
            [bits.host                :as h])
  (:import  [java.security                                     KeyPairGenerator]
            [java.security                                     SecureRandom]
            [java.security                                     KeyFactory]
            [javax.crypto                                      KeyAgreement]
            [org.bouncycastle.jce                              ECNamedCurveTable]
            [org.bouncycastle.jce.spec                         ECNamedCurveParameterSpec]
            [java.security.spec                                ECPoint]
            [java.security.spec                                ECPublicKeySpec]
            [java.security.spec                                ECPrivateKeySpec]
            [org.bouncycastle.jce                              ECPointUtil]
            [org.bouncycastle.jcajce.provider.asymmetric.util  EC5Util]
            [bits.crypt.api                                ECPrivateKey]
            [bits.crypt.api                                ECPublicKey]
            [bits.crypt.api                                AESKey]
            [bits.crypt.api                                ECSignature]
            [bits.crypt.bouncy_castle                      CipherProcess]
            [bits.crypt.bouncy_castle                      SignProcess]
            [java.security                                     Signature]
            [org.bouncycastle.asn1                             ASN1InputStream]
            [org.bouncycastle.asn1                             ASN1OutputStream]
            [org.bouncycastle.asn1                             DERInteger]
            [org.bouncycastle.asn1                             ASN1EncodableVector]
            [org.bouncycastle.asn1                             DERSequence]
            [java.io                                           ByteArrayOutputStream]))

(def ec-key-gen (doto (KeyPairGenerator/getInstance "EC" "BC")
                  (.initialize 384 (SecureRandom.))))

(def ec-key-fact (KeyFactory/getInstance "EC" "BC"))

(defn ec-param-spec-for [curve-name]
  (let [norm-name (some-> curve-name str/upper-case (str/replace "_" "-"))
        params (ECNamedCurveTable/getParameterSpec norm-name)]
    (when-not params
      (throw (ex-info (str "Unknown curve: " norm-name) {:original-name curve-name :normalized-name norm-name})))
    params))

(defn curve
  ([] (curve "P_384"))
  ([name] (-> name ec-param-spec-for .getCurve)))

(defn ECPublicKey->bc-pub [{:keys [pub-x pub-y type]}]
  (let [param-spec (ec-param-spec-for type)
        curve      (.getCurve param-spec)
        elliptic-c (EC5Util/convertCurve curve (.getSeed param-spec))
        point      (.createPoint curve pub-x pub-y false)
        ec-point   (ECPoint. (-> point .getAffineXCoord .toBigInteger)
                             (-> point .getAffineYCoord .toBigInteger))
        point-spec (EC5Util/convertSpec elliptic-c param-spec)
        pkey-spec  (ECPublicKeySpec. ec-point point-spec)]
    (.generatePublic ec-key-fact pkey-spec)))

(defn ECPrivateKey->bc-priv [{:keys [private type]}]
  (let [param-spec (ec-param-spec-for type)
        curve      (.getCurve param-spec)
        elliptic-c (EC5Util/convertCurve curve (.getSeed param-spec))
        conv-spec  (EC5Util/convertSpec elliptic-c param-spec)
        priv-spec  (ECPrivateKeySpec. private conv-spec)]
    (.generatePrivate ec-key-fact priv-spec)))

(defn bc-pub->ECPublicKey [pub type]
  (let [x (-> pub .getQ .getX .toBigInteger)
        y (-> pub .getQ .getY .toBigInteger)]
    (ECPublicKey. type x y)))

(defn bc-key-pair->ECPrivateKey [key-pair type]
  (let [priv                  (-> key-pair .getPrivate .getD)
        {:keys [pub-x pub-y]} (bc-pub->ECPublicKey (.getPublic key-pair) type)]
    (ECPrivateKey. type priv pub-x pub-y)))

(defn generate-key
  "Generates random P-384 key pair"
  []
  (let [priv (.generateKeyPair ec-key-gen)]
    (bc-key-pair->ECPrivateKey priv "P_384")))

(defn ec-key-generator []
  (fn [] (generate-key)))

(extend-type bits.crypt.api.ECPublicKey
  bits.crypt.api/ECDeriveSecretPublic
  (ec-derive-pub [pkey eph]
    (when-not (instance? ECPrivateKey eph)
      (throw (ex-info "Public DH requires ephemereal private key"
                      {:ephemereal eph})))
    (let [param-spec (ec-param-spec-for (:type pkey))
          bc-pub     (ECPublicKey->bc-pub pkey)
          key-agree  (KeyAgreement/getInstance "ECDH" "BC")
          eph-priv   (ECPrivateKey->bc-priv eph)]
      (.init     key-agree eph-priv)
      (.doPhase  key-agree bc-pub true)
      (.generateSecret key-agree))))

(extend-type bits.crypt.api.ECPrivateKey
  bits.crypt.api/ECDeriveSecretPrivate
  (ec-derive-priv [priv eph]
    (when-not (instance? ECPublicKey eph)
      (throw (ex-info "Private DH requires ephemereal public key"
                      {:ephemereal eph})))
    (let [param-spec (ec-param-spec-for (:type priv))
          bc-priv    (ECPrivateKey->bc-priv priv)
          key-agree  (KeyAgreement/getInstance "ECDH" "BC")
          eph-pub    (ECPublicKey->bc-pub eph)]
      (.init    key-agree bc-priv)
      (.doPhase key-agree eph-pub true)
      (.generateSecret key-agree))))

(defprotocol IECBaseKey
  (with-ephemereal [this ephemereal-key]))

(defprotocol IECKeyDerive
  (derive-key [this]))

;; when decrypting using EC IES the data are encrypted by AES/CBC/PKCS7Padding
;; and the key is derived from the shared secret
(defrecord ECPrivateKeyDecryptor [priv-key ephemereal-key]
  api/IDecryptor
  (decryptor [this] (CipherProcess. this))

  IECKeyDerive
  (derive-key [this]
    (let [key (-> priv-key
                  (api/ec-derive-priv ephemereal-key)
                  bc/hkdf)]
      key))

  bc/IJavaInit
  (-java-init [this]
    (let [aes-key   (AESKey. (derive-key this) nil)
          aes       (bc/-java-init (api/decryptor aes-key))]
      aes)))

(defrecord ECPublicKeyEncryptor [pub-key ephemereal-key]
  api/IEncryptor
  (encryptor [this] (CipherProcess. this))

  IECKeyDerive
  (derive-key [this]
    (-> pub-key
        (api/ec-derive-pub ephemereal-key)
        bc/hkdf))

  ;; returns an ICipher (backed by AES/CBC/PKCS7Padding)
  bc/IJavaInit
  (-java-init [this]
    (let [aes-key   (AESKey. (derive-key this) nil)
          aes       (bc/-java-init (api/encryptor aes-key))
          wrap-ret  (fn [data] {:d data :k (api/to-public ephemereal-key)})]
      (reify bits.crypt.bouncy-castle/ICipher
        (update! [this data]
          (bc/update! aes data))
        (finish! [this data]
          (wrap-ret (bc/finish! aes data)))
        (finish! [this]
          (wrap-ret (bc/finish! aes)))))))

(defn der-signature->ECSignature [sig-bytes]
  (when sig-bytes
    (let [dec (ASN1InputStream. sig-bytes)
          der-seq (.readObject dec)
          r   (.getObjectAt der-seq 0)
          s   (.getObjectAt der-seq 1)]
      (.close dec)
      (ECSignature. (when r (.getValue r))
                    (when s (.getValue s))))))

(extend-protocol h/IAsByteArray

  ECSignature
  (-as-byte-array [x]
    (with-open [bous (ByteArrayOutputStream.)
                asn  (ASN1OutputStream. bous)]
      (let [v    (ASN1EncodableVector.)]
        (.add v (DERInteger. (:r x)))
        (.add v (DERInteger. (:s x)))
        (.writeObject asn (DERSequence.  v))
        (.toByteArray bous)))))

(extend-type bits.crypt.api.ECPrivateKey

  api/ISignator
  (signator [key]
    (SignProcess. "BC" "SHA384withECDSA"
                  #(.initSign % (bc/-java-key key))
                  #(-> % .sign der-signature->ECSignature)))

  bc/IJavaKey
  (-algo-params [key] nil)
  (-java-key    [key]
    (ECPrivateKey->bc-priv key))

  IECBaseKey
  (with-ephemereal [this eph]
    (ECPrivateKeyDecryptor. this eph)))

(extend-type bits.crypt.api.ECPublicKey

  api/IEncryptor
  (encryptor [this]
    (let [ephemereal (generate-key)]
      (with-ephemereal this ephemereal)))

  bc/IJavaKey
  (-algo-params [key] nil)
  (-java-key    [key]
    (ECPublicKey->bc-pub key))

  api/IVerificator
  (verificator [key signature]
    (SignProcess. "BC" "SHA384withECDSA"
                  #(.initVerify % (-> key api/to-public bc/-java-key))
                  #(.verify     % (h/as-byte-array signature))))

  IECBaseKey
  (with-ephemereal [this eph]
    ;; delegate the encryption to ECPublicKeyEncryptor
    (-> (ECPublicKeyEncryptor. this eph)
        api/encryptor)))

(defn e2e-point-to-map [point]
  {:x (-> point .getX .toBigInteger)
   :y (-> point .getY .toBigInteger)})

(defn decode-pub-key-from-bytes
  "Decodes the point which makes the public key from given bytes"
  [name bytes]
  (let [ec     (curve name)
        point  (.decodePoint ec bytes)
        {:keys [x y]} (e2e-point-to-map point)]
    (bits.crypt.api.ECPublicKey. name x y)))

(defn ec-priv-num-to-key [cname num]
  (let [spec          (ec-param-spec-for cname)
        pub           (-> spec .getG (.multiply num))
        {:keys [x y]} (e2e-point-to-map pub)]
    (bits.crypt.api.ECPrivateKey. cname num x y)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;	Key conversions
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(extend-type ECPublicKey
  bits.crypt.api/IKeySerialize
  (key-serialize [{:keys [type pub-x pub-y]}]
    (when-not (= type "P_384")
      (throw (ex-info "Unsupported curve type"
                      {:curve-type type})))
    (h/concat-bytes [4] (h/int->bytes pub-x 48) (h/int->bytes pub-y 48))))

(defn key-deserialize [bytes]
  ;; let's not over-engeneer it at the beginning
  (when (< (count bytes) 97)
    (throw (ex-info "Cannot deserialize EC key, byte array too small" {})))
  (when-not (= 4 (aget bytes 0))
    (throw (ex-info "Incorrect key header"
                    {:expected 4, :actual (aget bytes 0)})))
  [(ECPublicKey. "P_384"
                 (BigInteger. 1 (h/slice bytes 1 49))
                 (BigInteger. 1 (h/slice bytes 49 97)))
   (h/slice bytes 97)])
