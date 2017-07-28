(ns bits.crypt.toolbox
  "Utilities for RSA and AES"
  (:require [bits.host :as h]
            [bits.crypt :as c]
            [bits.crypt.e2e :as ec]
            [bits.crypt.api]))

#+cljs
(defn random-bytes [size]
  (let [buf (js/Uint8Array. size)
        wcrypto js/crypto]
    (.getRandomValues wcrypto buf)
    (h/ByteBox. buf)))

#+clj
(def ^:private sec-random (java.security.SecureRandom.))
#+clj
(defn random-bytes
  ([size] (random-bytes size sec-random))
  ([size ^java.util.Random random]
     (let [buf (byte-array size)]
       (.nextBytes random buf)
       buf)))

(defn random-aes-key
  "Generates random AES key of requested length (in bits)"
  ([]
   (c/aes-key (random-bytes 32)))
  ([size]
   (c/aes-key (random-bytes (/ size 8)))))

(defn rsa-aes-encrypt
  [msg rsa-key & [aes-key]]
  (let  [aes-key (if aes-key
                   (assoc aes-key :iv nil) ; force zero iv
                   (random-aes-key 256))
         enc     ((-> aes-key c/encryptor) msg)
         keyenc  ((-> rsa-key c/to-public c/encryptor) (:key aes-key))]
    (when-not (= 256 (count keyenc))
      (throw (ex-info "Encrypted code is not 256 bytes"
                      {:count (count keyenc)})))
    (h/join [keyenc enc])))

(defn rsa-aes-decrypt
  ([msg rsa-key]
     (let [aes ((c/decryptor rsa-key) (h/slice msg 0 256))
           msg ((-> aes c/aes-key c/decryptor) (h/slice msg 256))]
       msg)))

(defn verify-keys
  "Returns true if given pub key matches the private key"
  [priv pub]
  (let [challenge (->> (repeatedly #(rand-int 256)) (take 64) into-array)
        sign      (c/signator priv)
        signature (sign challenge)
        ver       (c/verificator pub signature)]
    (ver challenge)))

(defn ec-encrypt
  [msg pub-key]
  ((c/encryptor pub-key) msg))

(defn ec-decrypt
  [{:keys [k d] :as msg} priv-key]
  (let [eph-dec (c/with-ephemereal priv-key k)]
    ((c/decryptor eph-dec) d)))

(defn assert-ec-private-key
  [key]
  (when-not (c/ec-private-key? key)
    (throw (ex-info "Expected EC private key" {:key key})))
  key)

(defn assert-ec-public-key
  [key]
  (when-not (c/ec-public-key? key)
    (throw (ex-info "Expected EC public key" {:key key})))
  key)

(defn signature?
  "Returns true if given argument could be signature"
  [what]
  (boolean
    (or (h/bytes? what)
      (instance? bits.crypt.api.ECSignature what))))

(defn assert-aes-key
  [key]
  (when-not (c/aes-key? key)
    (throw (ex-info "Not an AES key" {:key key})))
  key)

(defn aes-encrypt [key ciphertext]
  ((c/encryptor key) ciphertext))

(defn aes-decrypt [key ciphertext]
  ((c/decryptor key) ciphertext))

(defn data-fingerprint
  "Returns required number of bytes which represent fingerprint of given byte array.
   The fingerprint is computed as successive XOR of appropriate bytes"
  ([bytea] (data-fingerprint bytea 4))
  ([bytea digest-bytes]
     (let [set-byte-fn #+clj aset-byte #+cljs aset
           bytea       (h/as-byte-array bytea)]
       (when (not= 0 (mod (count bytea) digest-bytes))
         (throw (ex-info (str "Can only digest byte arrays of size divisible by " digest-bytes) {:bytes bytea})))
       (loop [acc      (h/mutable-byte-array digest-bytes)
              offset   0]
         (if (< offset (count bytea))
           (do
             (dotimes [idx digest-bytes]
               (set-byte-fn acc idx (bit-xor (aget acc idx)
                                      (aget bytea (+ offset idx)))))
             (recur acc (+ offset digest-bytes)))
           acc)))))


(def ec-priv-num-to-key ec/ec-priv-num-to-key)
