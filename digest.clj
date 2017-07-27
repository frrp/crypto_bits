(ns bits.crypt.digest
  "Tools for deterministic hash of clojure data structures"
  (:require [clojure.string :as s]
            [bits.host :as h]
            [bits.crypt.bouncy-castle :as bc]))

(defprotocol IDataDigest
  (-data-digest [o] "Compute (recursively) object data digets"))


(defn prefix+length32 [^Character t ^Long n]
  (when-not (<= 0 n 4294967295)
    (throw (ex-info "Cannot encode length in 32 bytes"
                    {:tag t, :n n})))

  (byte-array [(long t)
               (bit-and (bit-shift-right n 24) 0xff)
               (bit-and (bit-shift-right n 16) 0xff)
               (bit-and (bit-shift-right n  8) 0xff)
               (bit-and n                      0xff)]))

(defn prefix+length64 [^Character t ^Long n]
  (byte-array [(long t)
               (bit-and (bit-shift-right n 56) 0xff)
               (bit-and (bit-shift-right n 48) 0xff)
               (bit-and (bit-shift-right n 40) 0xff)
               (bit-and (bit-shift-right n 32) 0xff)
               (bit-and (bit-shift-right n 24) 0xff)
               (bit-and (bit-shift-right n 16) 0xff)
               (bit-and (bit-shift-right n  8) 0xff)
               (bit-and n                      0xff)]))

;; from Clojure code
(def ^:private thread-local-utc-date-format
  (proxy [ThreadLocal] []
    (initialValue []
      (doto (java.text.SimpleDateFormat. "yyyy-MM-dd'T'HH:mm:ss.SSS-00:00")
        (.setTimeZone (java.util.TimeZone/getTimeZone "GMT"))))))

(defn make-prelude [x]
  (byte-array [(long x)]))

(def value-nil            (bc/sha-256 "N"))
(def value-boolean-true   (bc/sha-256 "T"))
(def value-boolean-false  (bc/sha-256 "F"))

(def prefix-byte-array    \b)
(def prefix-string        \s)
(def prefix-symbol        \')
(def prefix-keyword       \:)
(def prefix-sequence      \[)
(def prefix-set           \t)
(def prefix-map           \{)
(def prefix-tag           \#)

(def prelude-inst         (make-prelude \i))
(def prelude-number       (make-prelude \n))
(def prelude-sha256       (make-prelude \h))

(defn sha-for-record [r]
  (let [name (-> r h/type-name (.getBytes "UTF-8"))]
    (h/incremental bc/sha-256
                   (prefix+length32 prefix-tag (count name)) name)))

(extend-protocol IDataDigest
  (Class/forName "[B")
  (-data-digest [bytes]
    (bc/sha-256 (prefix+length64 prefix-byte-array (count bytes)) bytes))

  nil
  (-data-digest [_]
    value-nil)

  java.lang.Boolean
  (-data-digest [b]
    (if b
      value-boolean-true
      value-boolean-false))

  Number
  (-data-digest [n]
    (bc/sha-256 prelude-number (.getBytes (str n) "UTF-8")))

  String
  (-data-digest [s]
    (let [b (.getBytes s "UTF-8")]
      (bc/sha-256 (prefix+length32 prefix-string (count b)) b)))

  clojure.lang.Symbol
  (-data-digest [s]
    (let [b (-> s str (.getBytes "UTF-8"))]
      (bc/sha-256 (prefix+length32 prefix-symbol (count b)) b)))

  clojure.lang.Keyword
  (-data-digest [k]
    (let [s (str k)
          b (.getBytes s "UTF-8")]
      (bc/sha-256 (prefix+length32 prefix-keyword (count b)) b)))

  java.util.Date
  (-data-digest [d]
    (let [s (.format (.get thread-local-utc-date-format) d)
          b (.getBytes s "UTF-8")]
      (bc/sha-256 prelude-inst b)))

  bits.crypt.sha256.Sha256
  (-data-digest [s]
    (bc/sha-256 prelude-sha256 (h/as-byte-array s)))

  clojure.lang.IPersistentCollection
  (-data-digest [s]
    (let [prelude (prefix+length32 prefix-sequence (count s))
          acc     (h/incremental bc/sha-256 prelude)]
      (h/finish! (transduce (map -data-digest) h/update! acc s))))

  clojure.lang.IPersistentSet
  (-data-digest [s]
    (let [prelude  (prefix+length32 prefix-set (count s))
          children (->> s (map -data-digest) sort)
          acc      (h/incremental bc/sha-256 prelude)]
      (h/finish! (reduce h/update! acc children))))

  clojure.lang.IPersistentMap
  (-data-digest [m]
    (let [sha  (if (instance? clojure.lang.IRecord m)
                 (sha-for-record m)
                 (h/incremental bc/sha-256))]
      (h/update! sha (prefix+length32 prefix-map (count m)))
      (->> (map (fn [[k v]] [(-data-digest k) (-data-digest v)]) m)
           (sort-by first)
           (transduce cat h/update! sha)
           h/finish!))))

(defn data-digest [o]
  (if (bc/sha256? o)
    o
    (-data-digest o)))

(comment
  (require '[bits.host :as h])

  (def testp (h/as-byte-array "some prelude"))
  (def testr {"bits.record/hash"   "uPoYvNl5V2foANVn8swXbhYUF30vyEHkU9XVU7zUmiU="
             "bits.record/parent"  "uPoYvNl5V2foANVn8swXbhYUF30vyEHkU9XVU7zUmiU="
             "bits.record/topc"    "bits.topic/policy"
             "bits.record/private" "something really private"
             "bits.record/public"  "answer is 42"})

  (time ;; 100k => 11.4
   (dotimes [x 100000]
     (->> testr
          (map (fn [[k v]] (bc/sha-256 testp (bc/sha-256 testp k) (bc/sha-256 testp v))))
          sort
          (apply bc/sha-256 testp))))

  (time ;; 100k => 9s
   (dotimes [x 100000]
     (->> testr
          (map (fn [[k v]] [(bc/sha-256 testp k) (bc/sha-256 testp v)]))
          (sort-by first)
          (apply concat)
          (apply bc/sha-256 testp)
          )))


  ;;#sha256 "uPoYvNl5V2foANVn8swXbhYUF30vyEHkU9XVU7zUmiU="

  (time ;; 15.349s
   (dotimes [x 1000000]
     ;;#sha256 "uPoYvNl5V2foANVn8swXbhYUF30vyEHkU9XVU7zUmiU="
     (bc/sha-256 a (bc/sha-256 a) (bc/sha-256 a))))


  (h/as-byte-array (bc/sha-256 a))

  )
