(ns cryptelo.crypt.sha256
  (:require [cryptelo.host :as h])
  (:import com.google.common.primitives.UnsignedBytes
           java.util.UUID
           java.nio.ByteBuffer))

(def ubytes-compare
  (let [uc (UnsignedBytes/lexicographicalComparator)]
    (fn ^long  [^bytes x ^bytes y]
      (.compare uc x y))))

(deftype Sha256 [^Long hsh ^bytes ba]
  Object
  (hashCode [_] hsh)

  (equals [_ o]
    (and (instance? Sha256 o)
         (= hsh (.-hsh ^Sha256 o))
         (java.util.Arrays/equals ba ^bytes (.-ba ^Sha256 o))))

  Comparable
  (compareTo [_ o]
    (ubytes-compare ba (.-ba ^Sha256 o)))

  cryptelo.host.IAsByteArray
  (-as-byte-array [_] ba)

  cryptelo.host.IAsBytes
  (-as-bytes [_] ba)

  cryptelo.host.IBytesEqual
  (-bytes-equal [_ that]
    (h/bytes= ba that)))

(defn wrap-sha-256
  [byte-array]
  (when-not (= 32 (count byte-array))
    (throw "Incorrect sha length, should be 32"))
  (Sha256. (-> byte-array java.nio.ByteBuffer/wrap .asIntBuffer .get) byte-array))

(defmethod print-method Sha256 [^Sha256 sha w]
  (.write w "#sha256 \"")
  (.write w (-> sha .-ba h/to-base64))
  (.write w "\""))

(defn sha256? [x]
  (instance? Sha256 x))

;; these utilities are used by PostgreSQL driver to store shas as 2 uuids

(defn sha256-to-uuids [sha]
  (let [bb (-> sha h/as-byte-array ByteBuffer/wrap)]
    [(UUID. (.getLong bb) (.getLong bb))
     (UUID. (.getLong bb) (.getLong bb))]))

(defn uuids-to-sha256 [uuid1 uuid2]
  (let [bb (ByteBuffer/allocate 32)]
    (doto bb
      (.putLong (.getMostSignificantBits uuid1))
      (.putLong (.getLeastSignificantBits uuid1))
      (.putLong (.getMostSignificantBits uuid2))
      (.putLong (.getLeastSignificantBits uuid2)))
    (-> bb .array wrap-sha-256)))
