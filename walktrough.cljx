(ns cryptelo.walktrough)

(require '[cryptelo.crypt :as crypt])
(require '[cryptelo.crypt.api :as crypt.api])
(require '[cryptelo.crypt.toolbox :as crypt.tbx])
(require '[cryptelo.host :as host])

(def alice     (crypt/random-private-key))
;;#cryptelo.crypt.api.ECPrivateKey{
;;  :type "P_384",
;;  :private #bighex "16d9e8d27a8d35b8a5ece067d1cd01f45dd23ebd8cd9a3783fed7affa7a8868786c2054d984afdc4f1ee7f9eaa577e12",
;;  :pub-x #bighex "6d72a8cc71de417b6e59efbb24216713cf4100aef284f455ce567cd57def57169646a510f49ab83a4d858d5dd96a69b0",
;;  :pub-y #bighex "0b976c6e2b4cae22067b4f0a76a682b71923ff85d4b34fd61f571dd0f56c33bc98c19276265a5c18b74201f05cbcf4f3"}

(def alice-pub (crypt.api/to-public alice))
;; #cryptelo.crypt.api.ECPublicKey{
;;   :type "P_384",
;;   :pub-x #bighex "6d72a8cc71de417b6e59efbb24216713cf4100aef284f455ce567cd57def57169646a510f49ab83a4d858d5dd96a69b0",
;;   :pub-y #bighex "0b976c6e2b4cae22067b4f0a76a682b71923ff85d4b34fd61f571dd0f56c33bc98c19276265a5c18b74201f05cbcf4f3"}
nil

(def bob       (crypt/random-private-key))
;; #cryptelo.crypt.api.ECPrivateKey{
;;   :type "P_384",
;;   :private #bighex "86f236cb8b225431b6e503a31184cabe00c85c9e213df04fa7bc6bcc794f2d70a712ae10167d2c0051aa81bd61ab69",
;;   :pub-x #bighex "c1c95736fd425176fdf850b605749a45c7fc8af7e8eabd173c1e732ecc0f8b2d0ea47312a7295471932a97b17e2ffc2d", :pub-y #bighex "016af5e29efca7afd07b0563678f102feaceca388d2cf8d61f4fc5be129bad5bc6fd170d03192a0c9a064e29f6a887ca"}

(def bob-pub   (crypt.api/to-public bob))
;; #cryptelo.crypt.api.ECPublicKey{
;;   :type "P_384",
;;   :pub-x #bighex "c1c95736fd425176fdf850b605749a45c7fc8af7e8eabd173c1e732ecc0f8b2d0ea47312a7295471932a97b17e2ffc2d",
;;   :pub-y #bighex "016af5e29efca7afd07b0563678f102feaceca388d2cf8d61f4fc5be129bad5bc6fd170d03192a0c9a064e29f6a887ca"}


(def aes-key   (crypt.tbx/random-aes-key))
;; #cryptelo.crypt.api.AESKey{:key #base64 "ihOurEjIP7hkRAY/tnPY43EWpI/b87HQipYZtrAYwDg=",
;;                            :iv nil}

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; AES
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def random-data  (crypt.tbx/random-bytes 73))
;; #base64 "HOBGmFP2Eo0AGMpFn4zGEBoi7fRfkofdvGoS3j75HqPbGvtVdIDOF/pUiM+UQI90KToP6hQeiu3KP7f6jJEpF8D0tgweFe4/DQ=="

(def aes-encryptor (crypt/encryptor aes-key))
(def aes-decryptor (crypt/decryptor aes-key))

(def ciphertext    (aes-encryptor   random-data))
;; #base64 "AC2dY3uqA3aCS6iUunnN7Lx3S/c+ci2C9RU7h4tZPJutfBmyuokMlQdidebGnttKYtXeBFBt4sk/MPYpcCz6CJqnt4wofAYu2mQ8dICW7A0="

(def plaintext     (aes-decryptor   ciphertext))
;; #base64 "HOBGmFP2Eo0AGMpFn4zGEBoi7fRfkofdvGoS3j75HqPbGvtVdIDOF/pUiM+UQI90KToP6hQeiu3KP7f6jJEpF8D0tgweFe4/DQ=="

(host/bytes= plaintext random-data)
;; true

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; EC operations
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; The basis for Diffie-Helman over EC keys

(def shared-sec-alice (crypt/ec-derive-priv alice bob-pub))
;; #base64 "k3URh9yxk3rBczqcKxAa6obMdSZ9gr5tJcchWJf+vJ2h1xqR1vEJVLcjtxZkLIUf"
(def shared-sec-bob   (crypt/ec-derive-priv bob   alice-pub))
;; #base64 "k3URh9yxk3rBczqcKxAa6obMdSZ9gr5tJcchWJf+vJ2h1xqR1vEJVLcjtxZkLIUf"

(host/bytes= shared-sec-alice shared-sec-bob)
;; true

;; Real ECIES scheme hashes produced key from DH
;; encryption is then done using AES-256
(def dh-alice         (crypt/ec-dh-priv alice bob-pub))
;; #js [41 206 51 209 106 25 44 234 38 183 34 76 178 19 92 228 245 18 88 232 250 180 205 41 51 16 27 183 172 210 214 200]

(def dh-bob           (crypt/ec-dh-priv bob   alice-pub))
;; #js [41 206 51 209 106 25 44 234 38 183 34 76 178 19 92 228 245 18 88 232 250 180 205 41 51 16 27 183 172 210 214 200]


(def alice-signator    (crypt/signator alice))

(def signature         (alice-signator random-data))
;; #cryptelo.crypt.api.ECSignature{
;;   :r #bighex "1db567dab88285a6198c0acb688b133d09b7f8f86d76505ba6c51d7c87e71530cebe1617cf1f86ce3e6f040c9561beb2",
;;   :s #bighex "1c51cf613b1edc95e28ff3fccfac07876e14323539066ca4994860857f15cc4eda0b294e6c7fd55e3bc34e5a8899f007"}
(def alice-verificator (crypt/verificator alice-pub signature))
(def verified?         (alice-verificator random-data))
;; true


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; PBKDF2 key derivation
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def salt        (crypt.tbx/random-bytes 16))
;; #base64 "M86KExvkSbmF2Hx3J9HJEw=="

;;                                                 password      # iterations  salt
(def derived-key (crypt/derive-key-pbkdf2-sha256 "AliceHatesBob" (* 40 1000)   salt))
;; #js [189 88 183 134 165 219 200 78 207 140 209 45 182 31 90 47 52 9 119 47 192 249 148 125 205 186 15 54 235 219 158 231]
