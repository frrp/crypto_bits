(ns bits.transport.curl-client
  "Server client using curl (just for fun)"
  (:require [bits.host :as h]
            [bits.middleware :as m]
            [bits.middleware.client :as client]
            [bits.transport :as t]

            [bits.async :refer [go-with-channel]]
            [clojure.core.async :as cca]
            [clojure.java.shell :as shell]))

(defn post-command [uri command]
  (let [ret (shell/sh "curl" "-X" "POST" "--silent" "-4"
                      "--form" "bits_command=@-;type=application/edn"
                      (str uri)
                      :in (h/pr-str-edn command))]
    ret))

(defn parse-response [{:keys [exit out err] :as ret}]
  (if (not= exit 0)
    [(ex-info "curl call was not success" ret)]
    (h/wrap-error vector h/parse-edn-string out)))

(defn curl-client [uri]
  (comp parse-response (partial post-command (str uri)) m/cleanup-command))

(defn wrap-curl-client
  [client commands uri]
  (let [make-request (curl-client uri)]
    (m/wrap-server-command
     client commands
     (fn [_]
       (fn [command]
         (go-with-channel [return (m/make-command-output command)]
           (cca/onto-chan return (make-request command))))))))
