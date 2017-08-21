(ns bits.transport.http-client
  (:require [bits.host :as h]
            [bits.middleware :as m]
            [bits.transport :as t]

            [clojure.core.async :as cca]
            [org.httpkit.client  :as http]))

(defn post-command [url command & [callback]]
  (http/request {:method     :post,
                 :url        url
                 :as         :text,
                 :multipart  [{:name         "bits_command",
                               :content      (h/pr-str-edn command)}]}
                callback))

(defn parse-response [{:keys [status body error]}]
  (if (h/error? error)
    [error]
    (if (t/http-success? status)
      (h/wrap-error vector h/parse-edn-string body)
      [(ex-info "Unexpected HTTP status" {:status status})])))

(defn wrap-post-client
  "Simple http backend which transfer data as post requests
   with data in bits_command parameter"
  [server commands uri]
  (m/wrap-server-command
   server commands m/command-handler
   (fn [command _]
     (let [return (m/make-command-output command 1)]
       (post-command (str uri) (m/cleanup-command command)
                     #(->> % parse-response (cca/onto-chan return)))
       return))))
