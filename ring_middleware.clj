(ns bits.transport.ring-middleware
  (:require [bits.host :as h]
            [bits.async :as a]
            [bits.middleware :as m]
            [bits.middleware.server :as server]

            [ring.util.response :as response]

            ;; server setup
            ring.middleware.params
            ring.middleware.nested-params
            ring.middleware.keyword-params
            ring.middleware.multipart-params)

  (:import [java.net ServerSocket]))

(defn handle-request-sync
  "Dispatches command comming as bits_command parameter.
   Commands are handled synchronously.

   Prerequisite: m/wrap-errors-to-channel"
  [server req]
  (-> (try
        (if-let [command (or (some-> req :params :bits_command h/parse-edn-string)
                             (:edn-params req))]
          (let [command (-> (merge server command)
                            (assoc m/command-make-output m/default-make-output))]
            (a/<<!! ((m/server-dispatcher server) (merge server command))))
          [(ex-info "Empty command" {})])
        (catch Throwable e [e]))

      h/pr-str-edn
      response/response
      (response/content-type "application/edn")
      (response/charset "utf-8")))

(defn wrap-handle-request-sync [server]
  (fn [req]
    (handle-request-sync server req)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;      Server
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def http-port 54321)

(defn free-port []
  (with-open [s (ServerSocket. 0)]
    (.getLocalPort s)))

(defn wrap-allow-cors [orig]
  (fn [req]
    (let [origin (get-in req [:headers "origin"])]
      (-> (orig req)
          (assoc-in [:headers "Access-Control-Allow-Origin"] origin)
          (assoc-in [:headers "Access-Control-Allow-Credentials"] "true")
          (assoc-in [:headers "Access-Control-Allow-Methods"] "PUT, POST")))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;	debugging utilities
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn create-api-server
  "Server dedicated only to debugging"
  [handler & [port]]
  (require 'ring.adapter.jetty9)
  (-> handler
      ring.middleware.keyword-params/wrap-keyword-params
      ring.middleware.nested-params/wrap-nested-params
      ring.middleware.params/wrap-params
      (ring.middleware.multipart-params/wrap-multipart-params
       {:store (comp slurp :stream)})

      ((resolve 'ring.adapter.jetty9/run-jetty)   {:port (or port (free-port))
                                                   :host "localhost"
                                                   :join? false})))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;;	Stage 260 - translate http request to middleware
;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn wrap-260-server-to-ring-handler
  "Takes server and returns ring handler"
  [server]
  (cond-> server
    true
    (m/wrap-server-command (constantly true) m/errors-to-output-channel)

    true
    wrap-handle-request-sync

    (server/logging? server)
    (m/log-to-atom m/log :server-240-http)))
