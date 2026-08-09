;; quic-interop-runner endpoint — serves files from /www over HTTP/3.
;;
;; Invoked from run_endpoint.sh with args: TESTCASE CERT KEY WWWROOT.
;; The Ring handler resolves the request path against WWWROOT and streams
;; back the file. Matches the runner contract in bench/quic-interop-runner/
;; repo/quic.md: transfer + handshake + http3 test cases all just download
;; files from the server.

(require '[s-exp.enso :as enso])

(defn -main [& _]
  (let [args *command-line-args*
        testcase (nth args 0)
        cert (nth args 1)
        key (nth args 2)
        wwwroot (nth args 3)
        srv (enso/run-server
             (fn [{:keys [uri]}]
               (let [safe-path (subs (or uri "/") 1)
                     f (java.io.File. wwwroot safe-path)]
                 (if (.isFile f)
                   {:status 200
                    :headers {"content-type" "application/octet-stream"
                              "content-length" (str (.length f))}
                    :body f}
                   {:status 404
                    :headers {"content-type" "text/plain"}
                    :body "not found"})))
             {:port 0
              :http3 true
              :http3-port 443
              :http3-cert-path cert
              :http3-key-path key})]
    (println "enso h3 up: testcase=" testcase " www=" wwwroot)
    (.addShutdownHook (Runtime/getRuntime)
                      (Thread. #(enso/stop srv)))
    @(promise)))

(-main)
