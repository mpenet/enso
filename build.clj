(ns build
  (:require [clojure.java.shell :as shell]
            [clojure.string]
            [clojure.tools.build.api :as b]
            [clojure.tools.build.tasks.process :as p]))

(def lib 'com.s-exp/enso)
;; CI tag-driven releases set ENSO_VERSION from `github.ref_name` with
;; the leading `v` stripped, so e.g. tag `v1.0.0-alpha29` publishes
;; `1.0.0-alpha29` on Clojars regardless of the local commit count.
;; Local dev falls back to a git-count-based auto version.
(def version (or (System/getenv "ENSO_VERSION")
                 (format "1.0.0-alpha%s" (b/git-count-revs nil))))
(def class-dir "target/classes")
;; Jar contents are staged separately from `class-dir`: target/classes
;; is on the dev/test/bench classpaths, and copying src/clj into it
;; leaves stale .clj snapshots that shadow the live sources.
(def jar-class-dir "target/jar-classes")
(def basis (delay (b/create-basis {:project "deps.edn"})))
(def target-dir "target")

(defn- sh
  [& cmds]
  (doseq [cmd cmds]
    (p/process {:command-args ["sh" "-c" cmd]})))

(defn clean [_]
  (b/delete {:path "target"}))

(defn javac [_]
  (b/javac {:src-dirs ["src/java"]
            :class-dir class-dir
            :basis @basis
            :javac-opts ["--release" "21"]}))

(defn javac-bench
  "Compile bench-only Java sources (Netty + Jetty h3 servers for task #95).
  Uses the bench alias basis so Netty/Jetty deps are on the compile path."
  [_]
  (javac nil)
  (b/javac {:src-dirs ["bench/java"]
            :class-dir class-dir
            :basis (b/create-basis {:project "deps.edn" :aliases [:bench]})
            :javac-opts ["--release" "21"]}))

(defn shim
  "Build the enso_quiche JNI shim into target/native/<os>-<arch>/. Callers
  that don't need HTTP/3 can skip this."
  [_]
  (sh "make -C native/enso_quiche"))

;; --- Jar assembly ----------------------------------------------------------
;;
;; We publish four flavors of the artifact:
;;
;;   enso-<v>.jar                — core (Java + Clojure, NO native shim).
;;                                 Users bring their own libquiche (or add a
;;                                 platform classifier jar).
;;   enso-<v>-<os>-<arch>.jar    — per-classifier native jar. Contains only
;;                                 META-INF/native/<os>-<arch>/libenso_quiche.
;;                                 Netty-style: pull the one you need.
;;   enso-<v>-all.jar            — fat jar with the core + all four static
;;                                 shims. Ships zero-install for anyone who
;;                                 doesn't want to think about classifiers.
;;
;; The `jar` task is the plain "whatever's under target/native/ gets bundled"
;; behaviour we've always had — it's what dev use of `clj -T:build jar` will
;; keep producing. `jar-all`, `jar-core`, and `jar-classifier` are the
;; release-time helpers.

(def jar-core-file (format "target/%s-%s.jar" (name lib) version))
(def jar-all-file (format "target/%s-%s-all.jar" (name lib) version))
(defn- jar-classifier-file [classifier]
  (format "target/%s-%s-%s.jar" (name lib) version classifier))

(defn- write-pom-into
  "Emit the shared pom.xml + attribution files into a jar staging dir."
  [staging]
  (b/write-pom {:class-dir staging
                :lib lib
                :version version
                :basis @basis
                :src-dirs ["src/clj"]
                :pom-data [[:description "Zero-dep, near 0-alloc, High Performance Ring adapter for Clojure"]
                           [:url "https://github.com/mpenet/enso"]
                           [:licenses
                            [:license
                             [:name "Mozilla Public License 2.0"]
                             [:url "https://www.mozilla.org/en-US/MPL/2.0/"]]]
                           [:scm
                            [:url "https://github.com/mpenet/enso"]
                            [:connection "scm:git:git://github.com/mpenet/enso.git"]
                            [:developerConnection "scm:git:ssh://git@github.com/mpenet/enso.git"]]]})
  ;; NOTICE gets bundled at META-INF/NOTICE so downstream tools that
  ;; aggregate ATTRIBUTION files pick up the quiche + BoringSSL notice.
  (let [notice (java.io.File. "NOTICE")]
    (when (.exists notice)
      (let [dst (java.io.File. (str staging "/META-INF/NOTICE"))]
        (.mkdirs (.getParentFile dst))
        (java.nio.file.Files/copy
         (.toPath notice) (.toPath dst)
         ^"[Ljava.nio.file.CopyOption;"
         (into-array java.nio.file.CopyOption
                     [java.nio.file.StandardCopyOption/REPLACE_EXISTING]))))))

(defn jar
  "Legacy / dev jar. Contents mirror what's staged under target/native/ at
  call time — dynamic-linked shim if you `make -C native/enso_quiche`,
  none if `target/native` is absent. For release flavors use
  `jar-core`, `jar-all`, `jar-classifier`."
  [_]
  (javac nil)
  (b/delete {:path jar-class-dir})
  (b/copy-dir {:src-dirs [class-dir]
               :target-dir jar-class-dir})
  (when (.exists (java.io.File. "target/native"))
    (b/copy-dir {:src-dirs ["target/native"]
                 :target-dir (str jar-class-dir "/META-INF/native")}))
  (write-pom-into jar-class-dir)
  (b/copy-dir {:src-dirs ["src/clj"]
               :target-dir jar-class-dir})
  (b/jar {:class-dir jar-class-dir
          :jar-file jar-core-file}))

(defn- stage-core
  "Common jar staging: Java classes + Clojure sources + pom. Leaves
  target/native alone — caller decides which shims (if any) to add."
  [staging]
  (javac nil)
  (b/delete {:path staging})
  (b/copy-dir {:src-dirs [class-dir]
               :target-dir staging})
  (write-pom-into staging)
  (b/copy-dir {:src-dirs ["src/clj"]
               :target-dir staging}))

(defn jar-core
  "Core artifact: no native shim inside. Consumers who want HTTP/3 add a
  matching classifier jar (see `jar-classifier`) or the `-all` fat jar."
  [_]
  (let [staging "target/jar-core-classes"]
    (stage-core staging)
    (b/jar {:class-dir staging
            :jar-file jar-core-file})
    {:jar-file jar-core-file}))

(defn jar-classifier
  "Per-platform native jar. Pass `:classifier \"darwin-arm64\"` (or
  `linux-amd64`, etc.). Only META-INF/native/<classifier>/libenso_quiche.*
  and the pom go in — no Java classes. Small (~3-4 MB per platform)
  because it ships just the statically-linked shim."
  [{:keys [classifier]}]
  (when-not classifier (throw (ex-info ":classifier required" {})))
  (let [staging (str "target/jar-" classifier "-classes")
        src-dir (format "target/native/%s" classifier)]
    (when-not (.exists (java.io.File. src-dir))
      (throw (ex-info (str "no shim at " src-dir) {:classifier classifier})))
    (b/delete {:path staging})
    (b/copy-dir {:src-dirs [src-dir]
                 :target-dir (str staging "/META-INF/native/" classifier)})
    (write-pom-into staging)
    (let [out (jar-classifier-file classifier)]
      (b/jar {:class-dir staging :jar-file out})
      {:jar-file out :classifier classifier})))

(defn jar-all
  "Fat jar with core + every shim present under target/native/. Assumes
  the release CI has staged all four platform shims before calling."
  [_]
  (let [staging "target/jar-all-classes"]
    (stage-core staging)
    (when (.exists (java.io.File. "target/native"))
      (b/copy-dir {:src-dirs ["target/native"]
                   :target-dir (str staging "/META-INF/native")}))
    (b/jar {:class-dir staging
            :jar-file jar-all-file})
    {:jar-file jar-all-file}))

(defn install [_]
  (jar nil)
  (b/install {:basis @basis
              :lib lib
              :version version
              :jar-file jar-core-file
              :class-dir jar-class-dir}))

(def ^:private clojars-url "https://clojars.org/repo")
(def ^:private clojars-repo-id "clojars")

(defn deploy-jars
  "Publish core + every per-platform classifier + fat jar to Clojars in
  a single atomic `mvn deploy:deploy-file` call. Clojars rejects any
  redeploy against an existing version, so all sidecar artifacts have
  to be attached to the same upload as the main jar. `-Dfiles`,
  `-Dclassifiers`, `-Dtypes` are comma-separated parallel lists.
  Assumes CI has already run `jar-core`, `jar-classifier` per platform,
  and `jar-all`. POM comes from the core-jar staging dir. Credentials
  read from ~/.m2/settings.xml — CI writes it from repo secrets before
  invoking."
  [opts]
  (let [pom (format "target/jar-core-classes/META-INF/maven/%s/pom.xml" lib)
        ;; Preflight: Clojars rejects any redeploy against an existing
        ;; version. Half-deployed states (e.g. from a CI flake) wedge the
        ;; tag forever. HEAD the core pom URL; abort with a clear message
        ;; before we upload anything.
        pom-url (format "%s/%s/%s/%s-%s.pom"
                        clojars-url
                        (clojure.string/replace (namespace lib) "." "/")
                        (name lib) (name lib) version)
        {:keys [exit out]} (shell/sh "curl" "-s" "-o" "/dev/null"
                                     "-w" "%{http_code}"
                                     "-I" pom-url)]
    (when (and (zero? exit) (= "200" (clojure.string/trim (str out))))
      (throw (ex-info (str "version " version
                           " already published at " pom-url
                           " — bump ENSO_VERSION or delete the artifact on Clojars")
                      {:version version :url pom-url})))
    (when-not (.exists (java.io.File. pom))
      (throw (ex-info (str "missing " pom " — run jar-core first") {:pom pom})))
    (when-not (.exists (java.io.File. jar-core-file))
      (throw (ex-info (str "missing " jar-core-file) {})))
    ;; Sidecar artifacts: per-platform classifier jars only. The fat
    ;; jar (`jar-all`, ~18 MB) exceeds Clojars' per-file limit and gets
    ;; a 413 — users needing multi-platform declare multiple classifier
    ;; coords instead (netty-style). `jar-all` still builds locally
    ;; for uber-jar-style deploys.
    (let [sidecars (->> (some-> (java.io.File. "target/native")
                                .listFiles seq)
                        (filter #(.isDirectory ^java.io.File %))
                        (map #(vector (.getName ^java.io.File %)
                                      (jar-classifier-file (.getName ^java.io.File %))))
                        (filter (fn [[_ j]] (.exists (java.io.File. ^String j))))
                        vec)
          files (clojure.string/join "," (map second sidecars))
          classifiers (clojure.string/join "," (map first sidecars))
          types (clojure.string/join "," (repeat (count sidecars) "jar"))
          args (cond-> ["mvn" "-B" "deploy:deploy-file"
                        (str "-Durl=" clojars-url)
                        (str "-DrepositoryId=" clojars-repo-id)
                        (str "-Dfile=" jar-core-file)
                        (str "-DpomFile=" pom)
                        "-DgeneratePom=false"]
                 (seq sidecars) (into [(str "-Dfiles=" files)
                                       (str "-Dclassifiers=" classifiers)
                                       (str "-Dtypes=" types)]))
          {:keys [exit out err]} (apply shell/sh args)]
      (println "deploying core +" (count sidecars) "sidecars:"
               (mapv first sidecars))
      (println out)
      (when-not (zero? exit)
        (println err)
        (throw (ex-info "mvn deploy failed" {:exit exit})))
      (println "deployed" jar-core-file
               "+" (count sidecars) "classifier jars")))
  opts)

(defn tag
  "Create annotated tag matching the computed `version`, then push it. The
  release CI workflow (`.github/workflows/release.yml`) triggers on tag
  push — it builds shims, assembles jars, and publishes core +
  every classifier + fat jar to Clojars."
  [opts]
  (sh
   (format "git tag -a \"v%s\" --no-sign -m \"Release %s\"" version version)
   "git pull"
   "git push --follow-tags")
  opts)

#_{:clj-kondo/ignore [:clojure-lsp/unused-public-var]}
(defn release
  "Local trigger for a release: tag + push. All build/publish work happens
  in CI once the tag lands. Aborts on a dirty tree — surprise commits in
  a release build would be bad."
  [opts]
  (let [{:keys [exit out]} (shell/sh "git" "status" "--porcelain")]
    (when-not (zero? exit)
      (throw (ex-info "git status failed" {})))
    (when (seq (clojure.string/trim out))
      (throw (ex-info "working tree dirty — commit or stash before releasing"
                      {:status out}))))
  (tag opts))
