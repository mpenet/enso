(ns build
  (:require [clojure.java.shell :as shell]
            [clojure.string]
            [clojure.tools.build.api :as b]
            [clojure.tools.build.tasks.process :as p]
            [deps-deploy.deps-deploy :as dd]))

(def lib 'com.s-exp/enso)
(def version (format "1.0.0-alpha%s" (b/git-count-revs nil)))
(def class-dir "target/classes")
;; Jar contents are staged separately from `class-dir`: target/classes
;; is on the dev/test/bench classpaths, and copying src/clj into it
;; leaves stale .clj snapshots that shadow the live sources.
(def jar-class-dir "target/jar-classes")
(def jar-file (format "target/%s-%s.jar" (name lib) version))
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
            :javac-opts ["--release" "22"]}))

(defn javac-bench
  "Compile bench-only Java sources (Netty + Jetty h3 servers for task #95).
  Uses the bench alias basis so Netty/Jetty deps are on the compile path."
  [_]
  (javac nil)
  (b/javac {:src-dirs ["bench/java"]
            :class-dir class-dir
            :basis (b/create-basis {:project "deps.edn" :aliases [:bench]})
            :javac-opts ["--release" "22"]}))

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
(def jar-all-file  (format "target/%s-%s-all.jar" (name lib) version))
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
          :jar-file jar-file}))

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
              :jar-file jar-file
              :class-dir jar-class-dir}))

(defn deploy
  "Legacy — publishes the dev jar produced by `jar`. Kept for local one-off
  publishes. Release CI uses `deploy-core` against a pre-built core jar."
  [opts]
  (dd/deploy {:artifact jar-file
              :pom-file (format "%s/META-INF/maven/%s/pom.xml"
                                jar-class-dir
                                lib)
              :installer :remote
              :sign-releases? false})
  opts)

(def ^:private clojars-url "https://clojars.org/repo")
(def ^:private clojars-repo-id "clojars")

(defn- mvn-deploy!
  "Shells out to `mvn deploy:deploy-file` for one artifact. Uses the
  core-jar POM as authoritative — every classifier + fat artifact is
  the same GAV, differentiated only by the classifier metadata Aether
  attaches at deploy time. Credentials expected in ~/.m2/settings.xml
  under server id `clojars`."
  [{:keys [jar classifier pom]}]
  (let [args (cond-> ["mvn" "-q" "-B" "deploy:deploy-file"
                      (str "-Durl=" clojars-url)
                      (str "-DrepositoryId=" clojars-repo-id)
                      (str "-Dfile=" jar)
                      (str "-DpomFile=" pom)
                      "-DgeneratePom=false"]
               classifier (conj (str "-Dclassifier=" classifier)))
        {:keys [exit out err]} (apply shell/sh args)]
    (when-not (zero? exit)
      (throw (ex-info (str "mvn deploy failed for " jar)
                      {:exit exit :out out :err err})))
    (println "deployed" jar (when classifier (str "(classifier=" classifier ")")))))

(defn deploy-jars
  "Publish every jar under target/ to Clojars: core (no classifier),
  each per-platform classifier jar, and the fat jar as classifier `all`.
  Assumes CI has already run `jar-core`, `jar-classifier` per platform,
  and `jar-all`. POM comes from the core-jar staging dir. Credentials
  read from ~/.m2/settings.xml — CI writes it from repo secrets before
  invoking."
  [opts]
  (let [pom (format "target/jar-core-classes/META-INF/maven/%s/pom.xml" lib)]
    (when-not (.exists (java.io.File. pom))
      (throw (ex-info (str "missing " pom " — run jar-core first") {:pom pom})))
    ;; Core: no classifier.
    (when-not (.exists (java.io.File. jar-core-file))
      (throw (ex-info (str "missing " jar-core-file) {})))
    (mvn-deploy! {:jar jar-core-file :pom pom})
    ;; Per-platform classifier jars — walk target/native/ for the list.
    (let [native-dir (java.io.File. "target/native")]
      (when (.exists native-dir)
        (doseq [d (.listFiles native-dir)
                :when (.isDirectory d)]
          (let [classifier (.getName d)
                jar (jar-classifier-file classifier)]
            (when (.exists (java.io.File. jar))
              (mvn-deploy! {:jar jar :classifier classifier :pom pom}))))))
    ;; Fat jar → classifier `all`.
    (when (.exists (java.io.File. jar-all-file))
      (mvn-deploy! {:jar jar-all-file :classifier "all" :pom pom})))
  opts)

(defn tag
  "Create annotated tag matching the computed `version`, then push it. The
  release CI workflow (`.github/workflows/release.yml`) triggers on tag
  push — it builds shims, assembles jars, attaches to GitHub release,
  and publishes core + every classifier + fat jar to Clojars."
  [opts]
  (sh
   (format "git tag -a \"%s\" --no-sign -m \"Release %s\"" version version)
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
