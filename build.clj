(ns build
  (:require [clojure.tools.build.api :as b]
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

(defn clean [_]
  (b/delete {:path "target"}))

(defn javac [_]
  (b/javac {:src-dirs ["src/java"]
            :class-dir class-dir
            :basis @basis
            :javac-opts ["--release" "22"]}))

(defn shim
  "Build the enso_quiche JNI shim into target/native/<os>-<arch>/. Callers
  that don't need HTTP/3 can skip this."
  [_]
  (sh "make -C native/enso_quiche"))

(defn jar [_]
  (javac nil)
  (b/delete {:path jar-class-dir})
  (b/copy-dir {:src-dirs [class-dir]
               :target-dir jar-class-dir})
  ;; Bundle the JNI shim per platform under META-INF/native/<os>-<arch>/.
  ;; Quiche.java's loader extracts + System.load at runtime.
  (when (.exists (java.io.File. "target/native"))
    (b/copy-dir {:src-dirs ["target/native"]
                 :target-dir (str jar-class-dir "/META-INF/native")}))
  (b/write-pom {:class-dir jar-class-dir
                :lib lib
                :version version
                :basis @basis
                :src-dirs ["src/clj"]
                :pom-data [[:description "Zero-dep , near 0-alloc, High Performance Ring adapter for Clojure"]
                           [:url "https://github.com/mpenet/enso"]
                           [:licenses
                            [:license
                             [:name "Mozilla Public License 2.0"]
                             [:url "https://www.mozilla.org/en-US/MPL/2.0/"]]]
                           [:scm
                            [:url "https://github.com/mpenet/enso"]
                            [:connection "scm:git:git://github.com/mpenet/enso.git"]
                            [:developerConnection "scm:git:ssh://git@github.com/mpenet/enso.git"]]]})
  (b/copy-dir {:src-dirs ["src/clj"]
               :target-dir jar-class-dir})
  (b/jar {:class-dir jar-class-dir
          :jar-file jar-file}))

(defn install [_]
  (jar nil)
  (b/install {:basis @basis
              :lib lib
              :version version
              :jar-file jar-file
              :class-dir jar-class-dir}))

(defn deploy
  [opts]
  (dd/deploy {:artifact jar-file
              :pom-file (format "%s/META-INF/maven/%s/pom.xml"
                                jar-class-dir
                                lib)
              :installer :remote
              :sign-releases? false})
  opts)

(defn- sh
  [& cmds]
  (doseq [cmd cmds]
    (p/process {:command-args ["sh" "-c" cmd]})))

(defn tag
  [opts]
  (sh
   (format "git tag -a \"%s\" --no-sign -m \"Release %s\"" version version)
   "git pull"
   "git push --follow-tags")
  opts)

#_{:clj-kondo/ignore [:clojure-lsp/unused-public-var]}
(defn release
  [opts]
  (-> opts
      clean
      jar
      deploy
      tag))
