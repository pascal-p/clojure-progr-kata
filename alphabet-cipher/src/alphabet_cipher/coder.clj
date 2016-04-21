(ns alphabet-cipher.coder)

;;
;; Helper functions
;; 

;; rotation does not make sense on set
(defn aux-rot1 [s]
  "
rotate a collection by one element, try preserving the original collection type
rotating a set is meaningless, as a set has no implicit order
"
  (let [f (first s)
        r (rest s)
        ns (concat r [f])]
    (cond (vector? s) (vec ns)
;;          (set? s) (apply hash-set ns)
          (list? s) ns
          (map? s) (apply hash-map ns)
          :else
          ns)))

(defn rot1 [a]
  (if (coll? a) (aux-rot1 a)
      ()))

(defn rot
  ([a] (rot1 a))
  ([a n] (if (coll? a) (loop [res a x n]
                         (if (zero? x)
                           res
                           (recur (aux-rot1 res) (dec x))))
             ()))
  )

;; generate the chart (a sorted map)
;;
;; 1.a - gen-vect-char-range: generate a vector of keys (from start to end)
;; ex. (gen-vect-char-range \a \z)) ==>
;;     [:a :b :c :d :e :f :g :h :i :j :k :l :m :n :o :p :q :r :s :t :u :v :w :x :y :z]
;;
(defn gen-vect-char-range
  "expect a character interval: start and end"
  [start end]
  (into [] (map char (range (int start) (inc (int end))))))

;;
;; 1.b - gen-chart generates the sorted map
;;
;; (gen-chart)
;; {:a [:a :b :c :d :e :f :g :h :i :j :k :l :m :n :o :p :q :r :s :t :u :v :w :x :y :z],
;;  :b [:b :c :d :e :f :g :h :i :j :k :l :m :n :o :p :q :r :s :t :u :v :w :x :y :z :a],
;;  :c [:c :d :e :f :g :h :i :j :k :l :m :n :o :p :q :r :s :t :u :v :w :x :y :z :a :b],
;;  :d [:d :e :f :g :h :i :j :k :l :m :n :o :p :q :r :s :t :u :v :w :x :y :z :a :b :c],
;;  ...
;;  :y [:y :z :a :b :c :d :e :f :g :h :i :j :k :l :m :n :o :p :q :r :s :t :u :v :w :x],
;;  :z [:z :a :b :c :d :e :f :g :h :i :j :k :l :m :n :o :p :q :r :s :t :u :v :w :x :y]}
;;
(defn gen-chart
  []
  (let [kvect (map keyword (map str (gen-vect-char-range \a \z)))]
    (into
     (sorted-map)
     (reduce
      (fn [a-map key]
        (assoc a-map key (vec (rot kvect (- (apply int (name key)) (int \a))))))
      {}
      kvect))))

;; prep :: msg ==> (len msg') 
;;
;; suppress all spaces (at the start, within and at the end) in a given message
;; also compute the length of the transformed message
;; (prep " une phrase \n  sans   espaces ")
;; ==> (20 "unephrasesansespaces")
;;
(defn strip-space
  [msg]
  (clojure.string/join "" (clojure.string/split msg #"\s+")))

(defn trim-n-lc
  [msg]
  (clojure.string/lower-case (clojure.string/trim msg)))
  
(defn prep
  [msg]
  (let [nmsg (trim-n-lc (strip-space msg))
        len (count nmsg)]
    (list len nmsg)))

;; from a given symbol, returns its (ordinal) index
;; ex. (to-index "secret" 1) --> 4
;;     because the character at index 1 in secret is e and (- (int \e) (int \a)) is 4
(defn to-index
  [key ix]
  (let [len (count key)
        jx (mod ix len)]
    (- (int (get key jx)) (int \a)))
  )

;; helper function,
;; keyword-at :: extracts char at position ix in string msg, transfrom into a keyword
;; which is then returned
;; (keyword-at "jesuisunephrase" 15)
;; ==> nil
;; keyword-at "jesuisunephrase" 14)
;; :e
(defn keyword-at
  [msg ix]
  (if (or (< ix 0) (>= ix (count msg))) nil
      (keyword (str (get msg ix)))))

;;
;; (find-char my-chart "secretkey" "monmessageacoder" 10)
;; ==> "w"
;;
(defn find-char
  [chart msg cmsg ix]
  (let [len (count msg)
        jx (if (>= ix len) (mod ix len) ix)]
    (str
     (char
      (+ (.indexOf (chart (keyword-at msg jx)) (keyword-at cmsg ix))
         (int \a))))))


;;
;; (is-prefix? "secret" "sec" "k")
;; => false
;; (is-prefix? "secret" "sec" "r")
;; => true
;;
(defn is-prefix?
  [sec-key prefix ch]
  (let [ rexp (re-pattern (str "^" prefix ch)) ]
    (not
     (nil?
      (re-find rexp sec-key)))
    ))


(def my-chart (gen-chart))
  
;;
;; Main entry points
;;

;;
;; (encode "secretkey" "jesuisunmessageenclairquidoitrestersecret")
;; ==> "biulmlerkwwurkxoradekiunshmaxtvwmovqwgtvx"
(defn encode
  [sec-key msg]
  (let [ [len msg] (prep msg) ]
    (reduce
     (fn [ciph-msg ix]
       (str ciph-msg (name ((my-chart (keyword-at msg ix)) (to-index sec-key ix)))))
       ""
       (range 0 len)))
  )

;;
;; (decode "secretkey" "biulmlerkwwurkxoradekiunshmaxtvwmovqwgtvx")
;; ===> "jesuisunmessageenclairquidoitrestersecret"
;;
(defn decode
  [sec-key msg]
  (let [ [len msg] (prep msg)
         len-sk (count sec-key)]
     (reduce
      (fn [clear-msg ix]
        (str clear-msg (find-char my-chart sec-key msg ix)))
      ""
      (range 0 len)))
  )


;;
;; (decipher "biulmlerkwwurkxoradekiunshmaxtvwmovqwgtvx" "jesuisunmessageenclairquidoitrestersecret")
;; ==> "secretkey"
;;
(defn decipher [cipher msg]
  (let [ [len cipher] (prep cipher)
         [_ msg] (prep msg)
         limit (dec len) ]
    (loop [ix 0 prefix "" sec-key ""]
      (cond
        (> ix limit) sec-key
        (and (not (empty? sec-key)) (= prefix sec-key)) sec-key
        :else
        (let [ch (find-char my-chart msg cipher ix)]
          (if (is-prefix? sec-key prefix ch)
            (recur (inc ix) (str prefix ch) sec-key)
            (let [ nsec-key (str sec-key prefix) nprefix "" ]
              (if (is-prefix? nsec-key nprefix ch)
                (recur (inc ix) (str nprefix ch) nsec-key)
                (recur (inc ix) nprefix (str nsec-key ch)))
              )))
        ))))

