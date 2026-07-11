package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	// Intentional: server without timeouts (PERF-101 / BP-46 family may fire)
	_ = http.ListenAndServe(":8080", nil)
}
