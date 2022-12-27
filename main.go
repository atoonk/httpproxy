package main

import (
	"log"
	"net/http"

	"github.com/atoonk/httpproxy/httpproxy"
)

func main() {

	// Define the authorizeRequestFn and modifyResponseFn functions
	authorizeRequestFn := func(w http.ResponseWriter, r *http.Request) bool {
		// Add your logic here
		return true
	}
	modifyResponseFn := func(r *http.Response) error {
		return nil

	}

	// Create a new Proxy server instance
	proxy := httpproxy.NewProxy(authorizeRequestFn, modifyResponseFn)

	// Add a target host to the proxy
	err := proxy.AddHost("httpbin.org", []string{"http://httpbin.org:80"})
	if err != nil {
		log.Fatal(err)
	}

	// Add a second target host to the proxy
	err = proxy.AddHost("localhost", []string{"http://localhost:8888", "http://nu.nl"})
	if err != nil {
		log.Fatal(err)
	}

	// // we create new server that will listen on port 8080
	// server := &http.Server{
	// 	Addr: ":8080",
	// 	Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// 		// we call the reverse proxy
	// 		proxy.ServeHTTP(w, r)

	// 		// Get the status code of the response
	// 		statusCode := proxy.GetStatuscode()
	// 		repsonseSize := proxy.GetSize()
	// 		logrequests(r, statusCode, repsonseSize)

	// 	}),
	// }

	// we start the server
	e := proxy.ServeHTTP()
	if e != nil {
		log.Fatal(e)
	}

}

// logging all requests to the proxy
func logrequests(r *http.Request, statusCode int, repsonseSize int64) {
	log.Printf("%s %s %s %s %d, %d", r.Method, r.URL.Path, r.RemoteAddr, r.UserAgent(), statusCode, repsonseSize)
}
