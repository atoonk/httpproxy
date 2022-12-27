package httpproxy

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/atoonk/httpproxy/httpproxy/vhostmanager"
	uuid "github.com/satori/go.uuid"
)

// middleware is a definition of  what a middleware is,
// take in one handlerfunc and wrap it within another handlerfunc
type middleware func(http.HandlerFunc) http.HandlerFunc

// Proxy is a simple HTTP proxy
type Proxy struct {
	authorizeRequestFn func(http.ResponseWriter, *http.Request) bool
	modifyResponseFn   func(*http.Response) error
	vhostmanager       vhostmanager.HostManager
	statuscode         int
	size               int64
	middlewareFn       func(http.Handler) http.Handler
}

// NewProxy creates a new Proxy
func NewProxy(authorizeRequestFn func(http.ResponseWriter, *http.Request) bool, modifyResponseFn func(*http.Response) error) *Proxy {
	return &Proxy{
		authorizeRequestFn: authorizeRequestFn,
		modifyResponseFn:   modifyResponseFn,
		vhostmanager:       vhostmanager.NewInMemoryHostManager(), // by default use thread-safe in-memory storage
	}
}

type errorHandlingRoundTripper struct {
	// The underlying RoundTripper to use for the actual request
	RoundTripper http.RoundTripper

	// Dialer is the dialer used to connect to the upstream server.
	// If nil, net.Dialer is used.
	Dialer net.Dialer

	// The number of times to retry the request on failure
	Retries int

	// The list of upstreams to try
	Upstreams []string

	// set time connect timeout
	Timeout time.Duration
}

func (rt *errorHandlingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	var err error
	tmpupstreams := rt.Upstreams

	shuffle(tmpupstreams)
	for i := 0; i < rt.Retries; i++ {
		// multiply timeout by i to increase timeout
		timeout := rt.Timeout
		if i > 0 {
			timeout = rt.Timeout * time.Duration(i*10)
		}
		fmt.Println(timeout)
		for _, upstream := range tmpupstreams {

			upstreamURL, err := url.Parse(upstream)
			if err != nil {
				return nil, err
			}
			req.URL.Host = upstreamURL.Host
			req.URL.Scheme = upstreamURL.Scheme

			// Customer dialer to set timeout
			dialer := &net.Dialer{
				Timeout:   timeout,
				KeepAlive: timeout,
				DualStack: true,
			}
			// Customer transport to set timeout
			transport := &http.Transport{
				DialContext:           dialer.DialContext,
				MaxIdleConns:          100,
				IdleConnTimeout:       timeout,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				ResponseHeaderTimeout: timeout,
			}
			rt.RoundTripper = transport

			//fmt.Printf("%+v", rt.RoundTripper.(*http.Transport))

			var res *http.Response
			res, err = rt.RoundTripper.RoundTrip(req)

			if err != nil {
				log.Println("Upstream: ", upstream, ">", err)
				continue
			}

			if res.StatusCode >= 500 && res.StatusCode <= 599 {
				err = fmt.Errorf("upstream: %s returned status code: %d", upstream, res.StatusCode)
				log.Println(err)
				continue
			} else {
				return res, nil
			}

		}
	}
	err = fmt.Errorf("all upstreams failed")
	//fmt.Printf("All upstreams failed after %d retries for %s %s %s\n", rt.Retries, req.Method, req.URL, err)
	return nil, err
}

/*
func (rt *errorHandlingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	fmt.Println("in errorHandlingRoundTripper")
	for _, upstream := range rt.Upstreams {
		upstreamURL, err := url.Parse(upstream)
		if err != nil {
			return nil, err
		}
		req.URL.Host = upstreamURL.Host
		req.URL.Scheme = upstreamURL.Scheme
		// print the request
		fmt.Println(req)
		res, err := rt.RoundTripper.RoundTrip(req)
		if err == nil {
			return res, nil
		}
	}
	return nil, fmt.Errorf("all upstreams failed")
}
*/

// WithHostManager sets the proxy's host manager
func (p *Proxy) WithHostManager(hm vhostmanager.HostManager) *Proxy {
	p.vhostmanager = hm
	return p
}

func shuffle(s []string) {
	for i := range s {
		j := rand.Intn(i + 1)
		s[i], s[j] = s[j], s[i]
	}
}

// AddHost adds a target host to the proxy
func (p *Proxy) AddHost(sni string, upstreams []string) error {

	//upstream := upstreams[rand.Intn(len(upstreams))]
	//targetURL, err := url.Parse(upstream)
	//if err != nil {
	//	return err
	//}
	// Create a new ReverseProxy

	//proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy := &httputil.ReverseProxy{}

	// Set the RoundTripper to our custom errorHandlingRoundTripper
	proxy.Transport = &errorHandlingRoundTripper{
		RoundTripper: http.DefaultTransport,
		Retries:      3,
		Upstreams:    upstreams,
		Timeout:      1000 * time.Millisecond,
	}
	// now also set timouts
	proxy.Transport.(*errorHandlingRoundTripper).RoundTripper.(*http.Transport).DialContext = (&net.Dialer{
		Timeout:   30 * time.Nanosecond,
		KeepAlive: 30 * time.Nanosecond,
	}).DialContext
	proxy.Transport.(*errorHandlingRoundTripper).RoundTripper.(*http.Transport).TLSHandshakeTimeout = 10 * time.Second

	// Set the Director to our custom director

	proxy.Director = func(req *http.Request) {
		// This uses the incoming request, you can modify it here
		// Now pick an upstream from the list if there are any

		// print request URL
		fmt.Println("Request URL: ", req.URL)

	}

	proxy.ModifyResponse = p.logResponse

	return p.vhostmanager.PutHost(sni, upstreams, nil, proxy)

}

func (p *Proxy) GetStatuscode() int {
	return p.statuscode
}
func (p *Proxy) GetSize() int64 {
	return p.size
}
func (p *Proxy) logResponse(rsp *http.Response) error {
	p.statuscode = rsp.StatusCode
	p.size = rsp.ContentLength

	return nil
}

func (p *Proxy) ServeHTTP() error {

	// Get the target host for the request

	// Create a new ReverseProxy
	/*
		proxy := httputil.NewSingleHostReverseProxy(p.targetURL)
		proxy.Director = func(req *http.Request) {
			req.URL.Scheme = p.targetURL.Scheme
			req.URL.Host = p.targetURL.Host
			req.Host = p.targetURL.Host
			req.URL.Path = r.URL.Path
			req.URL.RawQuery = r.URL.RawQuery
		}

		proxy.ModifyResponse = p.logResponse
	*/

	// create an endpoint grouping called privateChain for
	// urls we want to protect with middlewares

	var privateChain = []middleware{

		AuthMiddleware,
		PrivateMiddleware,
		RequestIdMiddleware,
	}

	server := http.Server{
		Addr: ":8080",
		//Handler: http.HandlerFunc(p.proxyHandler),

		// build the chain of middlewares
		Handler: buildChain(
			p.proxyHandler, privateChain...,
		),
	}
	return server.ListenAndServe()

}

// This is the ProxyHandler
func (p *Proxy) proxyHandler(rw http.ResponseWriter, req *http.Request) {
	host, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		host = req.Host
	}
	target, found, err := p.vhostmanager.GetHost(host)

	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(rw, "not found", http.StatusNotFound)
		return
	}

	// Forward the request to the target server using the ReverseProxy
	target.ReverseProxy.ServeHTTP(rw, req)
	log.Printf("%s %s %s %s %d, %d", req.Method, req.URL.Path, req.RemoteAddr, req.UserAgent(), p.statuscode, p.size)

}

// buildChain builds the middlware chain recursively, functions are first class
func buildChain(f http.HandlerFunc, m ...middleware) http.HandlerFunc {
	// if our chain is done, use the original handlerfunc
	if len(m) == 0 {
		return f
	}
	// otherwise nest the handlerfuncs
	return m[0](buildChain(f, m[1:cap(m)]...))
}

// AuthMiddleware - takes in a http.HandlerFunc, and returns a http.HandlerFunc
var AuthMiddleware = func(f http.HandlerFunc) http.HandlerFunc {
	// one time scope setup area for middleware
	return func(w http.ResponseWriter, r *http.Request) {
		// ... pre handler functionality
		fmt.Println("start auth")
		f(w, r)
		fmt.Println("end auth")
		// ... post handler functionality
	}
}

// PrivateMiddleware - takes in a http.HandlerFunc, and returns a http.HandlerFunc
var PrivateMiddleware = func(f http.HandlerFunc) http.HandlerFunc {
	// one time scope setup area for middleware
	return func(w http.ResponseWriter, r *http.Request) {
		// ... pre handler functionality
		fmt.Println("start private")
		f(w, r)
		fmt.Println("end private")
		// ... post handler functionality
	}
}

// RequestIdMiddleware - takes in a http.HandlerFunc, and returns a http.HandlerFunc
var RequestIdMiddleware = func(f http.HandlerFunc) http.HandlerFunc {
	// one time scope setup area for middleware
	return func(w http.ResponseWriter, r *http.Request) {
		// add a request id..
		r.Header.Set("X-Request-Id", uuid.NewV4().String())

		//backdrop.Set(r, "id", uuid.NewV4())
		// ... pre handler functionality
		fmt.Println("start RequestIdMiddleware")
		f(w, r)
		fmt.Println("end RequestIdMiddleware")
		// ... post handler functionality
	}
}
