package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type proxy struct {
	Endpoint      string
	ListenAddress string
	Verbose       bool
	AlwaysFilter  string

	scheme string
	host   string
}

func (p *proxy) init() error {
	var link *url.URL
	var err error

	if link, err = url.Parse(p.Endpoint); err != nil {
		return fmt.Errorf("error: failure while parsing endpoint: %s. Error: %s",
			p.Endpoint, err.Error())
	}

	// Only http/https are supported schemes
	switch link.Scheme {
	case "http", "https":
	default:
		link.Scheme = "https"
	}

	// Unknown schemes sometimes result in empty host value
	if link.Host == "" {
		return fmt.Errorf("error: empty host or protocol information in submitted endpoint (%s)",
			p.Endpoint)
	}

	// Update proxy struct
	p.scheme = link.Scheme
	p.host = link.Host

	return nil
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqBodyContent, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ep := *r.URL

	if p.Verbose {
		extra := ""
		if len(reqBodyContent) != 0 {
			extra = fmt.Sprintf("\n%s", reqBodyContent)
		}
		log.Printf("%s %s%s", r.Method, ep.String(), extra)
	}

	var req *http.Request

	switch ep.Path {
	case "/":
		http.Redirect(w, r, "/_plugin/kibana/app/kibana#/discover?_g=()", http.StatusFound)
		return
	case "/_plugin/kibana/app/kibana":
		if r.Method != http.MethodGet {
			http.Error(w, "denied6", http.StatusForbidden)
			return
		}

		req, err = http.NewRequest(http.MethodGet, (&url.URL{
			Host:   p.host,
			Scheme: p.scheme,
			Path:   ep.Path,
		}).String(), nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	case "/favicon.ico",
		"/_plugin/kibana/bundles/app/kibana/bootstrap.js",
		"/_plugin/kibana/bundles/commons.bundle.js",
		"/_plugin/kibana/bundles/commons.style.css",
		"/_plugin/kibana/bundles/ebdca7741674eca4e1fadeca157f3ae6.svg",
		"/_plugin/kibana/bundles/kibana.bundle.js",
		"/_plugin/kibana/bundles/kibana.style.css",
		"/_plugin/kibana/bundles/vendors.bundle.js",
		"/_plugin/kibana/bundles/vendors.style.css",
		"/_plugin/kibana/plugins/kibana/assets/dashboard.svg",
		"/_plugin/kibana/plugins/kibana/assets/discover.svg",
		"/_plugin/kibana/plugins/kibana/assets/logout.svg",
		"/_plugin/kibana/plugins/kibana/assets/play-circle.svg",
		"/_plugin/kibana/plugins/kibana/assets/settings.svg",
		"/_plugin/kibana/plugins/kibana/assets/visualize.svg",
		"/_plugin/kibana/plugins/kibana/assets/wrench.svg",
		"/_plugin/kibana/plugins/timelion/icon.svg",
		"/_plugin/kibana/ui/favicons/favicon.ico",
		"/_plugin/kibana/ui/favicons/manifest.json",
		"/_plugin/kibana/ui/fonts/open_sans/open_sans_v15_latin_600.woff2",
		"/_plugin/kibana/ui/fonts/open_sans/open_sans_v15_latin_700.woff2",
		"/_plugin/kibana/bundles/4b5a84aaf1c9485e060c503a0ff8cadb.woff2",
		"/_plugin/kibana/bundles/dfb02f8f6d0cedc009ee5887cc68f1f3.woff2",
		"/_plugin/kibana/bundles/7c87870ab40d63cfb8870c1f183f9939.woff2",
		"/_plugin/kibana/bundles/fa2772327f55d8198301fdb8bcfc8158.woff",
		"/_plugin/kibana/bundles/e18bbf611f2a2e43afc071aa2f4e1512.ttf",
		"/_plugin/kibana/bundles/448c34a56d699c29117adc64c43affeb.woff2",
		"/_plugin/kibana/ui/fonts/open_sans/open_sans_v15_latin_regular.woff2":
		if r.Method != http.MethodGet {
			http.Error(w, "denied1", http.StatusForbidden)
			return
		}

		req, err = http.NewRequest(http.MethodGet, (&url.URL{
			Host:   p.host,
			Scheme: p.scheme,
			Path:   ep.Path,
		}).String(), nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	case "/_plugin/kibana/api/saved_objects/_bulk_get":
		if r.Method != http.MethodPost {
			http.Error(w, "denied2", http.StatusForbidden)
			return
		}

		var bgr []struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}
		err = json.Unmarshal(reqBodyContent, &bgr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for _, item := range bgr {
			if item.Type != "index-pattern" {
				http.Error(w, "unknown item type in bulk get request", http.StatusBadRequest)
				return
			}
		}
		dataToPost, err := json.Marshal(&bgr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		req, err = http.NewRequest(http.MethodPost, (&url.URL{
			Host:   p.host,
			Scheme: p.scheme,
			Path:   ep.Path,
		}).String(), bytes.NewReader(dataToPost))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// we need Kbn-Version for XSRF check - even though the error message received incorrectly states a different header is needed!
		req.Header.Set("Kbn-Version", r.Header.Get("Kbn-Version"))

	case "/_plugin/kibana/api/saved_objects/_find":
		if r.Method != http.MethodGet {
			http.Error(w, "denied3", http.StatusForbidden)
			return
		}

		vals := ep.Query()
		if vals.Get("type") != "index-pattern" {
			http.Error(w, "denied5", http.StatusForbidden)
			return
		}

		field := vals.Get("fields")
		var fields []string
		if field != "" {
			fields = []string{field}
		}

		req, err = http.NewRequest(r.Method, (&url.URL{
			Host:   p.host,
			Scheme: p.scheme,
			Path:   ep.Path,
			RawQuery: (&url.Values{
				"type":     []string{"index-pattern"},
				"fields":   fields,
				"per_page": []string{vals.Get("per_page")},
			}).Encode(),
		}).String(), bytes.NewReader(reqBodyContent))
		if err != nil {
			log.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

	case "/_plugin/kibana/elasticsearch/_msearch":
		if r.Method != http.MethodPost {
			http.Error(w, "denied4", http.StatusForbidden)
			return
		}

		var searchBits []string
		for idx, bit := range strings.Split(strings.TrimSpace(string(reqBodyContent)), "\n") {
			var m map[string]interface{}
			err = json.Unmarshal([]byte(bit), &m)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if idx%2 == 0 { // index
				if m["index"] == "" {
					http.Error(w, "no index requested", http.StatusBadRequest)
					return
				}
			} else { // query
				q, ok := m["query"].(map[string]interface{})
				if !ok {
					http.Error(w, "no query", http.StatusBadRequest)
					return
				}

				boolQuery, ok := q["bool"].(map[string]interface{})
				if !ok {
					http.Error(w, "no bool query", http.StatusBadRequest)
					return
				}

				filter, ok := boolQuery["filter"].([]interface{})
				if !ok {
					http.Error(w, "no filter in bool query", http.StatusBadRequest)
					return
				}

				var extraFilters []string
				if p.AlwaysFilter != "" {
					extraFilters = append(extraFilters, p.AlwaysFilter)
				}
				for _, f := range r.Header["X-Elasticsearch-Filters"] {
					b, err := base64.StdEncoding.DecodeString(f)
					if err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					extraFilters = append(extraFilters, string(b))
				}
				for _, f := range extraFilters {
					var fm interface{}
					err = json.Unmarshal([]byte(f), &fm)
					if err != nil {
						http.Error(w, err.Error(), http.StatusBadRequest)
						return
					}
					filter = append(filter, fm)
				}

				boolQuery["filter"] = filter
				m["query"] = map[string]interface{}{
					"bool": boolQuery,
				}
			}
			bb, err := json.Marshal(&m)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			searchBits = append(searchBits, string(bb))
			log.Println(string(bb))
		}
		if len(searchBits)%2 != 0 {
			http.Error(w, "don't understand query", http.StatusBadRequest)
			return
		}

		req, err = http.NewRequest(r.Method, (&url.URL{
			Host:   p.host,
			Scheme: p.scheme,
			Path:   ep.Path,
		}).String(), bytes.NewReader([]byte(strings.Join(searchBits, "\n")+"\n")))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// we need Kbn-Version for XSRF check - even though the error message received incorrectly states a different header is needed!
		req.Header.Set("Kbn-Version", r.Header.Get("Kbn-Version"))

		// ironically the content-type is not standard json... but this is required to be set
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	default:
		http.Error(w, "denied", http.StatusForbidden)
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	// Write back headers to requesting client
	rh := w.Header()
	for k, vals := range resp.Header {
		for _, v := range vals {
			rh.Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Send response back to requesting client
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Println(err) // can't do http.Error as status code is already written
	}
}

func (p *proxy) RunForever() error {
	err := p.init()
	if err != nil {
		return err
	}

	log.Printf("Listening on %s...\n", p.ListenAddress)
	server := &http.Server{
		Addr:    p.ListenAddress,
		Handler: p,
	}

	// Shutdown on signal
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sc
		log.Println("Signal received, shutting down...")
		ctx, cx := context.WithTimeout(context.Background(), 20*time.Second)
		defer cx()
		err := server.Shutdown(ctx)
		if err != nil && err != http.ErrServerClosed {
			log.Println(err)
		}
	}()

	return server.ListenAndServe()
}

func main() {
	p := &proxy{}

	flag.StringVar(&p.Endpoint, "endpoint", "", "e.g. http://localhost:9200")
	flag.StringVar(&p.ListenAddress, "listen", "127.0.0.1:9300", "Local TCP port to listen on")
	flag.StringVar(&p.AlwaysFilter, "filter", "", "JSON filter that always will be added. Mostly used for debug. May be left blank")
	flag.BoolVar(&p.Verbose, "verbose", false, "Log queries")
	flag.Parse()

	if p.Endpoint == "" {
		log.Println("You need to specify Amazon ElasticSearch endpoint.")
		log.Fatalln("Please run with '-h' for a list of available arguments.")
	}

	err := p.RunForever()
	if err != nil && err != http.ErrServerClosed {
		log.Fatalln(err)
	}
}
