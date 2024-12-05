// This code is forked from Tailscale codebase which is governed by
// a BSD-style licence. See https://github.com/tailscale/tailscale
//
// The link below is the code from which this code originates:
// https://github.com/tailscale/tailscale/blob/741ae9956e674177687062b5499a80db83505076/cmd/nginx-auth/nginx-auth.go
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"

	"context"
	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"github.com/patrickmn/go-cache"
)

var (
	listenProto      = flag.String("network", "tcp", "type of network to listen on, defaults to tcp")
	listenAddr       = flag.String("addr", "127.0.0.1:", "address to listen on, defaults to 127.0.0.1:")
	headerRemoteIP   = flag.String("remote-ip-header", "X-Forwarded-For", "HTTP header field containing the remote IP")
	headerRemotePort = flag.String("remote-port-header", "X-Forwarded-Port", "HTTP header field containing the remote port")
	allowlistPath    = "/etc/allowlist.yaml" // Path to the allowlist file
	debug            = flag.Bool("debug", false, "enable debug logging")
)

var whoisCache = cache.New(-1, -1) // No expiration or cleanup

// AllowlistConfig represents the structure of the allowlist file
type AllowlistConfig struct {
	Allowlist map[string][]string `yaml:"allowlist"`
}

var (
	allowlist = make(map[string][]string)
	mu        sync.RWMutex
)

func getWhoIsCached(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	// Check if the result is already in the cache
	if result, found := whoisCache.Get(remoteAddr); found {
		return result.(*apitype.WhoIsResponse), nil
	}

	// If not in cache, make the API call with context
	client := &tailscale.LocalClient{}
	info, err := client.WhoIs(ctx, remoteAddr)
	if err != nil {
		return nil, err
	}

	// Store the result in the cache indefinitely
	whoisCache.Set(remoteAddr, info, cache.NoExpiration)
	return info, nil
}



// LoadAllowlist dynamically loads the allowlist from the file
func LoadAllowlist(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open allowlist file: %w", err)
	}
	defer file.Close()

	var config AllowlistConfig
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return fmt.Errorf("failed to decode allowlist file: %w", err)
	}

	mu.Lock()
	allowlist = config.Allowlist
	mu.Unlock()
	return nil
}

func watchAllowlist(filePath string) {
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        log.Fatalf("Failed to create file watcher: %v", err)
    }
    defer watcher.Close()

    err = watcher.Add(filePath)
    if err != nil {
        log.Fatalf("Failed to add file to watcher: %v", err)
    }

    for {
        select {
        case event, ok := <-watcher.Events:
            if !ok {
                return
            }
            if event.Op&fsnotify.Write == fsnotify.Write {
                log.Printf("Allowlist file changed: %s", event.Name)
                if err := LoadAllowlist(filePath); err != nil {
                    log.Printf("Failed to reload allowlist: %v", err)
                } else {
                    log.Println("Allowlist reloaded successfully")
                }
            }
        case err, ok := <-watcher.Errors:
            if !ok {
                return
            }
            log.Printf("Watcher error: %v", err)
        }
    }
}


// IsUserAllowed checks if a user is allowed access to a specific host
func IsUserAllowed(host, user string) bool {
	mu.RLock()
	defer mu.RUnlock()
	allowedUsers, exists := allowlist[host]
	if !exists {
		return false
	}
	for _, allowedUser := range allowedUsers {
		if user == allowedUser {
			return true
		}
	}
	return false
}

func main() {
	flag.Parse()
	if *listenAddr == "" {
		log.Fatal("listen address not set")
	}

	// Initial loading of the allowlist
	if err := LoadAllowlist(allowlistPath); err != nil {
		log.Fatalf("Failed to load allowlist: %v", err)
	}

	 // Start watching the allowlist file for changes
	 go watchAllowlist(allowlistPath)


	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if *debug {
			log.Printf("received request with header %+v", r.Header)
		}

		remoteHost := r.Header.Get(*headerRemoteIP)
		if remoteHost == "" {
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("missing header %s", *headerRemoteIP)
			return
		}

		remotePort := r.Header.Get(*headerRemotePort)
		if remotePort == "" {
			w.WriteHeader(http.StatusBadRequest)
			log.Printf("missing header %s", *headerRemotePort)
			return
		}

		remoteAddr, err := netip.ParseAddrPort(net.JoinHostPort(remoteHost, remotePort))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			log.Printf("remote address and port are not valid: %v", err)
			return
		}

		info, err := getWhoIsCached(r.Context(), remoteAddr.String())
		// log.Printf("Node: %+v", info.Node)
		// log.Printf("UserProfile: %+v", info.UserProfile)
		// log.Printf("Capabilities: %+v", info.CapMap)
		
		
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			log.Printf("can't look up %s: %v", remoteAddr, err)
			return
		}

		if len(info.Node.Tags) != 0 {
			w.WriteHeader(http.StatusForbidden)
			log.Printf("node %s is tagged", info.Node.Hostinfo.Hostname())
			return
		}

		// tailnet of connected node. When accessing shared nodes, this
		// will be empty because the tailnet of the sharee is not exposed.
		var tailnet string

		if !info.Node.Hostinfo.ShareeNode() {
			var ok bool
			_, tailnet, ok = strings.Cut(info.Node.Name, info.Node.ComputedName+".")
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				log.Printf("can't extract tailnet name from hostname %q", info.Node.Name)
				return
			}
			tailnet = strings.TrimSuffix(tailnet, ".beta.tailscale.net")
		}

		if expectedTailnet := r.Header.Get("Expected-Tailnet"); expectedTailnet != "" && expectedTailnet != tailnet {
			w.WriteHeader(http.StatusForbidden)
			log.Printf("user is part of tailnet %s, wanted: %s", tailnet, url.QueryEscape(expectedTailnet))
			return
		}

		user := info.UserProfile.LoginName
		host := r.Header.Get("X-Forwarded-Host")

		if !IsUserAllowed(host, user) {
			w.WriteHeader(http.StatusForbidden)
			log.Printf("User %s is NOT allowed to access %s", user, host)
			return
		}

		h := w.Header()
		h.Set("Tailscale-Login", strings.Split(info.UserProfile.LoginName, "@")[0])
		h.Set("Tailscale-User", info.UserProfile.LoginName)
		h.Set("Tailscale-Name", info.UserProfile.DisplayName)
		h.Set("Tailscale-Profile-Picture", info.UserProfile.ProfilePicURL)
		h.Set("Tailscale-Tailnet", tailnet)
		w.WriteHeader(http.StatusNoContent)
	})

	ln, err := net.Listen(*listenProto, *listenAddr)
	if err != nil {
		log.Fatalf("can't listen on %s: %v", *listenAddr, err)
	}
	defer ln.Close()

	log.Printf("listening on %s", ln.Addr())
	log.Fatal(http.Serve(ln, mux))
}
