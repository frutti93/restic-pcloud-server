// restic-pcloud-server: a restic REST-protocol server backed by pCloud via rclone,
// with verify-after-write: every Save is independently re-checked against what pCloud
// actually stored, and retried fresh (delete + re-upload) on mismatch, instead of trusting
// rclone/pCloud's own "success" response.
package main

import (
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"
)

// version is set at build time via -ldflags "-X main.version=<short-sha>".
var version = "dev"

var (
	rcloneRoot   string
	rcloneConfig string
	caCertPath   string
	maxRetries   int
	listenAddr   string
	debug        bool
	authUser     string
	authPass     string
	showVersion  bool

	inFlight int64
	saveSeq  int64
)

func init() {
	flag.StringVar(
		&rcloneRoot,
		"remote-root",
		"pcloud:Backups/restic",
		"fixed rclone remote:path root for the single restic repository",
	)
	flag.StringVar(&rcloneConfig, "rclone-config", "", "path to rclone.conf")
	flag.StringVar(
		&caCertPath,
		"ca-cert",
		"",
		"CA bundle for rclone's TLS verification",
	)
	flag.IntVar(
		&maxRetries,
		"max-retries",
		3,
		"max fresh re-upload retries after a failed verification",
	)
	flag.StringVar(&listenAddr, "listen", "127.0.0.1:8080", "address to listen on")
	flag.BoolVar(
		&debug,
		"debug",
		false,
		"log per-request/per-stage timing and concurrency",
	)
	flag.StringVar(
		&authUser,
		"auth-user",
		os.Getenv("RESTIC_PCLOUD_AUTH_USER"),
		"HTTP Basic Auth username",
	)
	flag.StringVar(
		&authPass,
		"auth-pass",
		os.Getenv("RESTIC_PCLOUD_AUTH_PASS"),
		"HTTP Basic Auth password",
	)
	flag.BoolVar(&showVersion, "version", false, "print the build version and exit")
}

// authMiddleware enforces HTTP Basic Auth when credentials are configured.
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	if authUser == "" && authPass == "" {
		return next
	}

	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok ||
			subtle.ConstantTimeCompare([]byte(u), []byte(authUser)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p), []byte(authPass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="restic-pcloud-server"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func rcloneBaseArgs() []string {
	args := []string{}

	if rcloneConfig != "" {
		args = append(args, "--config", rcloneConfig)
	}
	if caCertPath != "" {
		args = append(args, "--ca-cert", caCertPath)
	}

	return args
}

func runRclone(args ...string) ([]byte, error) {
	full := append(rcloneBaseArgs(), args...)
	cmd := exec.Command("rclone", full...)
	out, err := cmd.CombinedOutput()
	return out, err
}

// repoRoot always returns the configured root.
// The client cannot select a repository subdirectory via the URL.
func repoRoot() string {
	return rcloneRoot
}

// Restic data objects live under a two-character prefix directory.
// All other object types are stored directly under their respective directories.
func remotePath(kind, name string) string {
	base := repoRoot()

	if kind == "config" {
		return fmt.Sprintf("%s/config", base)
	}

	if kind == "data" && len(name) >= 2 {
		return fmt.Sprintf("%s/data/%s/%s", base, name[:2], name)
	}

	return fmt.Sprintf("%s/%s/%s", base, kind, name)
}

func remoteDir(kind string) string {
	return fmt.Sprintf("%s/%s", repoRoot(), kind)
}

type lsjsonEntry struct {
	Path  string `json:"Path"`
	Name  string `json:"Name"`
	Size  int64  `json:"Size"`
	IsDir bool   `json:"IsDir"`
}

// remoteSizeOnce returns the size of a single object,
// or -1 if it does not exist. It performs no retries.
func remoteSizeOnce(path string) int64 {
	out, err := runRclone("lsjson", path)
	if err != nil {
		return -1
	}

	var entries []lsjsonEntry
	if err := json.Unmarshal(out, &entries); err != nil || len(entries) == 0 {
		return -1
	}

	return entries[0].Size
}

// remoteSize retries failed stat operations because pCloud can temporarily
// report existing objects as missing.
func remoteSize(path string) int64 {
	const attempts = 4
	const delay = 800 * time.Millisecond

	var size int64 = -1

	for attempt := 1; attempt <= attempts; attempt++ {
		size = remoteSizeOnce(path)

		if size >= 0 {
			if attempt > 1 {
				debugf(
					"STAT %s: found on attempt %d/%d after earlier not-found (%d bytes)",
					path,
					attempt,
					attempts,
					size,
				)
			}
			return size
		}

		if attempt < attempts {
			time.Sleep(delay)
		}
	}

	return -1
}

// Repository creation is accepted only at the root URL.
// Object requests use /config, /data/<name>, /index/<name>, etc.
var (
	repoCreateRE = regexp.MustCompile(`^/?$`)
	pathRE       = regexp.MustCompile(`^/([a-z]+)(?:/([0-9a-fA-F]+))?/?$`)
)

func logf(format string, a ...interface{}) {
	log.Printf("[info] "+format, a...)
}

const (
	colorReset  = "\033[0m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorRed    = "\033[31m"
	colorCyan   = "\033[36m"
)

func debugf(format string, a ...interface{}) {
	if debug {
		log.Printf("[debug] "+format, a...)
	}
}

// statusRecorder captures the HTTP status code for request logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// loggingMiddleware records request timing and concurrency when debug is enabled.
func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !debug {
			next(w, r)
			return
		}

		n := atomic.AddInt64(&inFlight, 1)
		defer atomic.AddInt64(&inFlight, -1)

		start := time.Now()
		rec := &statusRecorder{
			ResponseWriter: w,
			status:         http.StatusOK,
		}

		debugf("-> %s %s (in-flight=%d)", r.Method, r.URL.Path, n)
		next(rec, r)
		debugf(
			"<- %s %s status=%d duration=%s (in-flight was %d)",
			r.Method,
			r.URL.Path,
			rec.status,
			time.Since(start),
			n,
		)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Restic initializes a repository using POST /?create=true.
	if r.Method == http.MethodPost && r.URL.Query().Get("create") == "true" {
		if repoCreateRE.MatchString(r.URL.Path) {
			w.WriteHeader(http.StatusOK)
			return
		}

		http.NotFound(w, r)
		return
	}

	m := pathRE.FindStringSubmatch(r.URL.Path)
	if m == nil {
		http.NotFound(w, r)
		return
	}

	kind, name := m[1], m[2]

	// Config is a single file, not a listable directory.
	hasName := name != "" || kind == "config"

	switch {
	case r.Method == http.MethodHead && hasName:
		handleHead(w, kind, name)

	case r.Method == http.MethodGet && hasName:
		handleGet(w, r, kind, name)

	case r.Method == http.MethodGet && name == "":
		handleList(w, r, kind)

	case r.Method == http.MethodPost && hasName:
		handleSave(w, r, kind, name)

	case r.Method == http.MethodDelete && hasName:
		handleDelete(w, kind, name)

	default:
		http.Error(w, "unsupported", http.StatusMethodNotAllowed)
	}
}

func handleHead(w http.ResponseWriter, kind, name string) {
	size := remoteSize(remotePath(kind, name))
	if size < 0 {
		http.NotFound(w, nil)
		return
	}

	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)
}

func handleGet(w http.ResponseWriter, r *http.Request, kind, name string) {
	path := remotePath(kind, name)
	size := remoteSize(path)

	if size < 0 {
		http.NotFound(w, r)
		return
	}

	args := []string{"cat", path}
	status := http.StatusOK

	if rng := r.Header.Get("Range"); rng != "" {
		var start, end int64

		if _, err := fmt.Sscanf(rng, "bytes=%d-%d", &start, &end); err == nil {
			count := end - start + 1

			args = append(
				args,
				"--offset", strconv.FormatInt(start, 10),
				"--count", strconv.FormatInt(count, 10),
			)

			w.Header().Set(
				"Content-Range",
				fmt.Sprintf("bytes %d-%d/%d", start, end, size),
			)
			w.Header().Set("Content-Length", strconv.FormatInt(count, 10))
			status = http.StatusPartialContent
		}
	} else {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}

	full := append(rcloneBaseArgs(), args...)
	cmd := exec.Command("rclone", full...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := cmd.Start(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(status)
	_, _ = io.Copy(w, stdout)

	if err := cmd.Wait(); err != nil {
		logf("GET %s: rclone cat error after headers sent: %v", path, err)
	}
}

func handleList(w http.ResponseWriter, r *http.Request, kind string) {
	// Data objects are stored one level down in two-character prefix directories.
	args := []string{"lsjson"}

	if kind == "data" {
		args = append(args, "-R")
	}

	args = append(args, remoteDir(kind))

	out, err := runRclone(args...)

	var entries []lsjsonEntry
	if err == nil {
		if err := json.Unmarshal(out, &entries); err != nil {
			logf("LIST %s: invalid rclone JSON: %v", kind, err)
		}
	} else {
		debugf("LIST %s: rclone error: %v", kind, err)
	}

	// Restic REST v2 listing format.
	type v2entry struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
	}

	var result []v2entry

	for _, e := range entries {
		if e.IsDir {
			continue
		}

		result = append(result, v2entry{
			Name: e.Name,
			Size: e.Size,
		})
	}

	if result == nil {
		result = []v2entry{}
	}

	w.Header().Set("Content-Type", "application/vnd.x.restic.rest.v2")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		logf("LIST %s: failed to encode response: %v", kind, err)
	}
}

// handleSave writes the object and independently verifies its remote size.
// On mismatch, it deletes the bad object and retries the upload.
func handleSave(w http.ResponseWriter, r *http.Request, kind, name string) {
	reqID := atomic.AddInt64(&saveSeq, 1)
	saveStart := time.Now()

	tmp, err := os.CreateTemp("", "pcloud-repair-*.tmp")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer os.Remove(tmp.Name())
	defer tmp.Close()

	recvStart := time.Now()
	written, err := io.Copy(tmp, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := tmp.Close(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	recvDur := time.Since(recvStart)
	path := remotePath(kind, name)
	var lastErr string

	// The initial write plus maxRetries fresh retries.
	for attempt := 0; attempt <= maxRetries; attempt++ {
		label := "initial attempt"

		if attempt > 0 {
			label = fmt.Sprintf("retry %d/%d", attempt, maxRetries)
		}

		willRetry := attempt < maxRetries

		copyStart := time.Now()
		out, err := runRclone("copyto", tmp.Name(), path)
		copyDur := time.Since(copyStart).Round(time.Second)

		if err != nil {
			lastErr = fmt.Sprintf("copyto failed: %v: %s", err, out)

			if willRetry {
				logf(
					"SAVE %s [req %05d] %s: %s%s%s - retrying (copyto=%s)",
					path, reqID, label,
					colorRed, lastErr, colorReset, copyDur,
				)
			}

			continue
		}

		verifyStart := time.Now()
		remoteSz := remoteSize(path)
		verifyDur := time.Since(verifyStart).Round(time.Second)

		debugf(
			"SAVE %s [req %05d] %s: recv=%s copyto=%s verify=%s bytes=%d",
			path, reqID, label, recvDur, copyDur, verifyDur, written,
		)

		if remoteSz == written {
			if attempt > 0 {
				logf(
					"SAVE %s [req %05d] %s: %sverified OK%s (%d bytes, total %s)",
					path, reqID, label,
					colorGreen, colorReset, written,
					time.Since(saveStart).Round(time.Second),
				)
			}

			w.WriteHeader(http.StatusOK)
			return
		}

		if remoteSz < 0 {
			lastErr = fmt.Sprintf(
				"wrote %d bytes but pCloud still shows it missing",
				written,
			)
		} else {
			lastErr = fmt.Sprintf(
				"size mismatch: wrote %d bytes, pCloud has %d",
				written, remoteSz,
			)
		}

		if willRetry {
			logf(
				"SAVE %s [req %05d] %s: %s%s%s - retrying fresh (copyto=%s verify=%s)",
				path, reqID, label,
				colorYellow, lastErr, colorReset, copyDur, verifyDur,
			)
		}

		// Best-effort cleanup of a failed or corrupted upload.
		_, _ = runRclone("deletefile", path)

		if willRetry {
			time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
		}
	}

	logf(
		"SAVE %s [req %05d]: %sgiving up%s after %d retries: %s (total %s)",
		path, reqID, colorRed, colorReset,
		maxRetries, lastErr,
		time.Since(saveStart).Round(time.Second),
	)

	http.Error(w, lastErr, http.StatusInternalServerError)
}

func handleDelete(w http.ResponseWriter, kind, name string) {
	path := remotePath(kind, name)

	if _, err := runRclone("deletefile", path); err != nil {
		http.NotFound(w, nil)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func main() {
	flag.Parse()

	if showVersion {
		fmt.Println(version)
		return
	}

	if rcloneConfig == "" {
		fmt.Fprintln(os.Stderr, "must pass -rclone-config")
		os.Exit(1)
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	log.Printf(
		"restic-pcloud-server %s%s%s listening on %s, remote root %s (max-retries=%d, debug=%v)",
		colorCyan, version, colorReset,
		listenAddr, rcloneRoot, maxRetries, debug,
	)

	log.Fatal(http.ListenAndServe(
		listenAddr,
		loggingMiddleware(authMiddleware(handler)),
	))
}
