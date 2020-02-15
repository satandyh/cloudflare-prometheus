package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	cf "github.com/satandyh/cloudflare-prometheus/cf"
	prom "github.com/satandyh/cloudflare-prometheus/prom"
)

const (
	errorToken = "Set your token to the CFTOKEN variable"
	errorEmail = "Set your email to the CFEMAIL variable"
)

// Token linked with email account
var Token = func() string {
	ret, ok := os.LookupEnv("CFTOKEN")
	if !ok {
		// default value - my own
		log.Fatal(errorToken)
	}
	return ret
}()

// Email account that have access
var Email = func() string {
	ret, ok := os.LookupEnv("CFEMAIL")
	if !ok {
		// default value - my own
		log.Fatal(errorEmail)
	}
	return ret
}()

// Port is for prometheus exporter server
var Port = func() int {
	var ret int
	var err error
	v, ok := os.LookupEnv("CFPORT")
	if !ok {
		// default value like official for CloudFlare
		ret = 9199
	} else {
		ret, err = strconv.Atoi(v)
		if err != nil {
			log.Fatal(err)
		}
	}
	return ret
}()

// Period is time interval in seconds between requests to CloudFlare
var Period = func() time.Duration {
	var ret time.Duration
	v, ok := os.LookupEnv("CFPERIOD")
	if !ok {
		// default value 5 minutes
		ret = time.Duration(300)
	} else {
		x, err := strconv.Atoi(v)
		if err != nil {
			log.Fatal(err)
		}
		ret = time.Duration(x)
	}
	return ret
}()

func main() {

	ticker := time.NewTicker(Period * time.Second) // time period in with we will do queries (5 minutes default)
	zones := cf.ListZones(Token, Email)            // get our zones from CloudFlare

	// create prometheus metrics and initialize them
	var cfActionMetrics = prom.GenerateMetrics("action", prom.ListWAFactions) // Action events by zone
	var cfSourceMetrics = prom.GenerateMetrics("source", prom.ListWAFsources) // Source events by zone
	var cfFirewallEventsTotal = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "cffirewall_events_total",
		Help: "Total number of firewall events"},
		[]string{"zone"}) // total events by zone

	// main part of our app
	// do each N time
	go func() {
		for timer := range ticker.C {

			// do for all our zones
			// in parallel mode
			for _, zone := range zones {
				// use goroutines
				go func(zonename, zoneid string) {

					// get list with events for one zone
					zoneEvents := cf.GetAllZoneWAFevents(Token, Email, zoneid, timer, Period)

					// we have a lot of event types
					// each of it is one separate metric
					for _, eventtype := range prom.ListWAFactions { // by action
						a := float64(zoneEvents.GetActionCount(eventtype))
						cfActionMetrics[eventtype].WithLabelValues(zonename).Set(a)
					}
					for _, eventtype := range prom.ListWAFsources { // by source
						a := float64(zoneEvents.GetSourceCount(eventtype))
						cfSourceMetrics[eventtype].WithLabelValues(zonename).Set(a)
					}
					{ // total events
						a := float64(zoneEvents.GetResultCount())
						cfFirewallEventsTotal.WithLabelValues(zonename).Set(a)
					}
				}(zone.Name, zone.ID)
			}
		}
	}()

	// server main part
	http.Handle("/metrics", promhttp.Handler())
	err := http.ListenAndServe(strings.Join([]string{":", strconv.Itoa(Port)}, ""), nil)
	if err != nil {
		log.Fatal(err)
	}
}
