package prom

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ListWAFactions valid values: unknown, allow, drop, challenge, jschallenge, simulate, connectionClose, log
var ListWAFactions = []string{
	"unknown",
	"allow",
	"drop",
	"challenge",
	"jschallenge",
	"simulate",
	"connectionClose",
	"log",
}

// ListWAFsources valid values: unknown, asn, country, ip, ipRange, securityLevel, zoneLockdown, waf, uaBlock, rateLimit, firewallRules, bic, hot, l7ddos
var ListWAFsources = []string{
	"unknown",
	"asn",
	"country",
	"ip",
	"ipRange",
	"securityLevel",
	"zoneLockdown",
	"waf",
	"uaBlock",
	"rateLimit",
	"firewallRules",
	"bic",
	"hot",
	"l7ddos",
}

func GenerateMetrics(suffix string, name []string) map[string]*prometheus.GaugeVec {
	cfmetrics := make(map[string]*prometheus.GaugeVec)
	for _, v := range name {
		cfmetrics[v] = promauto.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cloudflare_firewall_" + suffix + "_" + v,
			Help: "Firewall events with " + suffix + " " + v},
			[]string{"zone"})
	}
	return cfmetrics
}
