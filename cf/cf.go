package cf

import (
	"strconv"
	//"errors"
	"encoding/json"
	"log"
	"time"

	"github.com/pkg/errors"

	cloudflare "github.com/cloudflare/cloudflare-go"
	"github.com/go-resty/resty"
)

const (
	// CloudFlareURL main API URL - for resty only
	CloudFlareURL = "https://api.cloudflare.com/client/v4"

	// error messages
	errorWAFeventsGet   = "Something goes wrong with answer from CloudFlare"
	errorWAFeventsParse = "Cannot properly unmarshal data from CloudFlare"
)

// WAFevents main structure of response data of WAF events page
type WAFevents struct {
	Result []struct {
		RayID   string `json:"ray_id"`
		Kind    string `json:"kind"`
		Source  string `json:"source"`
		Action  string `json:"action"`
		RuleID  string `json:"rule_id"`
		IP      string `json:"ip"`
		IPClass string `json:"ip_class"`
		Country string `json:"country"`
		Colo    string `json:"colo"`
		Host    string `json:"host"`
		Method  string `json:"method"`
		Proto   string `json:"proto"`
		Scheme  string `json:"scheme"`
		Ua      string `json:"ua"`
		URI     string `json:"uri"`
		Match   []struct {
			RuleID   string `json:"rule_id"`
			Source   string `json:"source"`
			Action   string `json:"action"`
			Metadata struct {
				IPClass string `json:"ip_class"`
			} `json:"metadata"`
		} `json:"matches"`
		OccurredAt string `json:"occurred_at"`
	} `json:"result"`
	ResultInfo struct {
		Cursors struct {
			After  string `json:"after"`
			Before string `json:"before"`
		} `json:"cursors"`
		ScannedRange struct {
			Since string `json:"since"`
			Until string `json:"until"`
		} `json:"scanned_range"`
	} `json:"result_info"`
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Messages []string `json:"messages"`
}

// list of WAFevents
type ListWAFevents struct {
	Pages []WAFevents
}

// get After cursor
func (resp *WAFevents) GetAfterCursor() string {
	return resp.ResultInfo.Cursors.After
}

// get count of result events
func (resp *WAFevents) GetResultCount() int {
	return len(resp.Result)
}

// get count of result events for list
func (list *ListWAFevents) GetResultCount() int {
	count := 0
	for _, page := range list.Pages {
		count = count + len(page.Result)
	}
	return count
}

// count with filter by Action
func (resp *WAFevents) GetActionCount(filter string) int {
	count := 0
	for _, v := range resp.Result {
		if v.Action == filter {
			count++
		}
	}
	return count
}

// count with filter by Action for list
func (list *ListWAFevents) GetActionCount(filter string) int {
	count := 0
	for _, page := range list.Pages {
		count = count + page.GetActionCount(filter)
	}
	return count
}

// count with filter by Source
func (resp *WAFevents) GetSourceCount(filter string) int {
	count := 0
	for _, v := range resp.Result {
		if v.Source == filter {
			count++
		}
	}
	return count
}

// count with filter by Source for list
func (list *ListWAFevents) GetSourceCount(filter string) int {
	count := 0
	for _, page := range list.Pages {
		count = count + page.GetSourceCount(filter)
	}
	return count
}

// get all our zones
// uses cloudflare-go library
func ListZones(token, email string) []cloudflare.Zone {
	// get connect
	api, err := cloudflare.New(token, email)
	if err != nil {
		log.Fatal(err)
	}

	zones, err := api.ListZones()
	if err != nil {
		log.Fatal(err)
	}

	return zones
}

// get part events for WAF and Firewall for one separate zone
// uses resty library and WAFevents structure
func GetPageZoneWAFevents(token, email, zoneID, cursor string, moment time.Time, duration time.Duration) (WAFevents, error) {
	// create client for connection
	client := resty.New()
	// create object with our results
	var events WAFevents
	// some params that we need before start our
	params := map[string]string{
		"limit": "1000",                                                                   //maximum limit of events
		"since": moment.UTC().Add(-duration * time.Second).Format("2006-01-02T15:04:05Z"), //time not before
		"until": moment.UTC().Format("2006-01-02T15:04:05Z"),                              //time not after
	}
	if cursor != "" {
		params["cursor"] = cursor
	}

	// get events of zone for last 5 minutes
	// use reqest and get response (and maybe close)
	resp, err := client.R().
		SetHeaders(map[string]string{
			"Content-Type": "application/json",
			"X-Auth-Email": email,
			"X-Auth-Key":   token,
		}).
		SetQueryParams(params).
		Get(CloudFlareURL + "/zones/" + zoneID + "/security/events")
	if err != nil {
		return events, errors.Wrap(err, errorWAFeventsGet)
		//log.Fatal(err)
	}

	err = json.Unmarshal(resp.Body(), &events)
	if err != nil {
		return events, errors.Wrap(err, errorWAFeventsParse)
		//log.Fatal(err)
	}
	return events, nil
}

func GetAllZoneWAFevents(token, email, zoneID string, moment time.Time, duration time.Duration) (ListWAFevents, error) {
	var events ListWAFevents

	// run first time
	firstTimeEvents, err := GetPageZoneWAFevents(token, email, zoneID, "", moment, duration)
	if err != nil {
		return events, err
	}
	events.Pages = append(events.Pages, firstTimeEvents)

	//analyze our first time
	// if we have some events (resultCount > 0)
	// then try another one time to get next part of data and so on
	// until we have no any events (resultCount == 0)
	resultCount := events.GetResultCount()
	for i := 0; resultCount > 0; i++ {
		nextTimeEvents, err := GetPageZoneWAFevents(token, email, zoneID, events.Pages[i].GetAfterCursor(), moment, duration)
		if err != nil {
			return events, errors.Wrap(err, "Cannot to get page "+strconv.Itoa(i))
		}
		events.Pages = append(events.Pages, nextTimeEvents)
		// get count of events in this page
		resultCount = events.Pages[i+1].GetResultCount()
	}
	return events, nil
}
