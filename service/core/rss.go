package core

import (
	"github.com/mmcdole/gofeed"
	"golang.org/x/net/html"
	"log"
	"regexp"
	"strings"
	"time"
	"vuln-info-backend/models"
	"vuln-info-backend/persistance/crud"
)

var lastEntry time.Time

var notification crud.NotificationCRUD

const FEED_CATEGORY_VULN = "Typ/Schwachstelle"

/*
CheckFeed fetches the feed URL and calls the Parser,
if there are new items since the last update of the feed.
*/
func CheckFeed(dfnURL string) {
	fp := gofeed.NewParser()

	feed, err := fp.ParseURL(dfnURL)
	if err != nil {
		log.Println(err.Error())
	} else {
		log.Println("RSS: Checking Feed: ", feed.Title)

		//Check if the feed contains new updates since the last refresh
		if feed.UpdatedParsed.After(lastEntry) {
			FindValuableEntries(*feed)
			lastEntry = *feed.Items[0].PublishedParsed

		} else {
			log.Printf("RSS: Nothing new in %v\n", feed.Title)
		}
	}

}

/*
findValuableEntries loops the new items, which are of type "Schwachstelle"
and searches for occurring CVE identifiers in the body and the title.
If so, a new notification object gets created in the database.

*/
func FindValuableEntries(feed gofeed.Feed) [3]int {

	//
	newEntriesCount := 0
	valuableEntriesCount := 0
	cvesCount := 0

	for _, item := range feed.Items {

		//Feed also contains other information than vulnerability info
		if item.Categories[0] == FEED_CATEGORY_VULN &&

			//This function is only called, when there are new entries, but
			//var feed also bring old entries with it, so only the new ones
			//are checked
			item.PublishedParsed.After(lastEntry) {
			newEntriesCount++

			//Map to find put the found CVEs in.
			//Map because the key has to be unique and duplicates get avoided
			var cves = make(map[string]int)

			scores := parseScores(item.Description)

			//Also check the item title, because sometimes CVEs are in there as well
			getCVEs(item.Title, &cves)
			parseDescription(item.Description, &cves)

			if len(cves) > 0 {
				valuableEntriesCount++
				cvesCount = cvesCount + len(cves)
				vulns := getVulnObjs(cves)
				saveNotification(*item, scores, vulns)
				cves = nil

			} else {
				saveNotification(*item, scores, []models.Vulnerability{})
			}

		}
	}

	log.Printf("RSS: Checked %v new entries in %v. Found %v valuable entries, containing %v CVEs.",
		newEntriesCount, feed.Title, valuableEntriesCount, cvesCount)
	return [3]int{newEntriesCount, valuableEntriesCount, cvesCount}
}

/*
getVulnObjs takes the map of the pre found CVE stings, checks them
against the Database and returns the according vulnerability objects.
Otherwise, it will be created and returned afterwards.
Additionally, information about CVE Description and assigned CWE will
be added from the Circl API. This information will also be updated in
the MatchCPEs function.
*/
func getVulnObjs(cves map[string]int) []models.Vulnerability {
	var vulns []models.Vulnerability

	for cve, _ := range cves {
		// Get additional information
		info := callCircl(cve)

		var summary string
		var cwe string

		// Escape null pointer in case info obj is nil
		if info == nil {
			summary = ""
			cwe = ""
		} else {
			summary = info.Summary
			cwe = info.Cwe
		}

		vuln, _ := vulnerability.UpdateOrCreate(
			models.CreateVulnerabilityInput{
				CVEId:       cve,
				Description: summary,
				CWE:         cwe,
			})
		vulns = append(vulns, *vuln)
	}

	return vulns

}

func saveNotification(item gofeed.Item, scores map[string]string, vulns []models.Vulnerability) {
	//Create the new object...
	notificationObj := models.CreateNotificationInput{
		PubDate:         item.PublishedParsed,
		Title:           item.Title,
		Link:            item.Link,
		CVSSbase:        scores["CVSS Base Score"],
		CVSSEx:          scores["CVSS Exploitability"],
		CVSSimpact:      scores["CVSS Impact"],
		CVSStemp:        scores["CVSS Temporal"],
		Message:         item.Description,
		Vulnerabilities: vulns,
	}
	//... and save it
	notification.Create(notificationObj)

}

/*
parseScores Gets the scores from the Body of the message. Scores are separately
used in the notification object, because they are good indicator of prioritization
and are valuable for filtering in the UI.
*/
func parseScores(text string) map[string]string {

	tkn := html.NewTokenizer(strings.NewReader(text))

	var scores = make(map[string]string)

	var isBaseScore bool
	var isExplScore bool
	var isImpact bool
	var isTemp bool

	for {
		tt := tkn.Next()

		switch {
		case tt == html.ErrorToken:
			return scores

		case tt == html.TextToken:
			t := tkn.Token()
			// Wanted Part of the Item
			if isBaseScore {
				scores["CVSS Base Score"] = strings.ReplaceAll(t.Data, " ", "")
				isBaseScore = false
			}
			if isExplScore {
				scores["CVSS Exploitability"] = strings.ReplaceAll(t.Data, " ", "")
				isExplScore = false
			}
			if isImpact {
				scores["CVSS Impact"] = strings.ReplaceAll(t.Data, " ", "")
				isImpact = false
			}
			if isTemp {
				scores["CVSS Temporal"] = strings.ReplaceAll(t.Data, " ", "")
				isTemp = false
			}

			// Keys for the CVSS Scores
			isBaseScore = t.Data == "CVSS Base Score:"
			isExplScore = t.Data == "CVSS Exploitability:"
			isImpact = t.Data == "CVSS Impact:"
			isTemp = t.Data == "CVSS Temporal:"
		}

	}

}

/*
parseDescription Function iterates over the description part of the Item and searches
for the headline "Zusammenfassung der Auswirkungen", because that's where
the CVEs are usually in. In the next iteration it passes the related text
to the getCVEs function, which fills the map with the findings.
Only text tokens are used as anchor because the html in the items is usually
of bad quality
*/
func parseDescription(text string, cves *map[string]int) {

	tkn := html.NewTokenizer(strings.NewReader(text))

	var isZSF bool

	for {
		tt := tkn.Next()

		switch {
		case tt == html.ErrorToken:
			return

		case tt == html.TextToken:
			t := tkn.Token()
			//Step 2
			//Take the Test and pass it
			if isZSF {
				// Check for included CVEs
				getCVEs(t.Data, cves)
				isZSF = false

			}
			//Step 1
			//Find the headline
			zsf := strings.ReplaceAll(strings.ToLower(t.Data), " ", "")
			isZSF = zsf == "zusammenfassungderauswirkung:"

		}

	}

}

/*
getCVEs Finds the strings that match the ReEx for are NIST specified CVE number
and puts it in the map, allocated in findValuableEntries
*/
func getCVEs(txt string, output *map[string]int) {
	var regex = regexp.MustCompile(`CVE-\d\d\d\d-\d\d\d\d+\b`)

	for i, match := range regex.FindAllString(txt, -1) {
		match = strings.ReplaceAll(match, " ", "")
		(*output)[match] = i
	}

}
