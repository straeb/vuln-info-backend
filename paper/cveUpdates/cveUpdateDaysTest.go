package cveUpdates

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"testing"
	"time"
	"vuln-info-backend/models"
)

var cves = []string{
	"CVE-2022-21834",
	"CVE-2022-22002",
	"CVE-2022-22717",
	"CVE-2022-24493",
	"CVE-2022-21897",
	"CVE-2022-26918",
	"CVE-2022-23294",
	"CVE-2022-21959",
	"CVE-2022-22008",
	"CVE-2022-24528",
	"CVE-2022-0435",
	"CVE-2021-42778",
	"CVE-2021-3733",
	"CVE-2021-3698",
	"CVE-2021-3948",
	"CVE-2021-3623",
	"CVE-2022-21682",
	"CVE-2021-41817",
	"CVE-2020-25717",
	"CVE-2021-4093",
	"CVE-2022-0797",
	"CVE-2022-0790",
	"CVE-2022-0462",
	"CVE-2022-0470",
	"CVE-2022-0310",
	"CVE-2022-0297",
	"CVE-2022-0290",
	"CVE-2022-0108",
	"CVE-2021-4102",
	"CVE-2022-0103",
	"CVE-2021-4101",
	"CVE-2022-0778",
	"CVE-2022-21824",
	"CVE-2021-44533",
	"CVE-2021-44532",
	"CVE-2021-44531",
	"CVE-2022-21427",
	"CVE-2022-21357",
	"CVE-2022-21326",
	"CVE-2022-21307",
	"CVE-2022-21254",
	"CVE-2021-4206",
	"CVE-2022-26358",
	"CVE-2022-24754",
	"CVE-2022-23648",
	"CVE-2022-0714",
	"CVE-2022-25313",
	"CVE-2022-0534",
	"CVE-2022-0487",
	"CVE-2022-23034",
	"CVE-2021-44716",
	"CVE-2018-25032",
	"CVE-2022-22632",
	"CVE-2022-22590",
	"CVE-2021-42526",
	"CVE-2022-24097",
	"CVE-2022-24960",
	"CVE-2022-0016",
	"CVE-2021-44702",
	"CVE-2021-45980",
	"CVE-2021-40781",
	"CVE-2022-29582",
	"CVE-2022-1353",
	"CVE-2022-1280",
	"CVE-2021-4202",
	"CVE-2022-0492",
	"CVE-2021-20320",
	"CVE-2022-21817",
	"CVE-2022-22310",
	"CVE-2021-38919",
	"CVE-2022-0500",
	"CVE-2022-0854",
	"CVE-2021-3698",
	"CVE-2021-45417",
	"CVE-2021-3631",
}

const BASE_URL = "https://cve.circl.lu/api/cve/"

var callErr = log.New(os.Stderr, "[FETCH] ", log.Ldate|log.Ltime)

var responses []models.Circl

func TestDays(t *testing.T) {

	for _, cve := range cves {

		obj := callCircl(cve)
		if obj.Id != "" {
			responses = append(responses, *obj)

		}
	}

	var days float64
	var diffs []float64
	for _, resp := range responses {

		layout := "2006-01-02T15:04:05"
		last, err := time.Parse(layout, resp.LastModified)
		if err != nil {
			println(resp.LastModified, resp.Id)
			panic(err)
		}
		pub, err := time.Parse(layout, resp.Published)
		if err != nil {
			println(resp.LastModified, resp.Id)
			panic(err)
		}

		diff := last.Sub(pub)

		hours := diff.Hours()

		//fmt.Println(roundFloat((hours / 24), 1))
		fmt.Println(resp.Id)

		days += hours / 24

		diffs = append(diffs, roundFloat((hours/24), 1))

	}

	println("Average Days")
	fmt.Println(days / float64(len(diffs)))
	println("n :")
	println(len(cves))

	for _, diffy := range diffs {
		fmt.Printf("%v, ", diffy)
	}
}

func roundFloat(val float64, precision uint) float64 {
	ratio := math.Pow(10, float64(precision))
	return math.Round(val*ratio) / ratio
}

func callCircl(cve string) *models.Circl {

	client := &http.Client{
		Timeout: time.Second * 20,
	}

	//Build Request
	req, err := http.NewRequest("GET",
		BASE_URL+cve,
		nil)
	if err != nil {
		callErr.Println(err.Error())
		return nil

	}

	req.Header.Set("user-agent", "golang application")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	//req.Header.Add("foo", "bar2")
	response, err := client.Do(req)
	//log.Printf("Fetch: %v\n", BASE_URL+cve)
	if err != nil {
		callErr.Println(err.Error())
		return nil
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			callErr.Println(err.Error())
		}
	}(response.Body)

	//
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		callErr.Println(err.Error())
		return nil
	}

	//Bind Body to Go object
	var respObj models.Circl
	err = json.Unmarshal(body, &respObj)
	if err != nil {
		callErr.Println(err.Error())
		return nil
	}
	return &respObj
}
