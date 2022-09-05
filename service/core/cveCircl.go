package core

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"
	"vuln-info-backend/models"
)

const BASE_URL = "https://cve.circl.lu/api/cve/"

func callCircl(cve string) *models.Circl {

	client := &http.Client{
		Timeout: time.Second * 10,
	}

	//Build Request
	req, err := http.NewRequest("GET",
		BASE_URL+cve,
		nil)
	if err != nil {
		log.Printf(err.Error())
		return nil

	}

	req.Header.Set("user-agent", "golang application")
	req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	//req.Header.Add("foo", "bar2")
	response, err := client.Do(req)
	log.Printf("Fetch: %v\n", BASE_URL+cve)
	if err != nil {
		log.Printf(err.Error())
		return nil
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Printf(err.Error())
		}
	}(response.Body)

	//
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Printf(err.Error())
		return nil
	}

	//Bind Body to Go object
	var respObj models.Circl
	err = json.Unmarshal(body, &respObj)
	if err != nil {
		log.Printf(err.Error())
		return nil
	}
	return &respObj
}
