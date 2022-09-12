package PoC

import (
	"bufio"
	"fmt"
	"github.com/joho/godotenv"
	"github.com/mmcdole/gofeed"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
	"vuln-info-backend/api/handler"
	db "vuln-info-backend/persistance/crud"
	"vuln-info-backend/service/core"
	"vuln-info-backend/test"
)

const description1 = `
<div>
<div><b>Bewertung:</b></div>
<div class="scoring">Gesamtbewertung des Risikos:</div> niedrig <br>
<div class="scoring">CVSS Base Score:</div> 1.0 <br>
<div class="scoring">CVSS Exploitability:</div> 2.0 <br>
<div class="scoring">CVSS Impact:</div> 3.0 <br>
<div class="scoring">CVSS Temporal:</div> 4.0 <br>

<b>Zusammenfassung der Auswirkung:</b><br>

CVE-2021-41159, CVE-2021-41159, CVE-2021-41159, CVE-2021-41159

CVE-2021-41160

</div>`

const description2 = `
<div>
<div><b>Bewertung:</b></div>
<div class="scoring">Gesamtbewertung des Risikos:</div> niedrig <br>
<div class="scoring">CVSS Base Score:</div> 1.0 <br>
<div class="scoring">CVSS Exploitability:</div> 2.0 <br>
<div class="scoring">CVSS Impact:</div> 3.0 <br>
<div class="scoring">CVSS Temporal:</div> 4.0 <br>

<b>Zusammenfassung der Auswirkung:</b><br>

CVE-2021-44228
CVE-2021-41160
</div>`

const description3 = `
<div>
<div><b>Bewertung:</b></div>
<div class="scoring">Gesamtbewertung des Risikos:</div> niedrig <br>
<div class="scoring">CVSS Base Score:</div> 1.0 <br>
<div class="scoring">CVSS Exploitability:</div> 2.0 <br>
<div class="scoring">CVSS Impact:</div> 3.0 <br>
<div class="scoring">CVSS Temporal:</div> 4.0 <br>

<b>Zusammenfassung der Auswirkung:</b><br>

</div>`

var yesterday = time.Now().AddDate(0, 0, -1)
var catgegory = []string{"Typ/Schwachstelle"}

var CVEItem1 = &gofeed.Item{
	Title:           "FreeRDP",
	Description:     description1,
	Categories:      catgegory,
	PublishedParsed: &yesterday,
	Link:            "1",
}

var CVEItem2 = &gofeed.Item{
	Title:           "FreeRDP + Log4j",
	Description:     description2,
	Categories:      catgegory,
	PublishedParsed: &yesterday,
	Link:            "2",
}
var CVEItem3 = &gofeed.Item{
	Title:           "Windows CVE-2022-21907",
	Description:     description3,
	Categories:      catgegory,
	PublishedParsed: &yesterday,
	Link:            "3",
}

var feed gofeed.Feed = gofeed.Feed{
	Title: "PoC Feed",
	Items: []*gofeed.Item{CVEItem1, CVEItem2, CVEItem3},
}

var vendorCRUD = db.VendorCRUD{}

/*
Please use the empty test DB from test/docker-compose.test.yml
*/
func TestPoC(t *testing.T) {

	test.SetUp()
	defer test.TearDown()

	output := core.FindValuableEntries(feed)
	expected := [3]int{3, 3, 5}
	if output != expected {
		t.Error("Test Failed:  expected {} , recieved: {}", expected, output)
	}

	var wg sync.WaitGroup

	wg.Add(2)
	go runServer(&wg)
	go runScript(&wg)

	wg.Done()

	time.Sleep(10 * time.Second)

	_, err := vendorCRUD.GetByName("fail=0")
	if err != nil {
		t.Error("API test failed")
	}

}

func runScript(wg *sync.WaitGroup) bool {
	defer wg.Done()
	err := godotenv.Load("../../.env")
	if err != nil {
		log.Panicln(err.Error())
	}
	os.Setenv("SECRET", "secret")

	cmd := exec.Command("python", "client.py")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		panic(err)
	}
	stderr, err := cmd.StderrPipe()

	if err != nil {
		panic(err)
	}
	err = cmd.Start()
	if err != nil {
		panic(err)
	}

	go copyOutput(stdout)
	go copyOutput(stderr)

	cmd.Wait()

	return true

}

func runServer(wg *sync.WaitGroup) {
	defer wg.Done()
	handler.InitRouting(false)
}

func copyOutput(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
}
