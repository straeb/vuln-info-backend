package test

import (
	"github.com/mmcdole/gofeed"
	"testing"
	"time"
	"vuln-info-backend/service/core"
)

const descriptionOne = `

<style>
	div.scoring {
		width:200px;
		float:left;
	}
</style>
<div>
<div><b>Bewertung:</b></div>
<div class="scoring">Gesamtbewertung des Risikos:</div> niedrig <br>
<div class="scoring">CVSS Base Score:</div> 8.8 <br>
<div class="scoring">CVSS Exploitability:</div> 2.8 <br>
<div class="scoring">CVSS Impact:</div> 5.9 <br>
<div class="scoring">CVSS Temporal:</div> 8.2 <br>
</div>
<br>
<div>
<b>Betroffene Plattformen:</b>
<ul>
<li>Debian Linux 9.13 Stretch</li>
</ul>
<b>Betroffene Software:</b>
<ul>
<li>LibreCAD</li>
</ul>
</div>
<br>
<div>
<b>Zusammenfassung der Auswirkung:</b><br>
Ein Angreifer kann eine Schwachstelle aus der Ferne ausnutzen, um beliebigen Programmcode auszuführen.

Für die Ausnutzung der Schwachstelle sind keine Privilegien erforderlich. Die Schwachstelle erfordert die Interaktion eines Benutzers.
Für Debian 9 Stretch (LTS) steht ein Sicherheitsupdate für &#39;librecad&#39; in Version 2.1.2-1+deb9u4 bereit, um die Schwachstelle zu beheben.
</div>`

const descriptionTwo = `

<style>
	div.scoring {
		width:200px;
		float:left;
	}
</style>
<div>
<div><b>Bewertung:</b></div>
<div class="scoring">Gesamtbewertung des Risikos:</div> niedrig <br>
<div class="scoring">CVSS Base Score:</div> 1.0 <br>
<div class="scoring">CVSS Exploitability:</div> 2.0 <br>
<div class="scoring">CVSS Impact:</div> 3.0 <br>
<div class="scoring">CVSS Temporal:</div> 4.0 <br>
</div>
<br>
<div>
<b>Betroffene Plattformen:</b>
<ul>
<li>Debian Linux 9.13 Stretch</li>
</ul>
<b>Betroffene Software:</b>
<ul>
<li>LibreCAD</li>
</ul>
</div>
<br>
<div>
<b>Zusammenfassung der Auswirkung:</b><br>
Ein Angreifer kann eine Schwachstelle aus der Ferne ausnutzen, um beliebigen Programmcode auszuführen.

CVE-2021-41159, CVE-2021-41159, CVE-2021-41159, CVE-2021-41159

CVE-2021-41160


Für die Ausnutzung der Schwachstelle sind keine Privilegien erforderlich. Die Schwachstelle erfordert die Interaktion eines Benutzers.
Für Debian 9 Stretch (LTS) steht ein Sicherheitsupdate für &#39;librecad&#39; in Version 2.1.2-1+deb9u4 bereit, um die Schwachstelle zu beheben.
</div>`

var yesterday = time.Now().AddDate(0, 0, -1)
var catgegory = []string{"Typ/Schwachstelle"}

var noCVEItem = &gofeed.Item{
	Title:           "Item 1 CVE-2022-xyz",
	Description:     "dsfgdfg",
	Categories:      catgegory,
	PublishedParsed: &yesterday,
}

var CVEItem = &gofeed.Item{
	Title:           "Item 1 CVE-2022-CVE-2022-38012",
	Description:     descriptionTwo,
	Categories:      catgegory,
	PublishedParsed: &yesterday,
}

var feed1 gofeed.Feed = gofeed.Feed{
	Title: "Test Title Feed",
	Items: []*gofeed.Item{noCVEItem, CVEItem},
}

//Switch between Prod (Docker) & Debug

func TestFindValuableEntries(t *testing.T) {

	defer TearDown()
	SetUp()

	output := core.FindValuableEntries(feed1)
	expected := [3]int{2, 1, 3}
	if output != expected {
		t.Error("Test Failed:  expected {} , recieved: {}", expected, output)
	}

	TearDown()
}
