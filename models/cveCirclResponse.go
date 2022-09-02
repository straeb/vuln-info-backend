package models

type Circl struct {
	Access struct {
		Authentication string `json:"authentication"`
		Complexity     string `json:"complexity"`
		Vector         string `json:"vector"`
	} `json:"access"`
	Assigner string `json:"assigner"`
	Capec    []struct {
		Id              string   `json:"id"`
		Name            string   `json:"name"`
		Prerequisites   string   `json:"prerequisites"`
		RelatedWeakness []string `json:"related_weakness"`
		Solutions       string   `json:"solutions"`
		Summary         string   `json:"summary"`
	} `json:"capec"`
	Cvss       float64 `json:"cvss"`
	CvssTime   string  `json:"cvss-time"`
	CvssVector string  `json:"cvss-vector"`
	Cwe        string  `json:"cwe"`
	Id         string  `json:"id"`
	Impact     struct {
		Availability    string `json:"availability"`
		Confidentiality string `json:"confidentiality"`
		Integrity       string `json:"integrity"`
	} `json:"impact"`
	LastModified            string `json:"last-modified"`
	Modified                string
	Published               string
	References              []string `json:"references"`
	Summary                 string   `json:"summary"`
	VulnerableConfiguration []struct {
		Id    string `json:"id"`
		Title string `json:"title"`
	} `json:"vulnerable_configuration"`
	VulnerableConfigurationCpe22 []interface{} `json:"vulnerable_configuration_cpe_2_2"`
	VulnerableProduct            []string      `json:"vulnerable_product"`
}
