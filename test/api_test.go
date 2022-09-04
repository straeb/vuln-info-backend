package test

import (
	"bufio"
	"fmt"
	"github.com/joho/godotenv"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
	"vuln-info-backend/api/handler"
)

func TestApi(t *testing.T) {

	defer TearDown()
	SetUp()

	var wg sync.WaitGroup

	wg.Add(2)
	go runServer(&wg)
	go runScript(&wg)

	time.Sleep(20 * time.Second)
	wg.Done()
}

func runScript(wg *sync.WaitGroup) {
	defer wg.Done()
	err := godotenv.Load("../.env")
	if err != nil {
		log.Panicln(err.Error())
	}
	os.Setenv("SECRET", "secret")

	cmd := exec.Command("python", "api_test_script.py")
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
}

func runServer(wg *sync.WaitGroup) {
	defer wg.Done()
	handler.InitRouting(true)
}

func copyOutput(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
}
