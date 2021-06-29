package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type c struct {
	Proxy     string `json:"proxy"`
	Password  string `json:"password"`
	PID       string `json:"pID"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

var (
	csrfRegex = regexp.MustCompile(`"[a-z0-9]{32}"`)
	accs      = []*account{}
	config    = &c{}
)

func init() {
	f, err := os.ReadFile("accounts.json")
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(f, &accs)
	if err != nil {
		panic(err)
	}
	f, err = os.ReadFile("config.json")
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(f, &config)
	if err != nil {
		panic(err)
	}
}

func getCookies(c *http.Client) ([]string, string) {
	req, err := http.NewRequest("GET", "https://www.change.org/", nil)
	if err != nil {
		return []string{}, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36 OPR/76.0.4017.208")
	req.Header.Set("Accept", "*/*")
	resp, err := c.Do(req)
	if err != nil {
		return []string{}, ""
	}
	defer resp.Body.Close()
	cookies, ok := resp.Header["Set-Cookie"]
	if !ok {
		return []string{}, ""
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return []string{}, ""
	}
	csrf := csrfRegex.FindString(string(b))
	return cookies, strings.ReplaceAll(csrf, "\"", "")
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// RandStringBytes generates a random string x letters long
func RandStringBytes(n int) string {
	time.Sleep(5 * time.Nanosecond)
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

type accountRegister struct {
	ValidateAs             string      `json:"validateAs"`
	FirstName              string      `json:"first_name"`
	LastName               string      `json:"last_name"`
	OrganizationName       string      `json:"organization_name"`
	Email                  string      `json:"email"`
	Password               string      `json:"password"`
	MarketingCommsConsent  interface{} `json:"marketing_comms_consent"`
	ShouldValidatePassword bool        `json:"shouldValidatePassword"`
	Locale                 string      `json:"locale"`
	InSapFlow              string      `json:"in_sap_flow"`
	UsingPendingPetitions  bool        `json:"using_pending_petitions"`
}

type account struct {
	Email     string   `json:"email"`
	Password  string   `json:"password"`
	Cookies   []string `json:"cookies"`
	UserID    int      `json:"id"`
	UUID      string   `json:"uuid"`
	FirstName string   `json:"first_name"`
	LastName  string   `json:"last_name"`
	CSRF      string   `json:"csrf"`
}

func registerAccount(c *http.Client, email, password, csrf string, cookies []string) *account {
	acc := &accountRegister{}
	acc.Email = email
	acc.Password = password
	acc.Locale = "en-US"
	acc.MarketingCommsConsent = nil
	acc.FirstName = config.FirstName
	acc.LastName = config.LastName
	acc.ValidateAs = "save"
	body, _ := json.Marshal(acc)
	req, err := http.NewRequest("POST", "https://www.change.org/api-proxy/-/users", strings.NewReader(string(body)))
	if err != nil {
		fmt.Println(err)
		return nil
	}
	req.Header.Set("Cookie", strings.Join(cookies, " ")+" G_ENABLED_IDPS=google")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36 OPR/76.0.4017.208")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Host", "www.change.org")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Content-Length", fmt.Sprint(len(string(body))))
	req.Header.Set("sec-ch-ua", `"Chromium";v="90", "Opera GX";v="76", ";Not A Brand";v="99"`)
	req.Header.Set("X-CSRF-Token", csrf)
	req.Header.Set("X-Requested-With", "jquery")
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("Origin", "https://www.change.org")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Referer", "https://www.change.org/")
	resp, err := c.Do(req)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	if resp.StatusCode == 201 {
		a := &account{}

		err = json.Unmarshal(b, &a)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		a.Email = email
		a.Password = password
		a.CSRF = csrf
		cookies2, ok := resp.Header["Set-Cookie"]
		if !ok {
			return nil
		}
		for i := 0; i < len(cookies2); i++ {
			cookies2[i] = strings.Split(cookies2[i], " ")[0]
		}
		for _, cookie := range cookies2 {
			cookies = append(cookies, cookie)
		}
		a.Cookies = cookies
		return a
	}
	fmt.Println(string(b))
	return nil
}

// MIGHT CAUSE PROBLEMS WITH CONCURRENT WRITING OF FILES
func saveAccount(acc *account) {
	accs = append(accs, acc)
	b, err := json.Marshal(accs)
	if err != nil {
		fmt.Println(err)
		return
	}
	os.WriteFile("accounts.json", b, 0064)
}

func signPetition(c *http.Client, acc *account, ID string) {
	req, err := http.NewRequest("POST", "https://www.change.org/api-proxy/-/signatures/"+ID, strings.NewReader(fmt.Sprintf(`{"petition_id":"%s","country_code":"US","enable_human_verification":false,"display_name":"%s","first_name":"%s","last_name":"%s","city":"","state_code":"","email":"%s","address":null,"postal_code":"","phone_number":null,"page_context":"petitions_show","alert_id":"","message":"","public":true,"traffic_metadata":{}}`, ID, acc.FirstName+" "+acc.LastName, acc.FirstName, acc.LastName, acc.Email)))
	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Set("Cookie", strings.Join(acc.Cookies, " ")+" G_ENABLED_IDPS=google")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36 OPR/76.0.4017.208")
	req.Header.Set("Accept", "application/json, text/javascript, */*; q=0.01")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Host", "www.change.org")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Content-Length", fmt.Sprint(len(fmt.Sprintf(`{"petition_id":"%s","country_code":"US","enable_human_verification":false,"display_name":"%s","first_name":"%s","last_name":"%s","city":"","state_code":"","email":"%s","address":null,"postal_code":"","phone_number":null,"page_context":"petitions_show","alert_id":"","message":"","public":true,"traffic_metadata":{}}`, ID, acc.FirstName+" "+acc.LastName, acc.FirstName, acc.LastName, acc.Email))))
	req.Header.Set("sec-ch-ua", `"Chromium";v="90", "Opera GX";v="76", ";Not A Brand";v="99"`)
	req.Header.Set("X-CSRF-Token", acc.CSRF)
	req.Header.Set("X-Requested-With", "jquery")
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("Origin", "https://www.change.org")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Referer", "https://www.change.org/")

	resp, err := c.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(b))
	if resp.StatusCode == 200 {
		fmt.Println("Added signature!")
		return
	}

	return

}

func makeClient(proxy string) *http.Client {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	proxyURL, _ := url.Parse(proxy)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: tlsConfig,
		Proxy:           http.ProxyURL(proxyURL),
	},
		Timeout: 60 * time.Second,
	}
	return client
}

func main() {
	for {
		wg := sync.WaitGroup{}
		for i := 0; i < 5; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				client := makeClient(config.Proxy)
				cookies, csrf := getCookies(client)
				if len(cookies) < 1 {
					fmt.Println("Failed to get cookies!")
					return
				}
				for i := 0; i < len(cookies); i++ {
					cookies[i] = strings.Split(cookies[i], " ")[0]
				}
				email := RandStringBytes(20) + "@mailo.xyz"
				password := config.Password
				acc := registerAccount(client, email, password, csrf, cookies)
				if acc == nil {
					fmt.Println("Failed to register account!")
					return
				}
				saveAccount(acc)
				signPetition(client, acc, config.PID)
			}()
		}
		wg.Wait()
	}
}
