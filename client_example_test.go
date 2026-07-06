package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"reflect"
	"sort"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

// --- KDF and Encryption Constants (must match server) ---
const (
	saltSizeClient           = 8
	pbkdf2IterationsClient   = 4096
	appIntegritySecretClient = "a-very-secret-string-for-app-integrity"
)

// Client-side representation of the server's encrypted response
type EncryptedResponseClient struct {
	Payload string `json:"payload"`
}

// The decryptClient function, updated to handle PBKDF2-derived keys.
func decryptClient(payloadB64 string, password []byte) ([]byte, error) {
	// 1. Base64 decode the entire payload
	data, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, err
	}

	// 2. Extract the salt (it's prepended to the data)
	if len(data) < saltSizeClient {
		return nil, fmt.Errorf("payload is too short to contain salt")
	}
	salt := data[:saltSizeClient]
	encryptedData := data[saltSizeClient:] // The rest is [nonce + ciphertext]

	// 3. Re-derive the key using the same PBKDF2 parameters as the server
	derivedKey := pbkdf2.Key(password, salt, pbkdf2IterationsClient, 32, sha256.New)

	// 4. Decrypt using AES-GCM
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("ciphertext is too short to contain nonce")
	}

	// The nonce is prepended to the actual ciphertext
	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]

	// Decrypt and verify the authentication tag
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// getTestJWT is a helper function to avoid code duplication. It authenticates and returns a JWT.
func getTestJWT(t *testing.T) (jwtToken string, longTermKey string) {
	t.Helper() // Marks this as a helper function

	baseURL := "http://127.0.0.1:3839"
	key := "CF67355A3333E6E143439161ADC2D82E"

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", baseURL+"/validate", nil)
	if err != nil {
		t.Fatalf("Helper failed to create request: %v", err)
	}
	req.Header.Set("X-Token", key)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Helper failed to send validation request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Helper validation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResponse struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		t.Fatalf("Helper failed to decode token response: %v", err)
	}
	resp.Body.Close()

	return tokenResponse.Token, key
}

// calculateSignature creates the integrity signature for a request.
func calculateSignature(path string, timestamp string) string {
	payload := fmt.Sprintf("%s,%s,%s", path, timestamp, appIntegritySecretClient)
	hasher := sha256.New()
	hasher.Write([]byte(payload))
	return hex.EncodeToString(hasher.Sum(nil))
}

// fetchAndDecrypt is a generic helper to call the gateway endpoint and decrypt the response.
func fetchAndDecrypt(t *testing.T, jwtToken, longTermKey, target, param string) []byte {
	t.Helper()

	// 1. Prepare request body
	reqBody := map[string]string{
		"target": target,
		"p":      param,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	// 2. Create and send request
	client := &http.Client{Timeout: 10 * time.Second}
	path := "/api/v1/gateway"
	req, err := http.NewRequest("POST", "http://127.0.0.1:3839"+path, bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("Failed to create gateway request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	signature := calculateSignature(path, timestamp) // Assumes calculateSignature helper exists
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Signature", signature)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send gateway request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("Gateway request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var encryptedResp EncryptedResponseClient
	if err := json.NewDecoder(resp.Body).Decode(&encryptedResp); err != nil {
		t.Fatalf("Failed to decode encrypted response: %v", err)
	}

	// 3. Decrypt payload
	decryptedPayload, err := decryptClient(encryptedResp.Payload, []byte(longTermKey))
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %v", err)
	}

	return decryptedPayload
}

// TestFetchMenusViaGateway demonstrates calling the new obfuscated gateway endpoint.
func TestFetchMenusViaGateway(t *testing.T) {
	// First, get a valid JWT to use for subsequent requests.
	jwtToken, longTermKey := getTestJWT(t)
	log.Println("--- Successfully obtained JWT for gateway tests ---")

	// --- Scenario 1: Fetch the Main Menu ---
	log.Println("\n--- Fetching Main Menu via Gateway (target: a1) ---")

	// Call the helper to get the decrypted main menu payload
	mainMenuPayload := fetchAndDecrypt(t, jwtToken, longTermKey, "a1", "")

	// Unmarshal the decrypted payload into a string slice
	var mainMenu []string
	if err := json.Unmarshal(mainMenuPayload, &mainMenu); err != nil {
		t.Fatalf("Failed to unmarshal main menu: %v", err)
	}

	fmt.Println("Decrypted Main Menu Items:")
	for _, item := range mainMenu {
		fmt.Printf("- %s\n", item)
	}
	// Here you would pass `mainMenu` to your promptui.Select `Items` field.

	// --- Scenario 2: Fetch the "Turntable" Sub-Menu ---
	log.Println("\n--- Fetching 'Turntable' Sub-Menu via Gateway (target: b2, p: d8a7f1) ---")

	// Call the helper to get the decrypted sub-menu payload
	// Note: "d8a7f1" is the obfuscated ID for "转盘" defined on the server.
	subMenuPayload := fetchAndDecrypt(t, jwtToken, longTermKey, "b2", "d8a7f1")

	// Unmarshal the decrypted payload
	var subMenu []string
	if err := json.Unmarshal(subMenuPayload, &subMenu); err != nil {
		t.Fatalf("Failed to unmarshal sub-menu: %v", err)
	}

	fmt.Println("Decrypted 'Turntable' Sub-Menu Items:")
	for _, item := range subMenu {
		fmt.Printf("- %s\n", item)
	}
	// Here you would pass `subMenu` to your second promptui.Select `Items` field.
}

// TestFetchRemoteConfigViaGateway demonstrates fetching remote configuration URLs.
func TestFetchRemoteConfigViaGateway(t *testing.T) {
	jwtToken, longTermKey := getTestJWT(t)
	log.Println("--- Successfully obtained JWT for gateway tests ---")

	log.Println("\n--- Fetching Remote Config URLs via Gateway (target: c3) ---")

	// Call the helper to get the decrypted config payload
	configPayload := fetchAndDecrypt(t, jwtToken, longTermKey, "c3", "")

	// Unmarshal the decrypted payload into a map
	var urlConfig map[string]string
	if err := json.Unmarshal(configPayload, &urlConfig); err != nil {
		t.Fatalf("Failed to unmarshal url config: %v", err)
	}

	fmt.Println("Decrypted Remote Config URLs:")
	for key, val := range urlConfig {
		fmt.Printf("- %s: %s\n", key, val)
	}

	// Verification
	if urlConfig["products"] == "" {
		t.Errorf("Products URL is empty in the fetched config")
	}
	if urlConfig["wanneng"] == "" {
		t.Errorf("Wanneng URL is empty in the fetched config")
	}
}

// TestGetRoundViaGateway demonstrates fetching and processing round data via the gateway.
func TestGetRoundViaGateway(t *testing.T) {
	jwtToken, longTermKey := getTestJWT(t)
	log.Println("--- Successfully obtained JWT for gateway tests ---")

	// --- Scenario 1: Fetch "universal" round data ---
	log.Println("\n--- Fetching 'universal' round data via Gateway (target: d4, p: u1) ---")

	// Call the helper to get the decrypted round data payload
	universalPayload := fetchAndDecrypt(t, jwtToken, longTermKey, "d4", "u1")

	// Unmarshal the decrypted payload into a slice of ValidRound
	var universalRounds []ValidRound
	if err := json.Unmarshal(universalPayload, &universalRounds); err != nil {
		t.Fatalf("Failed to unmarshal universal rounds: %v", err)
	}

	fmt.Println("Decrypted 'universal' Round Data:")
	if len(universalRounds) > 0 {
		for i, round := range universalRounds {
			fmt.Printf("- Item %d: Name=%s, Url=%s\n", i+1, round.Name, round.Url)
		}
	} else {
		fmt.Println("(No rounds found for this type)")
	}

	// --- Scenario 2: Fetch "wanneng" round data ---
	log.Println("\n--- Fetching 'wanneng' round data via Gateway (target: d4, p: w1) ---")

	// Call the helper to get the decrypted round data payload
	wannengPayload := fetchAndDecrypt(t, jwtToken, longTermKey, "d4", "w1")

	// Unmarshal the decrypted payload
	var wannengRounds []ValidRound
	if err := json.Unmarshal(wannengPayload, &wannengRounds); err != nil {
		t.Fatalf("Failed to unmarshal wanneng rounds: %v", err)
	}

	fmt.Println("Decrypted 'wanneng' Round Data:")
	if len(wannengRounds) > 0 {
		for i, round := range wannengRounds {
			fmt.Printf("- Item %d: Name=%s, Url=%s\n", i+1, round.Name, round.Url)
		}
	} else {
		fmt.Println("(No rounds found for this type)")
	}
}

// TestFetchSecretPairViaGateway demonstrates fetching a secret key/value pair.
func TestFetchSecretPairViaGateway(t *testing.T) {
	jwtToken, longTermKey := getTestJWT(t)
	log.Println("--- Successfully obtained JWT for gateway tests ---")

	log.Println("\n--- Fetching Secret K/V Pair via Gateway (target: e5) ---")

	// Call the helper to get the decrypted config payload
	secretPayload := fetchAndDecrypt(t, jwtToken, longTermKey, "e5", "")

	// Unmarshal the decrypted payload into a map
	var secretPair map[string]string
	if err := json.Unmarshal(secretPayload, &secretPair); err != nil {
		t.Fatalf("Failed to unmarshal secret pair: %v", err)
	}

	fmt.Println("Decrypted Secret Key/Value Pair:")
	fmt.Printf("- Key: %s\n- Value: %s\n", secretPair["key"], secretPair["value"])

	// Verification
	if secretPair["key"] != "secret" {
		t.Errorf("Secret key does not match expected. Got '%s'", secretPair["key"])
	}
	if secretPair["value"] != "c1714e41e5a907874c59a4d81a8486ea" {
		t.Errorf("Secret value does not match expected. Got '%s'", secretPair["value"])
	}
}

// TestFetchAnotherSecretStringViaGateway demonstrates fetching another secret string.
func TestFetchAnotherSecretStringViaGateway(t *testing.T) {
	jwtToken, longTermKey := getTestJWT(t)
	log.Println("--- Successfully obtained JWT for gateway tests ---")

	log.Println("\n--- Fetching Another Secret String via Gateway (target: f6) ---")

	// Call the helper to get the decrypted config payload
	secretStringPayload := fetchAndDecrypt(t, jwtToken, longTermKey, "f6", "")

	// Unmarshal the decrypted payload into a string
	var secretString string
	if err := json.Unmarshal(secretStringPayload, &secretString); err != nil {
		t.Fatalf("Failed to unmarshal secret string: %v", err)
	}

	fmt.Println("Decrypted Another Secret String:")
	fmt.Printf("- String: %s\n", secretString)

	// Verification
	if secretString != "hbktahqbyihfiidc" {
		t.Errorf("Secret string does not match expected. Got '%s'", secretString)
	}
}

// TestSortKeysViaGateway demonstrates sending a map and receiving its sorted keys.
func TestSortKeysViaGateway(t *testing.T) {
	jwtToken, longTermKey := getTestJWT(t)
	log.Println("--- Successfully obtained JWT for gateway tests ---")

	log.Println("\n--- Sending params map and fetching sorted keys via Gateway (target: g7) ---")

	// Prepare the params array (variable length, obfuscated values)
	paramsToSend := []string{"a", "b", "c", "d"}

	// 1. Prepare request body
	reqBody := map[string]any{ // Use any for params field
		"target": "g7",
		"params": paramsToSend,
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("Failed to marshal request body: %v", err)
	}

	// 2. Create and send request
	client := &http.Client{Timeout: 10 * time.Second}
	path := "/api/v1/gateway"
	req, err := http.NewRequest("POST", "http://127.0.0.1:3839"+path, bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("Failed to create gateway request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwtToken)

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	signature := calculateSignature(path, timestamp)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Signature", signature)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send gateway request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("Gateway request failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var encryptedResp EncryptedResponseClient
	if err := json.NewDecoder(resp.Body).Decode(&encryptedResp); err != nil {
		t.Fatalf("Failed to decode encrypted response: %v", err)
	}

	// 3. Decrypt payload
	decryptedPayload, err := decryptClient(encryptedResp.Payload, []byte(longTermKey))
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %v", err)
	}

	// Unmarshal the decrypted payload into a slice of strings
	var sortedKeys []string
	if err := json.Unmarshal(decryptedPayload, &sortedKeys); err != nil {
		t.Fatalf("Failed to unmarshal sorted keys: %v", err)
	}

	fmt.Println("Decrypted Sorted Keys:")
	for _, key := range sortedKeys {
		fmt.Printf("- %s\n", key)
	}

	// Verification
	expectedKeys := []string{"a", "b", "c", "d", "secret"}
	sort.Strings(expectedKeys) // Sort the expected keys for comparison
	if !reflect.DeepEqual(sortedKeys, expectedKeys) {
		t.Errorf("Sorted keys do not match expected. Got %v, want %v", sortedKeys, expectedKeys)
	}
}

// TestFetchActOnClickStringViaGateWay demonstrates fetching ActOnClickString string.
func TestFetchActOnClickStringViaGateWay(t *testing.T) {
	jwtToken, longTermKey := getTestJWT(t)
	log.Println("--- Successfully obtained JWT for gateway tests ---")

	log.Println("\n--- Fetching Act OnClick String via Gateway (target: f1) ---")

	// Call the helper to get the decrypted config payload
	actOnClickStringPayload := fetchAndDecrypt(t, jwtToken, longTermKey, "f1", "")

	// Unmarshal the decrypted payload into a string
	var actOnClickString string
	if err := json.Unmarshal(actOnClickStringPayload, &actOnClickString); err != nil {
		t.Fatalf("Failed to unmarshal Act OnClick string: %v", err)
	}

	fmt.Println("Decrypted Act OnClick String:")
	fmt.Printf("- String: %s\n", actOnClickString)

	// Verification
	if actOnClickString != ".task-prize a.daily_before1_btn_" {
		t.Errorf("Act OnClick string does not match expected. Got '%s'", actOnClickString)
	}
}

// TestFetchActOnClickStringViaGateWay demonstrates fetching CornFarmStringArray array.
func TestCornFarmStringArrayViaGateWay(t *testing.T) {
	jwtToken, longTermKey := getTestJWT(t)
	log.Println("--- Successfully obtained JWT for gateway tests ---")

	log.Println("\n--- Fetching CornFarm Array via Gateway (target: f111) ---")

	// Call the helper to get the decrypted config payload
	CornFarmArrayStringPayload := fetchAndDecrypt(t, jwtToken, longTermKey, "f111", "")

	// Unmarshal the decrypted payload into a string
	var cornFarmArrayString []string
	if err := json.Unmarshal(CornFarmArrayStringPayload, &cornFarmArrayString); err != nil {
		t.Fatalf("Failed to unmarshal CornFarm array: %v", err)
	}

	fmt.Println("Decrypted CornFarm Array:")
	fmt.Printf("- Array String: %v\n", cornFarmArrayString)

	// Verification
	expectKeys := []string{"pageToken", "pageRandomStr", "xiaoyouxiInfo"}
	if !reflect.DeepEqual(cornFarmArrayString, expectKeys) {
		t.Errorf("CornFarm array does not match expected. Got '%v'", cornFarmArrayString)
	}
}

func TestRegexpGetVarValueViaGateWay(t *testing.T) {
	jwtToken, longTermKey := getTestJWT(t)
	log.Println("--- Successfully obtained JWT for gateway tests ---")

	log.Println("\n--- Fetching Reg via Gateway (target: f111) ---")

	// Call the helper to get the decrypted config payload
	RegPayload := fetchAndDecrypt(t, jwtToken, longTermKey, "tt", "")

	// Unmarshal the decrypted payload into a string
	var Reg []string
	if err := json.Unmarshal(RegPayload, &Reg); err != nil {
		t.Fatalf("Failed to unmarshal Reg: %v", err)
	}

	fmt.Println("Decrypted Reg Array:")
	fmt.Printf("- Reg Array: %v\n", Reg)

	// Verification
	expectKeys := []string{`var\s+%s\s*=\s*(['"])([^'"]*)(['"])`, `var\s+%s\s*=\s*([^;\r\n]+)`}
	if !reflect.DeepEqual(Reg, expectKeys) {
		t.Errorf("Reg array does not match expected. Got '%v'", Reg)
	}
}

func TestRegexpGetVarJsonValueViaGateWay(t *testing.T) {
	jwtToken, longTermKey := getTestJWT(t)
	log.Println("--- Successfully obtained JWT for gateway tests ---")

	log.Println("\n--- Fetching Reg via Gateway (target: f111) ---")

	// Call the helper to get the decrypted config payload
	RegPayload := fetchAndDecrypt(t, jwtToken, longTermKey, "t", "")

	// Unmarshal the decrypted payload into a string
	var Reg []string
	if err := json.Unmarshal(RegPayload, &Reg); err != nil {
		t.Fatalf("Failed to unmarshal Reg: %v", err)
	}

	fmt.Println("Decrypted Reg Array:")
	fmt.Printf("- Reg Array: %v\n", Reg)

	// Verification
	expectKeys := []string{`var\s+%s\s*=\s*({[^\r\n]+});`}
	if !reflect.DeepEqual(Reg, expectKeys) {
		t.Errorf("Reg array does not match expected. Got '%v'", Reg)
	}
}

// TestFetchFarmUrlsViaGateway demonstrates fetching remote farm configuration URLs.
func TestFetchFarmUrlsViaGateway(t *testing.T) {
	jwtToken, longTermKey := getTestJWT(t)
	log.Println("--- Successfully obtained JWT for gateway tests ---")

	log.Println("\n--- Fetching Farm URLs via Gateway (target: c4) ---")

	// Call the helper to get the decrypted config payload
	configPayload := fetchAndDecrypt(t, jwtToken, longTermKey, "c4", "")

	// Unmarshal the decrypted payload into a slice of strings
	var urlConfig []string
	if err := json.Unmarshal(configPayload, &urlConfig); err != nil {
		t.Fatalf("Failed to unmarshal url config: %v", err)
	}

	fmt.Println("Decrypted Farm URLs:")
	for _, url := range urlConfig {
		fmt.Printf("- %s\n", url)
	}

	// Verification
	expectedUrls := []string{
		"https://huodong3.3839.com/n/hykb/cornfarm/index.php?imm=0",
		"https://huodong3.3839.com/n/hykb/cornfarm/ajax_daily.php",
		"https://huodong3.3839.com/n/hykb/cornfarm/ajax.php",
		"https://huodong3.3839.com/n/hykb/cornfarm/ajax_plant.php",
		"https://api.3839app.com/kuaibao/android/api.cloudgame.php",
		"https://huodong3.3839.com/n/hykb/cornfarm/ajax_sign.php",
	}

	if !reflect.DeepEqual(urlConfig, expectedUrls) {
		t.Errorf("Farm URLs do not match expected. Got %v, want %v", urlConfig, expectedUrls)
	}
}

func TestFetchExtractViaGateway(t *testing.T) {
	// First, get a valid JWT to use for subsequent requests.
	jwtToken, longTermKey := getTestJWT(t)
	log.Println("--- Successfully obtained JWT for gateway tests ---")

	log.Println("\n--- Fetching extractRe via Gateway (target: 2b, p: jzo2) ---")

	// Call the helper to get the decrypted payload
	ExtractRePayload := fetchAndDecrypt(t, jwtToken, longTermKey, "2b", "jzo2")

	// Unmarshal the decrypted payload into a string slice
	var ExtractRe string
	if err := json.Unmarshal(ExtractRePayload, &ExtractRe); err != nil {
		t.Fatalf("Failed to unmarshal ExtractRe: %v", err)
	}

	if ExtractRe != `[&?]comm_id=([^&]+)` {
		t.Errorf("extractRe does not match expected. Got '%s'", actOnClickString)
	}

	fmt.Println("Decrypted ExtractRePayload:")
	fmt.Println(ExtractRe)

	log.Println("\n--- Fetching ExtractS via Gateway (target: 2b, p: io12) ---")

	ExtractSPayload := fetchAndDecrypt(t, jwtToken, longTermKey, "2b", "io12")

	// Unmarshal the decrypted payload
	var ExtractS string
	if err := json.Unmarshal(ExtractSPayload, &ExtractS); err != nil {
		t.Fatalf("Failed to unmarshal ExtractS: %v", err)
	}

	if ExtractS != `"s":\s*"?([^"]+)"?` {
		t.Errorf("extractRe does not match expected. Got '%s'", actOnClickString)
	}

	fmt.Println("Decrypted ExtractSPayload:")
	fmt.Println(ExtractS)
}

func TestGameUrls(t *testing.T) {
	jwtToken, longTermKey := getTestJWT(t)

	gameUrlsPayload := fetchAndDecrypt(t, jwtToken, longTermKey, "i18", "")
	var gameUrls []string
	if err := json.Unmarshal(gameUrlsPayload, &gameUrls); err != nil {
		t.Fatalf("Failed to unmarshal gameUrls: %v", err)
	}

	fmt.Println("Decrypted game URLs:")
	for _, url := range gameUrls {
		fmt.Printf("- %s\n", url)
	}

	expectedUrls := []string{
		"https://huodong3.3839.com/n/hykb/cfxyx/ajax.php",
		"https://api.3839app.com/kuaibao/android/api.php",
		"https://api.3839app.com/kuaibao/android/api.cloudgame.php",
		"https://api.3839app.com/cdn/android/ranktop-home-1577-type-mini-page-1-level-2.htm",
	}

	if !reflect.DeepEqual(gameUrls, expectedUrls) {
		t.Errorf("Farm URLs do not match expected. Got %v, want %v", gameUrls, expectedUrls)
	}
}
