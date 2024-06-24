package auth

import (
	"strconv"
	"sync"
	"testing"
)

func TestStaticOIDCClientsStoreRace(t *testing.T) {
	var wg = &sync.WaitGroup{}
	var expectedValue OIDCClientConfig
	var store = NewEmptyStaticOIDCClientStore()
	const steps = 10000

	// One Goroutine changes the store state while 2 other try to read from it.
	wg.Add(1)
	go func() {
		for i := 0; i < steps; i++ {
			// Something comes with requests for a new and a valid domain,
			// so it is being added to the store.
			expectedValue.ClientID = "client-id"
			expectedValue.ClientSecret = "client-secret"
			expectedValue.RedirectURL = "https://" + strconv.Itoa(i) + ".example.com/redirect"
			domain := strconv.Itoa(i) + ".example.com"

			store.AddClient(domain, expectedValue.ClientID, expectedValue.ClientSecret, expectedValue.RedirectURL)
		}

		wg.Done()
	}()

	// Read and compare.
	var found bool
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			for i := 0; i < steps; i++ {
				_, err := store.GetClient("100000.example.com")
				if err == nil {
					found = true
					break
				}
			}

			wg.Done()
		}()
	}

	if found {
		t.Fatal("Received a value while should get ErrOIDCClientConfigNotFound")
	}
}
