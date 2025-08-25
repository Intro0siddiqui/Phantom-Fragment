package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/phantom-fragment/phantom-fragment/internal/config"
	"github.com/phantom-fragment/phantom-fragment/internal/security/secrets"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s <command> [args...]\n", os.Args[0])
		fmt.Println("Commands:")
		fmt.Println("  create-vault         Initialize secrets vault")
		fmt.Println("  store-secret         Store a secret")
		fmt.Println("  get-secret           Retrieve a secret")
		fmt.Println("  list-secrets         List all secrets")
		os.Exit(1)
	}

	command := os.Args[1]

	// Initialize configuration
	if err := config.Initialize(""); err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}

	vault, err := secrets.NewVault()
	if err != nil {
		log.Fatalf("Failed to create vault: %v", err)
	}

	switch command {
	case "create-vault":
		fmt.Println("Secrets vault initialized successfully")

	case "store-secret":
		if len(os.Args) < 4 {
			fmt.Println("Usage: store-secret <name> <value>")
			os.Exit(1)
		}
		if err := storeSecret(vault, os.Args[2], os.Args[3]); err != nil {
			log.Fatalf("Failed to store secret: %v", err)
		}
		fmt.Printf("Secret '%s' stored successfully\n", os.Args[2])

	case "get-secret":
		if len(os.Args) < 3 {
			fmt.Println("Usage: get-secret <name>")
			os.Exit(1)
		}
		if err := getSecret(vault, os.Args[2]); err != nil {
			log.Fatalf("Failed to get secret: %v", err)
		}

	case "list-secrets":
		if err := listSecrets(vault); err != nil {
			log.Fatalf("Failed to list secrets: %v", err)
		}

	default:
		fmt.Printf("Unknown command: %s\n", command)
		os.Exit(1)
	}
}

func storeSecret(vault *secrets.Vault, name, value string) error {
	secret := &secrets.Secret{
		ID:        name,
		Name:      name,
		Value:     value,
		Type:      "generic",
		Scope:     "user",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	return vault.SetSecret(secret)
}

func getSecret(vault *secrets.Vault, name string) error {
	secret, err := vault.GetSecret(name)
	if err != nil {
		return err
	}
	fmt.Printf("Secret: %s\n", secret.Value)
	return nil
}

func listSecrets(vault *secrets.Vault) error {
	secrets := vault.ListSecrets()
	if len(secrets) == 0 {
		fmt.Println("No secrets found")
		return nil
	}

	fmt.Println("Stored Secrets:")
	for _, secret := range secrets {
		fmt.Printf("  - %s (%s)\n", secret.Name, secret.Type)
	}
	return nil
}