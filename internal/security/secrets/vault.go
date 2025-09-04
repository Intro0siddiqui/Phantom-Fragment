package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/phantom-fragment/phantom-fragment/internal/config"
)

// SecretMetadata contains additional security metadata
type SecretMetadata struct {
	KeyDerivationSalt []byte    `json:"kdf_salt"`
	EncryptionMethod  string    `json:"encryption_method"`
	HMAC              []byte    `json:"hmac"`
	Version           int       `json:"version"`
	AccessCount       int       `json:"access_count"`
	LastAccessed      time.Time `json:"last_accessed"`
}

// Secret represents an encrypted secret value with enhanced security
type Secret struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Value     string            `json:"value"` // Encrypted value
	Type      string            `json:"type"`  // api_key, token, password, etc.
	Scope     string            `json:"scope"` // global, profile, project
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
	ExpiresAt time.Time         `json:"expires_at,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`

	// Enhanced security fields
	SecurityMeta SecretMetadata `json:"security_meta"`
	Owner        string         `json:"owner"`
	Permissions  []string       `json:"permissions"`
	Tags         []string       `json:"tags"`
}

// Vault manages encrypted secrets storage with enhanced security
type Vault struct {
	mu       sync.RWMutex
	secrets  map[string]*Secret
	key      []byte
	dataFile string

	// Enhanced security features
	masterSalt   []byte
	keyVersion   int
	_auditLogger AuditLogger
	accessPolicy AccessPolicy

	// Key rotation and backup
	rotationSchedule time.Duration
	lastRotation     time.Time
	backupEnabled    bool
	backupPath       string
}

// AuditLogger interface for secret access logging
type AuditLogger interface {
	LogSecretAccess(secretID, action, user string, metadata map[string]interface{})
	LogSecretViolation(secretID, violation string, metadata map[string]interface{})
}

// AccessPolicy defines access control for secrets
type AccessPolicy struct {
	RequireAuth      bool
	MaxAccessCount   int
	AccessTimeWindow time.Duration
	AllowedUsers     []string
	DeniedUsers      []string
}

// NewVault creates a new enhanced secrets vault with security features
func NewVault() (*Vault, error) {
	vaultDir := filepath.Join(config.GetConfigDir(), "vault")
	if err := os.MkdirAll(vaultDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create vault directory: %w", err)
	}

	// Load or generate master salt for key derivation
	masterSalt, err := loadOrGenerateMasterSalt(vaultDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load master salt: %w", err)
	}

	// Load or generate encryption key with enhanced security
	key, keyVersion, err := loadOrGenerateEnhancedKey(vaultDir, masterSalt)
	if err != nil {
		return nil, fmt.Errorf("failed to load encryption key: %w", err)
	}

	// Create vault with enhanced security features
	vault := &Vault{
		secrets:          make(map[string]*Secret),
		key:              key,
		dataFile:         filepath.Join(vaultDir, "secrets.json"),
		masterSalt:       masterSalt,
		keyVersion:       keyVersion,
		rotationSchedule: 30 * 24 * time.Hour, // 30 days
		backupEnabled:    true,
		backupPath:       filepath.Join(vaultDir, "backups"),
		accessPolicy: AccessPolicy{
			RequireAuth:      true,
			MaxAccessCount:   1000,
			AccessTimeWindow: time.Hour,
		},
	}

	// Load existing secrets
	if err := vault.load(); err != nil {
		return nil, fmt.Errorf("failed to load secrets: %w", err)
	}

	// Check if key rotation is needed
	if vault.needsKeyRotation() {
		// Schedule key rotation (would be done in background)
		vault.scheduleKeyRotation()
	}

	return vault, nil
}

// loadOrGenerateMasterSalt loads existing master salt or generates a new one
func loadOrGenerateMasterSalt(vaultDir string) ([]byte, error) {
	saltFile := filepath.Join(vaultDir, ".salt")

	if data, err := os.ReadFile(saltFile); err == nil {
		return data, nil
	}

	// Generate new 32-byte salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// Save salt with restrictive permissions
	if err := os.WriteFile(saltFile, salt, 0600); err != nil {
		return nil, err
	}

	return salt, nil
}

// loadOrGenerateEnhancedKey loads or generates encryption key with PBKDF2-like derivation
func loadOrGenerateEnhancedKey(vaultDir string, masterSalt []byte) ([]byte, int, error) {
	keyFile := filepath.Join(vaultDir, ".key")
	versionFile := filepath.Join(vaultDir, ".keyversion")

	// Check if key exists
	if keyData, err := os.ReadFile(keyFile); err == nil {
		// Load key version
		version := 1
		if versionData, err := os.ReadFile(versionFile); err == nil {
			if _, err := fmt.Sscanf(string(versionData), "%d", &version); err != nil {
				version = 1
			}
		}
		return keyData, version, nil
	}

	// Generate new key using PBKDF2-like approach with SHA-256
	password := make([]byte, 32)
	if _, err := rand.Read(password); err != nil {
		return nil, 0, err
	}

	// Derive key using multiple rounds of HMAC-SHA256
	key := deriveKeyPBKDF2(password, masterSalt, 100000, 32)

	// Save key and version with restrictive permissions
	if err := os.WriteFile(keyFile, key, 0600); err != nil {
		return nil, 0, err
	}

	if err := os.WriteFile(versionFile, []byte("1"), 0600); err != nil {
		return nil, 0, err
	}

	// Securely wipe the password from memory
	secureWipe(password)

	return key, 1, nil
}

// deriveKeyPBKDF2 implements PBKDF2 using HMAC-SHA256
func deriveKeyPBKDF2(password, salt []byte, iterations, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var key []byte
	for i := 1; i <= numBlocks; i++ {
		prf.Reset()
		prf.Write(salt)
		prf.Write([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
		u := prf.Sum(nil)

		t := make([]byte, len(u))
		copy(t, u)

		for j := 1; j < iterations; j++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)

			for k := range t {
				t[k] ^= u[k]
			}
		}

		key = append(key, t...)
	}

	return key[:keyLen]
}

// secureWipe overwrites sensitive data in memory
func secureWipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// needsKeyRotation checks if key rotation is needed
func (v *Vault) needsKeyRotation() bool {
	return time.Since(v.lastRotation) > v.rotationSchedule
}

// scheduleKeyRotation schedules key rotation (placeholder)
func (v *Vault) scheduleKeyRotation() {
	// In a real implementation, this would schedule background key rotation
	// For now, we'll just update the last rotation time
	v.lastRotation = time.Now()
}

// SetSecret stores or updates a secret
func (v *Vault) SetSecret(secret *Secret) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	encrypted, err := v.encrypt(secret.Value)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	secret.Value = encrypted
	secret.UpdatedAt = time.Now()

	if secret.CreatedAt.IsZero() {
		secret.CreatedAt = secret.UpdatedAt
	}

	v.secrets[secret.ID] = secret
	return v.save()
}

// GetSecret retrieves a secret by ID
func (v *Vault) GetSecret(id string) (*Secret, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	secret, exists := v.secrets[id]
	if !exists {
		return nil, fmt.Errorf("secret not found: %s", id)
	}

	decrypted, err := v.decrypt(secret.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}

	// Return a copy with decrypted value
	result := *secret
	result.Value = decrypted
	return &result, nil
}

// ListSecrets returns all secret IDs and metadata (without values)
func (v *Vault) ListSecrets() []Secret {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var secrets []Secret
	for _, secret := range v.secrets {
		// Return metadata only, value remains encrypted
		metadata := *secret
		metadata.Value = "[ENCRYPTED]"
		secrets = append(secrets, metadata)
	}
	return secrets
}

// DeleteSecret removes a secret
func (v *Vault) DeleteSecret(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if _, exists := v.secrets[id]; !exists {
		return fmt.Errorf("secret not found: %s", id)
	}

	delete(v.secrets, id)
	return v.save()
}

// RotateKey re-encrypts all secrets with a new key
func (v *Vault) RotateKey() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Decrypt all secrets with old key
	decryptedSecrets := make(map[string]string)
	for id, secret := range v.secrets {
		decrypted, err := v.decrypt(secret.Value)
		if err != nil {
			return fmt.Errorf("failed to decrypt secret %s: %w", id, err)
		}
		decryptedSecrets[id] = decrypted
	}

	// Generate new key
	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		return err
	}

	// Re-encrypt all secrets with new key
	oldKey := v.key
	v.key = newKey

	for id, decrypted := range decryptedSecrets {
		encrypted, err := v.encrypt(decrypted)
		if err != nil {
			v.key = oldKey // Restore old key on failure
			return fmt.Errorf("failed to re-encrypt secret %s: %w", id, err)
		}
		v.secrets[id].Value = encrypted
	}

	// Save new key
	vaultDir := filepath.Dir(v.dataFile)
	keyFile := filepath.Join(vaultDir, ".key")
	if err := os.WriteFile(keyFile, newKey, 0600); err != nil {
		v.key = oldKey // Restore old key on failure
		return err
	}

	return v.save()
}

// encrypt encrypts data using AES-GCM
func (v *Vault) encrypt(data string) (string, error) {
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts data using AES-GCM
func (v *Vault) decrypt(data string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(v.key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// load loads secrets from disk
func (v *Vault) load() error {
	if _, err := os.Stat(v.dataFile); os.IsNotExist(err) {
		return nil // No secrets file yet
	}

	data, err := os.ReadFile(v.dataFile)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &v.secrets)
}

// save saves secrets to disk
func (v *Vault) save() error {
	data, err := json.MarshalIndent(v.secrets, "", "  ")
	if err != nil {
		return err
	}

	// Write with restrictive permissions
	return os.WriteFile(v.dataFile, data, 0600)
}

// MCP Integration: Secrets Tool for MCP server
func (v *Vault) GetMCPTools() map[string]interface{} {
	return map[string]interface{}{
		"secrets_list": map[string]interface{}{
			"description": "List all secrets (metadata only)",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"scope": map[string]interface{}{
						"type":        "string",
						"description": "Filter by scope (global, profile, project)",
					},
				},
			},
		},
		"secrets_get": map[string]interface{}{
			"description": "Retrieve a secret value",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":        "string",
						"description": "Secret ID",
					},
				},
				"required": []string{"id"},
			},
		},
		"secrets_set": map[string]interface{}{
			"description": "Store or update a secret",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":        "string",
						"description": "Secret ID",
					},
					"name": map[string]interface{}{
						"type":        "string",
						"description": "Secret name",
					},
					"value": map[string]interface{}{
						"type":        "string",
						"description": "Secret value",
					},
					"type": map[string]interface{}{
						"type":        "string",
						"description": "Secret type",
					},
					"scope": map[string]interface{}{
						"type":        "string",
						"description": "Secret scope",
					},
					"expires_at": map[string]interface{}{
						"type":        "string",
						"description": "Expiration timestamp",
					},
				},
				"required": []string{"id", "name", "value", "type", "scope"},
			},
		},
		"secrets_delete": map[string]interface{}{
			"description": "Delete a secret",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{
						"type":        "string",
						"description": "Secret ID",
					},
				},
				"required": []string{"id"},
			},
		},
	}
}
