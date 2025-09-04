package oci

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// Converter handles OCI image conversion
type Converter struct {
	configDir string
	imageDir  string
}

// NewConverter creates a new OCI converter
func NewConverter(configDir, imageDir string) *Converter {
	return &Converter{
		configDir: configDir,
		imageDir:  imageDir,
	}
}

// ConvertToOCI converts a sandbox environment to OCI format
func (c *Converter) ConvertToOCI(sandboxID string) error {
	// Create OCI image layout
	layout := v1.ImageLayout{
		Version: "1.0.0",
	}

	layoutPath := filepath.Join(c.imageDir, "oci-layout")
	if err := c.writeJSON(layoutPath, layout); err != nil {
		return fmt.Errorf("failed to write image layout: %w", err)
	}

	// Create index
	index := v1.Index{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		MediaType: v1.MediaTypeImageIndex,
		Manifests: []v1.Descriptor{
			{
				MediaType: v1.MediaTypeImageManifest,
				Digest:    "sha256:1234567890abcdef",
				Size:      1234,
				Platform: &v1.Platform{
					Architecture: "amd64",
					OS:           "linux",
				},
			},
		},
	}

	indexPath := filepath.Join(c.imageDir, "index.json")
	if err := c.writeJSON(indexPath, index); err != nil {
		return fmt.Errorf("failed to write index: %w", err)
	}

	// Create blobs directory
	blobsDir := filepath.Join(c.imageDir, "blobs", "sha256")
	if err := os.MkdirAll(blobsDir, 0755); err != nil {
		return fmt.Errorf("failed to create blobs directory: %w", err)
	}

	// Create config
	config := v1.Image{
		Platform: v1.Platform{
			Architecture: "amd64",
			OS:           "linux",
		},
		Config: v1.ImageConfig{
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"LANG=C.UTF-8",
			},
			Cmd: []string{"/bin/bash"},
		},
		RootFS: v1.RootFS{
			Type:    "layers",
			DiffIDs: []digest.Digest{"sha256:abcdef1234567890"},
		},
		History: []v1.History{
			{
				Created:   func() *time.Time { t := time.Now(); return &t }(),
				CreatedBy: "phantom",
				Comment:   "Generated from sandbox environment",
			},
		},
	}

	configBlob := filepath.Join(blobsDir, "1234567890abcdef")
	if err := c.writeJSON(configBlob, config); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	// Create manifest
	manifest := v1.Manifest{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		MediaType: v1.MediaTypeImageManifest,
		Config: v1.Descriptor{
			MediaType: v1.MediaTypeImageConfig,
			Digest:    "sha256:1234567890abcdef",
			Size:      1234,
		},
		Layers: []v1.Descriptor{
			{
				MediaType: v1.MediaTypeImageLayerGzip,
				Digest:    "sha256:abcdef1234567890",
				Size:      5678,
			},
		},
	}

	manifestBlob := filepath.Join(blobsDir, "fedcba0987654321")
	if err := c.writeJSON(manifestBlob, manifest); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	// Create layer tarball
	layerPath := filepath.Join(blobsDir, "abcdef1234567890")
	if err := c.createLayer(layerPath, sandboxID); err != nil {
		return fmt.Errorf("failed to create layer: %w", err)
	}

	return nil
}

// createLayer creates a compressed layer tarball
func (c *Converter) createLayer(outputPath, sandboxID string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create layer file: %w", err)
	}
	defer file.Close()

	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	// Add sandbox files to layer
	sandboxDir := filepath.Join(c.configDir, "sandboxes", sandboxID)
	if err := filepath.Walk(sandboxDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(sandboxDir, path)
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		header := &tar.Header{
			Name:    relPath,
			Size:    info.Size(),
			Mode:    int64(info.Mode()),
			ModTime: info.ModTime(),
		}

		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		_, err = io.Copy(tarWriter, file)
		return err
	}); err != nil {
		return fmt.Errorf("failed to walk sandbox directory: %w", err)
	}

	return nil
}

// writeJSON writes JSON data to a file
func (c *Converter) writeJSON(path string, data interface{}) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// ConvertFromOCI converts OCI format back to sandbox
func (c *Converter) ConvertFromOCI(imagePath, sandboxID string) error {
	// Verify OCI layout
	layoutPath := filepath.Join(imagePath, "oci-layout")
	if _, err := os.Stat(layoutPath); os.IsNotExist(err) {
		return fmt.Errorf("invalid OCI image: missing oci-layout")
	}

	// Read index
	indexPath := filepath.Join(imagePath, "index.json")
	indexFile, err := os.Open(indexPath)
	if err != nil {
		return fmt.Errorf("failed to open index: %w", err)
	}
	defer indexFile.Close()

	var index v1.Index
	if err := json.NewDecoder(indexFile).Decode(&index); err != nil {
		return fmt.Errorf("failed to decode index: %w", err)
	}

	// Extract layer
	for _, manifest := range index.Manifests {
		if manifest.MediaType == v1.MediaTypeImageManifest {
			return c.extractLayer(imagePath, manifest.Digest.Hex(), sandboxID)
		}
	}

	return fmt.Errorf("no image manifest found")
}

// extractLayer extracts layer from OCI image
func (c *Converter) extractLayer(imagePath, digest, sandboxID string) error {
	layerPath := filepath.Join(imagePath, "blobs", "sha256", digest)

	file, err := os.Open(layerPath)
	if err != nil {
		return fmt.Errorf("failed to open layer: %w", err)
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	sandboxDir := filepath.Join(c.configDir, "sandboxes", sandboxID)
	if err := os.MkdirAll(sandboxDir, 0755); err != nil {
		return fmt.Errorf("failed to create sandbox directory: %w", err)
	}

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		targetPath := filepath.Join(sandboxDir, header.Name)

		// Ensure directory exists
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}

		// Skip directories
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Create file
		file, err := os.Create(targetPath)
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}

		if _, err := io.Copy(file, tarReader); err != nil {
			file.Close()
			return fmt.Errorf("failed to write file: %w", err)
		}
		file.Close()

		// Set permissions
		if err := os.Chmod(targetPath, os.FileMode(header.Mode)); err != nil {
			return fmt.Errorf("failed to set permissions: %w", err)
		}
	}

	return nil
}

// ValidateOCI validates OCI image format
func (c *Converter) ValidateOCI(imagePath string) error {
	// Check required files
	requiredFiles := []string{
		"oci-layout",
		"index.json",
		filepath.Join("blobs", "sha256"),
	}

	for _, file := range requiredFiles {
		path := filepath.Join(imagePath, file)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return fmt.Errorf("missing required file: %s", file)
		}
	}

	// Validate JSON files
	layoutPath := filepath.Join(imagePath, "oci-layout")
	var layout v1.ImageLayout
	if err := c.readJSON(layoutPath, &layout); err != nil {
		return fmt.Errorf("invalid oci-layout: %w", err)
	}

	indexPath := filepath.Join(imagePath, "index.json")
	var index v1.Index
	if err := c.readJSON(indexPath, &index); err != nil {
		return fmt.Errorf("invalid index.json: %w", err)
	}

	return nil
}

// readJSON reads JSON data from a file
func (c *Converter) readJSON(path string, data interface{}) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewDecoder(file).Decode(data)
}

// GetImageInfo returns information about an OCI image
func (c *Converter) GetImageInfo(imagePath string) (map[string]interface{}, error) {
	if err := c.ValidateOCI(imagePath); err != nil {
		return nil, fmt.Errorf("invalid OCI image: %w", err)
	}

	indexPath := filepath.Join(imagePath, "index.json")
	var index v1.Index
	if err := c.readJSON(indexPath, &index); err != nil {
		return nil, fmt.Errorf("failed to read index: %w", err)
	}

	info := map[string]interface{}{
		"valid":     true,
		"manifests": len(index.Manifests),
		"mediaType": index.MediaType,
	}

	if len(index.Manifests) > 0 {
		manifest := index.Manifests[0]
		info["architecture"] = manifest.Platform.Architecture
		info["os"] = manifest.Platform.OS
		info["digest"] = manifest.Digest.String()
	}

	return info, nil
}
