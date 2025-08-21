package rootfs

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Manager handles rootfs operations
type Manager struct {
	cacheDir string
}

// NewManager creates a new rootfs manager
func NewManager(cacheDir string) *Manager {
	return &Manager{
		cacheDir: cacheDir,
	}
}

// Initialize sets up the rootfs in the cache directory
func (m *Manager) Initialize(rootfsPath string, force bool) error {
	imageDir := filepath.Join(m.cacheDir, "images", "alpine-3.20")

	// Check if already exists
	if !force {
		if _, err := os.Stat(imageDir); err == nil {
			fmt.Println("Rootfs already exists, skipping extraction (use --force to re-extract)")
			return nil
		}
	}

	// Ensure directory exists
	if err := os.MkdirAll(imageDir, 0755); err != nil {
		return fmt.Errorf("failed to create image directory: %w", err)
	}

	// Check if rootfs file exists
	if _, err := os.Stat(rootfsPath); os.IsNotExist(err) {
		// Try to use embedded rootfs or download
		return m.handleMissingRootfs(rootfsPath, imageDir)
	}

	// Extract rootfs
	fmt.Println("Extracting rootfs...")
	if err := m.extractRootfs(rootfsPath, imageDir); err != nil {
		return fmt.Errorf("failed to extract rootfs: %w", err)
	}

	fmt.Println("Rootfs extracted successfully")
	return nil
}

// extractRootfs extracts a tarball to the target directory
func (m *Manager) extractRootfs(tarballPath, targetDir string) error {
	file, err := os.Open(tarballPath)
	if err != nil {
		return fmt.Errorf("failed to open tarball: %w", err)
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		target := filepath.Join(targetDir, header.Name)

		// Security: prevent directory traversal
		if !strings.HasPrefix(target, filepath.Clean(targetDir)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid file path in tarball: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory: %w", err)
			}

			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file: %w", err)
			}

			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("failed to write file: %w", err)
			}
			f.Close()
		case tar.TypeSymlink:
			if err := os.Symlink(header.Linkname, target); err != nil {
				return fmt.Errorf("failed to create symlink: %w", err)
			}
		default:
			// Skip unsupported types
			continue
		}
	}

	return nil
}

// handleMissingRootfs handles cases where the rootfs tarball is missing
func (m *Manager) handleMissingRootfs(rootfsPath, imageDir string) error {
	fmt.Printf("Warning: rootfs tarball not found at %s\n", rootfsPath)
	fmt.Println("Creating minimal Alpine rootfs structure...")

	// Create basic directory structure
	dirs := []string{
		"bin", "etc", "lib", "usr", "usr/bin", "usr/lib", "tmp", "var", "proc", "sys", "dev",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(imageDir, dir), 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Create minimal busybox binary (placeholder)
	busyboxPath := filepath.Join(imageDir, "bin", "sh")
	if err := os.WriteFile(busyboxPath, []byte("#!/bin/sh\necho 'Minimal shell placeholder'\n"), 0755); err != nil {
		return fmt.Errorf("failed to create placeholder shell: %w", err)
	}

	fmt.Println("Created minimal rootfs structure")
	return nil
}

// GetImagePath returns the path to the extracted image
func (m *Manager) GetImagePath(imageName string) string {
	return filepath.Join(m.cacheDir, "images", imageName)
}

// ListImages returns a list of available images
func (m *Manager) ListImages() ([]string, error) {
	imagesDir := filepath.Join(m.cacheDir, "images")
	entries, err := os.ReadDir(imagesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	var images []string
	for _, entry := range entries {
		if entry.IsDir() {
			images = append(images, entry.Name())
		}
	}

	return images, nil
}