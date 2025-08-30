package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ensureRootfs ensures that the rootfs for the sandbox is available.
// It checks if the rootfs already exists in the user's cache directory.
// If not, it extracts the embedded rootfs tarball into the cache directory.
func ensureRootfs() error {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return fmt.Errorf("could not get user cache dir: %w", err)
	}
	imagePath := filepath.Join(cacheDir, "ai-sandbox", "images", "alpine-3.20")

	if _, err := os.Stat(imagePath); err == nil {
		fmt.Println("Rootfs already exists, skipping extraction.")
		return nil
	}

	// Check if rootfs tarball exists
	if _, err := os.Stat("alpine-minirootfs.tar.gz"); os.IsNotExist(err) {
		fmt.Println("Warning: alpine-minirootfs.tar.gz not found. Sandbox will use Lima or system tools.")
		// Create a minimal directory structure to prevent errors
		if err := os.MkdirAll(imagePath, 0755); err != nil {
			return fmt.Errorf("could not create image directory: %w", err)
		}
		return nil
	}

	if err := os.MkdirAll(imagePath, 0755); err != nil {
		return fmt.Errorf("could not create image directory: %w", err)
	}

	fmt.Println("Extracting rootfs...")

	// Open the rootfs file directly
	rootfsFile, err := os.Open("alpine-minirootfs.tar.gz")
	if err != nil {
		return fmt.Errorf("could not open rootfs file: %w", err)
	}
	defer rootfsFile.Close()

	gzr, err := gzip.NewReader(rootfsFile)
	if err != nil {
		return fmt.Errorf("could not create gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("could not read tar header: %w", err)
		}

		target := filepath.Join(imagePath, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("could not create directory: %w", err)
			}
		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("could not create file: %w", err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("could not write to file: %w", err)
			}
			f.Close()
		case tar.TypeSymlink:
			if err := os.Symlink(header.Linkname, target); err != nil {
				return fmt.Errorf("could not create symlink: %w", err)
			}
		default:
			fmt.Printf("unsupported tar header type: %v for %s\n", header.Typeflag, header.Name)
		}
	}

	fmt.Println("Rootfs extracted successfully.")
	return nil
}
