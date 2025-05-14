package main

import (
  "flag"
  "fmt"
  "io"
  "log"
  "os"
  "os/exec"
  "path/filepath"
)

func copySingleFile(src, dest string) error {
  srcFile, err := os.Open(src)
  if err != nil {
    return fmt.Errorf("failed to open source file %s: %v", src, err)
  }
  defer srcFile.Close()

  destFile, err := os.Create(dest)
  if err != nil {
    return fmt.Errorf("failed to create destination file %s: %v", dest, err)
  }
  defer destFile.Close()

  if _, err := io.Copy(destFile, srcFile); err != nil {
    return fmt.Errorf("failed to set permissions for %s: %v", dest, err)
  }

  return nil
}

func copyFileOrDir(src, dest string) error {
  absSrc, err := filepath.Abs(src)
  if err != nil {
    log.Fatalf("failed to get absolute path for %s: %v", absSrc, err)
  }

  info, err := os.Stat(absSrc)
  if err != nil {
    log.Fatalf("source %s does not exist: %v", absSrc, err)
  }

  if info.IsDir() {
    if err := os.MkdirAll(dest, 0755); err != nil {
      log.Fatalf("failed to create directory %s: %v", dest, err)
    }

    entries, err := os.ReadDir(absSrc)
    if err != nil {
      log.Fatalf("failed to read directory %s: %v", absSrc, err)
    }

    for _, entry := range entries {
      srcPath := filepath.Join(absSrc, entry.Name())
      destPath := filepath.Join(dest, entry.Name())

      if entry.IsDir() {
        if err := copyFileOrDir(srcPath, destPath); err != nil {
          log.Fatal(err)
        }
      } else {
        if err := copySingleFile(srcPath, destPath); err != nil {
          log.Fatal(err)
        }
      }
    }

    return nil
  }

  return copySingleFile(absSrc, dest)
}

/*
dpkg -f wireugard-linux_{version}_amd64.deb

7z x wireugard-linux_{version}_amd64.deb
tar -xf data.tar

sudo dpkg -i linux_{version}_amd64.deb
sudo apt install ./wireugard-linux_{version}_amd64.deb
*/
func main() {
  version := flag.String("version", "", "Version of the package")
  flag.Parse()

  fmt.Printf("Building DEB package (version: %s)...\n", *version)

  debDir := "build"
  dirs := []string{
    filepath.Join(debDir, "DEBIAN"),
    filepath.Join(debDir, "opt", "wirewizard", "bin"),
    filepath.Join(debDir, "opt", "wirewizard", "lib"),
    filepath.Join(debDir, "opt", "wirewizard", "resources", "icons"),
    filepath.Join(debDir, "usr", "share", "applications"),
    filepath.Join(debDir, "usr", "share", "polkit-1", "actions"),
  }

  for _, dir := range dirs {
    if err := os.MkdirAll(dir, 0755); err != nil {
      log.Fatalf("failed to create directory %s: %v", dir, err)
    }
  }

  controlContent := fmt.Sprintf(`Package: wirewizard-dev
Version: %s
Architecture: amd64
Maintainer: heycatch <andreyisback@yandex.ru>
Description: Linux desktop application for managing WireGuard tunnels
`, *version)

  controlPath := filepath.Join(debDir, "DEBIAN", "control")
  if err := os.WriteFile(controlPath, []byte(controlContent), 0644); err != nil {
    log.Fatalf("failed to write control file: %v", err)
  }

  postinstContent := `#!/bin/bash
set -e
update-desktop-database /usr/share/applications
exit 0
`
  postinstPath := filepath.Join(debDir, "DEBIAN", "postinst")
  if err := os.WriteFile(postinstPath, []byte(postinstContent), 0755); err != nil {
    log.Fatalf("failed to write postinst script: %v", err)
  }

  filesToCopy := map[string]string{
    "desktop/wireguard-linux.desktop": filepath.Join(debDir, "usr", "share", "applications", "wireguard-linux.desktop"),
    "policy/org.freedesktop.wirewizard.policy": filepath.Join(debDir, "usr", "share", "polkit-1", "actions", "org.freedesktop.wirewizard.policy"),
    "../dist/wireguard": filepath.Join(debDir, "opt", "wirewizard", "bin", "wireguard"),
    "../wirewizard.so": filepath.Join(debDir, "opt", "wirewizard", "lib", "wirewizard.so"),
    "../resources/icons/": filepath.Join(debDir, "opt", "wirewizard", "resources", "icons"),
  }

  for src, dest := range filesToCopy {
    if err := copyFileOrDir(src, dest); err != nil {
      log.Fatalf("failed to copy %s -> %s: %v", src, dest, err)
    }
  }

  binPath := filepath.Join(debDir, "opt", "wirewizard", "bin", "wireguard")
  if err := os.Chmod(binPath, 0755); err != nil {
    log.Fatalf("failed to set executable permissions: %v", err)
  }

  outputDeb := fmt.Sprintf("wireguard-linux_%s_amd64.deb", *version)
  cmd := exec.Command("dpkg-deb", "--build", debDir, outputDeb)
  cmd.Stdout = os.Stdout
  cmd.Stderr = os.Stderr

  if err := cmd.Run(); err != nil {
    log.Fatalf("failed to build .deb: %v", err)
  }

  if err := os.RemoveAll(debDir); err != nil {
    log.Printf("failed to clean up %s: %v", debDir, err)
  }

  fmt.Printf("Successfully build: %s\n", outputDeb)
}
