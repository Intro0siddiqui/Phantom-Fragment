# AI Sandbox

This project is a sandboxing environment for AI. It uses a minimal Alpine Linux rootfs to create an isolated environment.

## Key Files

*   `main.go`: The main entry point of the application.
*   `ensureRootfs.go`: Ensures that the Alpine Linux rootfs is extracted and available in the user's cache directory.
*   `alpine-minirootfs.tar.gz`: The compressed root filesystem.
*   `build.sh`: A shell script to build the project.

