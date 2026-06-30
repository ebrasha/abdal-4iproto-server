/*
 **********************************************************************
 * -------------------------------------------------------------------
 * Project Name : Abdal 4iProto Server
 * File Name    : exe.go
 * Programmer   : Ebrahim Shafiei (EbraSha)
 * Email        : Prof.Shafiei@Gmail.com
 * Created On   : 2026-06-30 04:12:29
 * Description  : Resolves and caches the executable directory for runtime file paths
 * -------------------------------------------------------------------
 *
 * "Coding is an engaging and beloved hobby for me. I passionately and insatiably pursue knowledge in cybersecurity and programming."
 * – Ebrahim Shafiei
 *
 **********************************************************************
 */

package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var (
	cachedExeDir string
	cachedExeErr error
	exeDirOnce   sync.Once
)

// ExecutableDir returns (and on first call, sets) the executable directory.
// The chdir and symlink resolution happen exactly once for the lifetime of the
// process. Subsequent calls are cheap and goroutine-safe.
func ExecutableDir() (string, error) {
	exeDirOnce.Do(func() {
		exePath, err := os.Executable()
		if err != nil {
			cachedExeErr = fmt.Errorf("failed to get executable path: %w", err)
			return
		}

		exePath, err = filepath.EvalSymlinks(exePath)
		if err != nil {
			cachedExeErr = fmt.Errorf("failed to resolve symlinks: %w", err)
			return
		}

		dir := filepath.Dir(exePath)
		if err := os.Chdir(dir); err != nil {
			cachedExeErr = fmt.Errorf("failed to change working directory: %w", err)
			return
		}
		cachedExeDir = dir
	})
	return cachedExeDir, cachedExeErr
}
