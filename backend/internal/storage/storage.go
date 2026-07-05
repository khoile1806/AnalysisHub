package storage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// LocalStorage manages files (tools and job artifacts) on the local filesystem.
type LocalStorage struct {
	BasePath string
}

// New creates a LocalStorage rooted at basePath and ensures the required
// subdirectories exist.
func New(basePath string) (*LocalStorage, error) {
	dirs := []string{
		filepath.Join(basePath, "tools"),
		filepath.Join(basePath, "artifacts"),
		filepath.Join(basePath, "analysis-uploads"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return nil, fmt.Errorf("create storage directory %s: %w", d, err)
		}
	}
	return &LocalStorage{BasePath: basePath}, nil
}

// SaveTool writes the contents of reader to the tools directory under filename.
// It returns the stored filename (which equals the provided filename) or an error.
func (s *LocalStorage) SaveTool(filename string, reader io.Reader) (string, error) {
	dest := filepath.Join(s.BasePath, "tools", filepath.Base(filename))
	if err := s.writeFile(dest, reader); err != nil {
		return "", fmt.Errorf("save tool %s: %w", filename, err)
	}
	return filepath.Base(filename), nil
}

// GetToolPath returns the absolute filesystem path for a stored tool file.
func (s *LocalStorage) GetToolPath(filename string) string {
	return filepath.Join(s.BasePath, "tools", filepath.Base(filename))
}

// SaveArtifact writes the contents of reader to a job-specific artifacts directory.
// The directory <basePath>/artifacts/<jobID>/ is created if it does not exist.
// It returns the stored path relative to BasePath or an error.
func (s *LocalStorage) SaveArtifact(jobID string, filename string, reader io.Reader) (string, error) {
	dir := filepath.Join(s.BasePath, "artifacts", jobID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create artifact dir for job %s: %w", jobID, err)
	}
	dest := filepath.Join(dir, filepath.Base(filename))
	if err := s.writeFile(dest, reader); err != nil {
		return "", fmt.Errorf("save artifact %s for job %s: %w", filename, jobID, err)
	}
	// Return a path relative to BasePath for storage in the database
	rel := filepath.Join("artifacts", jobID, filepath.Base(filename))
	return rel, nil
}

// GetArtifactPath returns the absolute filesystem path for a stored artifact.
func (s *LocalStorage) GetArtifactPath(jobID string, filename string) string {
	return filepath.Join(s.BasePath, "artifacts", jobID, filepath.Base(filename))
}

// SaveAnalysisUpload stores a user-uploaded file for AI analysis under
// analysis-uploads/<sessionID>/<filename>. Returns the relative path.
func (s *LocalStorage) SaveAnalysisUpload(sessionID string, filename string, reader io.Reader) (string, error) {
	dir := filepath.Join(s.BasePath, "analysis-uploads", sessionID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create upload dir for session %s: %w", sessionID, err)
	}
	safe := filepath.Base(filename)
	dest := filepath.Join(dir, safe)
	if err := s.writeFile(dest, reader); err != nil {
		return "", fmt.Errorf("save upload %s: %w", filename, err)
	}
	return filepath.Join("analysis-uploads", sessionID, safe), nil
}

// GetAnalysisUploadPath returns the absolute path for a stored analysis upload.
func (s *LocalStorage) GetAnalysisUploadPath(relPath string) string {
	return filepath.Join(s.BasePath, relPath)
}

// GetArtifactByRelPath returns the absolute path given a relative artifact path
// (as stored in Job.ArtifactPath).
func (s *LocalStorage) GetArtifactByRelPath(relPath string) string {
	return filepath.Join(s.BasePath, relPath)
}

// SaveCaseEvidence stores a result/evidence file under
// case-evidence/<caseID>/<unique>-<filename>. Returns the relative path.
func (s *LocalStorage) SaveCaseEvidence(caseID, unique, filename string, reader io.Reader) (string, error) {
	dir := filepath.Join(s.BasePath, "case-evidence", caseID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create evidence dir for case %s: %w", caseID, err)
	}
	safe := unique + "-" + filepath.Base(filename)
	dest := filepath.Join(dir, safe)
	if err := s.writeFile(dest, reader); err != nil {
		return "", fmt.Errorf("save evidence %s: %w", filename, err)
	}
	return filepath.Join("case-evidence", caseID, safe), nil
}

// GetEvidencePath returns the absolute path for a stored evidence file.
func (s *LocalStorage) GetEvidencePath(relPath string) string {
	return filepath.Join(s.BasePath, relPath)
}

// SaveLogUpload stores an uploaded log file under log-uploads/<jobID>/ and
// returns its relative path. Each job gets its own directory so identical
// filenames across uploads never collide.
func (s *LocalStorage) SaveLogUpload(jobID, filename string, reader io.Reader) (string, error) {
	dir := filepath.Join(s.BasePath, "log-uploads", jobID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create log-upload dir for job %s: %w", jobID, err)
	}
	safe := filepath.Base(filename)
	dest := filepath.Join(dir, safe)
	if err := s.writeFile(dest, reader); err != nil {
		return "", fmt.Errorf("save log upload %s: %w", filename, err)
	}
	return filepath.Join("log-uploads", jobID, safe), nil
}

// GetLogUploadPath resolves a stored log-upload relative path to absolute.
func (s *LocalStorage) GetLogUploadPath(relPath string) string {
	return filepath.Join(s.BasePath, relPath)
}

// RemoveByRelPath deletes a stored file given its relative path.
func (s *LocalStorage) RemoveByRelPath(relPath string) error {
	if relPath == "" {
		return nil
	}
	return os.Remove(filepath.Join(s.BasePath, relPath))
}

// writeFile atomically creates or overwrites dest with data from reader.
func (s *LocalStorage) writeFile(dest string, reader io.Reader) error {
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("open file %s: %w", dest, err)
	}
	defer f.Close()

	if _, err := io.Copy(f, reader); err != nil {
		return fmt.Errorf("write file %s: %w", dest, err)
	}
	return nil
}
