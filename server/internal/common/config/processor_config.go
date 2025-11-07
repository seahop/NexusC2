// internal/common/config/processor_config.go
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// ProcessorConfig holds configuration for the async result processor
type ProcessorConfig struct {
	// Worker pool settings
	MaxWorkers     int           `json:"max_workers" yaml:"max_workers"`
	MinWorkers     int           `json:"min_workers" yaml:"min_workers"`
	WorkerIdleTime time.Duration `json:"worker_idle_time" yaml:"worker_idle_time"`

	// Queue settings
	MaxQueueSize int           `json:"max_queue_size" yaml:"max_queue_size"`
	QueueTimeout time.Duration `json:"queue_timeout" yaml:"queue_timeout"`

	// Batch processing
	BatchSize    int           `json:"batch_size" yaml:"batch_size"`
	BatchTimeout time.Duration `json:"batch_timeout" yaml:"batch_timeout"`
	BatchDelay   time.Duration `json:"batch_delay" yaml:"batch_delay"`

	// Thresholds
	LargePayloadThreshold int `json:"large_payload_threshold" yaml:"large_payload_threshold"`
	AsyncThreshold        int `json:"async_threshold" yaml:"async_threshold"`

	// Retry settings
	MaxRetries   int           `json:"max_retries" yaml:"max_retries"`
	RetryBackoff time.Duration `json:"retry_backoff" yaml:"retry_backoff"`

	// Database settings
	DBTimeout    time.Duration `json:"db_timeout" yaml:"db_timeout"`
	DBMaxRetries int           `json:"db_max_retries" yaml:"db_max_retries"`

	// Monitoring
	MetricsInterval time.Duration `json:"metrics_interval" yaml:"metrics_interval"`
	EnableMetrics   bool          `json:"enable_metrics" yaml:"enable_metrics"`
}

// DefaultProcessorConfig returns the default configuration
func DefaultProcessorConfig() *ProcessorConfig {
	return &ProcessorConfig{
		// Worker pool
		MaxWorkers:     20,
		MinWorkers:     5,
		WorkerIdleTime: 30 * time.Second,

		// Queue
		MaxQueueSize: 10000,
		QueueTimeout: 30 * time.Second,

		// Batch processing
		BatchSize:    50,
		BatchTimeout: 30 * time.Second,
		BatchDelay:   100 * time.Millisecond,

		// Thresholds
		LargePayloadThreshold: 100,
		AsyncThreshold:        20,

		// Retry
		MaxRetries:   3,
		RetryBackoff: 1 * time.Second,

		// Database
		DBTimeout:    15 * time.Second,
		DBMaxRetries: 3,

		// Monitoring
		MetricsInterval: 30 * time.Second,
		EnableMetrics:   true,
	}
}

// LoadFromEnv loads configuration from environment variables
func (c *ProcessorConfig) LoadFromEnv() {
	if val := os.Getenv("PROCESSOR_MAX_WORKERS"); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			c.MaxWorkers = n
		}
	}

	if val := os.Getenv("PROCESSOR_MIN_WORKERS"); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			c.MinWorkers = n
		}
	}

	if val := os.Getenv("PROCESSOR_QUEUE_SIZE"); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			c.MaxQueueSize = n
		}
	}

	if val := os.Getenv("PROCESSOR_BATCH_SIZE"); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			c.BatchSize = n
		}
	}

	if val := os.Getenv("PROCESSOR_ASYNC_THRESHOLD"); val != "" {
		if n, err := strconv.Atoi(val); err == nil {
			c.AsyncThreshold = n
		}
	}

	if val := os.Getenv("PROCESSOR_DB_TIMEOUT"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			c.DBTimeout = d
		}
	}

	if val := os.Getenv("PROCESSOR_ENABLE_METRICS"); val != "" {
		c.EnableMetrics = val == "true" || val == "1"
	}
}

// Validate checks if the configuration is valid
func (c *ProcessorConfig) Validate() error {
	if c.MaxWorkers < 1 {
		return fmt.Errorf("max_workers must be at least 1")
	}

	if c.MinWorkers < 1 || c.MinWorkers > c.MaxWorkers {
		return fmt.Errorf("min_workers must be between 1 and max_workers")
	}

	if c.MaxQueueSize < 100 {
		return fmt.Errorf("max_queue_size must be at least 100")
	}

	if c.BatchSize < 1 {
		return fmt.Errorf("batch_size must be at least 1")
	}

	if c.AsyncThreshold < 1 {
		return fmt.Errorf("async_threshold must be at least 1")
	}

	return nil
}
