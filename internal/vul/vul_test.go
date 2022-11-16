package vul

import "testing"

func TestNormalizeUrlPathForBenchmark(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/benchmark/sqli-06/BenchmarkTest02730", "BenchmarkTest02730"},
		{"/benchmark/xss-05/BenchmarkTest02687", "BenchmarkTest02687"},
		{"org.owasp.benchmark.testcode.BenchmarkTest00582.getNextNumber(BenchmarkTest00582.java:127)", "BenchmarkTest00582"},
		{"org.owasp.benchmark.testcode.BenchmarkTest01283.doPost(BenchmarkTest01283.java:65)", "BenchmarkTest01283"},
		{"/WebGoat/SqlOnlyInputValidation/attack", "/WebGoat/SqlOnlyInputValidation/attack"},
		{"/vulns/004-command-2.jsp", "/vulns/004-command-2.jsp"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := NormalizeUrlPath(tt.path); got != tt.want {
				t.Errorf("NormalizeUrlPath() = %v, want %v", got, tt.want)
			}
		})
	}
}
